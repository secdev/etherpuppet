/*
 * etherpuppet.c --- (PoC) schizophrenize an interface for it to obey to
                     its master (etherpuppetmaster)
 *  more informations at http://www.secdev.org/projects/etherpuppet.html
 *
 * Copyright (C) 2004  Philippe Biondi <phil@secdev.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */


/* $Id$ */

#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
//#include <netinet/in.h>
#include <string.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/if_arp.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/filter.h>

#define MTU 1600

#define PERROR(x) do { perror(x); exit(1); } while (0)
#define ERROR(x, args ...) do { fprintf(stderr,"ERROR:" x, ## args); exit(1); } while (0)

#define CLIENT 1
#define SERVER 2


#define SETBPF(x,y,val) do { the_BPF[(x)].k = (val); the_BPF[(y)].k = (val); } while(0)
#define SETBPFIPSRC(val) SETBPF(14,25,htonl(val))
#define SETBPFIPDST(val) SETBPF(5,16,htonl(val))
#define SETBPFPORTSRC(val) SETBPF(12,23,htons(val))
#define SETBPFPORTDST(val) SETBPF(10,21,htons(val))

/* Optimized version of:
 * not (tcp and
 *      ( (dst 68.69.70.71 and dst port 0xABCD and src port 0x1234 and src 64.65.66.67) or
 *        (src 68.69.70.71 and src port 0xABCD and dst port 0x1234 and dst 64.65.66.67))
 */

struct sock_filter the_BPF[]= {

        { 0x28,  0,  0, 0x0000000c }, // 00: ldh  [12]
        { 0x15,  0, 14, 0x00000800 }, // 01: jeq  #0x800       jt 2    jf 27
        { 0x30,  0,  0, 0x00000017 }, // 02: ldb  [23]
        { 0x15,  0, 11, 0x00000006 }, // 03: jeq  #0x6         jt 4    jf 15
        { 0x20,  0,  0, 0x0000001e }, // 04: ld   [30]
        { 0x15,  0,  9, 0x44454647 }, // 05: jeq  #0x44454647  jt 6    jf 15  // dst IP
        { 0x28,  0,  0, 0x00000014 }, // 06: ldh  [20]
        { 0x45,  7,  0, 0x00001fff }, // 07: jset #0x1fff      jt 15   jf 8
        { 0xb1,  0,  0, 0x0000000e }, // 08: ldxb 4*([14]&0xf)
        { 0x48,  0,  0, 0x00000010 }, // 19: ldh  [x + 16]
        { 0x15,  0,  4, 0x0000abcd }, // 10: jeq  #0xabcd      jt 11   jf 15  // dst port
        { 0x48,  0,  0, 0x0000000e }, // 11: ldh  [x + 14]
        { 0x15,  0,  2, 0x00001234 }, // 12: jeq  #0x1234      jt 13   jf 15  // src port
        { 0x20,  0,  0, 0x0000001a }, // 13: ld   [26]
        { 0x15, 11,  0, 0x40414243 }, // 14: jeq  #0x40414243  jt 26   jf 15  // src IP

        { 0x20,  0,  0, 0x0000001a }, // 15: ld   [26]
        { 0x15,  0, 10, 0x44454647 }, // 16: jeq  #0x44454647  jt 17   jf 27  // dst IP
        { 0x28,  0,  0, 0x00000014 }, // 17: ldh  [20]
        { 0x45,  8,  0, 0x00001fff }, // 18: jset #0x1fff      jt 27   jf 19
        { 0xb1,  0,  0, 0x0000000e }, // 19: ldxb 4*([14]&0xf)
        { 0x48,  0,  0, 0x0000000e }, // 20: ldh  [x + 14]
        { 0x15,  0,  5, 0x0000abcd }, // 21: jeq  #0xabcd      jt 22   jf 27  // dst port
        { 0x48,  0,  0, 0x00000010 }, // 22: ldh  [x + 16]
        { 0x15,  0,  3, 0x00001234 }, // 23: jeq  #0x1234      jt 24   jf 27  // src port
        { 0x20,  0,  0, 0x0000001e }, // 24: ld   [30]
        { 0x15,  0,  1, 0x40414243 }, // 25: jeq  #0x40414243  jt 26   jf 27  // src IP
        { 0x6,   0,  0, 0x00000000 }, // 26: ret  #0
        { 0x6,   0,  0, MTU        }, // 27: ret  #MTU
};

struct sock_fprog the_filter = {
        sizeof(the_BPF)/sizeof(the_BPF[0]),
        the_BPF,
};




void usage()
{
        fprintf(stderr, "Usage: etherpuppet {-s port|-c targetip:port} -i iface\n"
                        "       etherpuppet -m {-s port|-c targetip:port} [-I ifname]\n");
        exit(0);
}

int main(int argc, char *argv[])
{
        struct sockaddr_in sin, sin2;
        struct sockaddr_ll sll;
        struct ifreq ifr;
        int fd, s, s2, sinlen, sin2len, port, PORT, l, ifidx, m, n;
        short int h;

        char c, *p, *ip;
        char buf[1600];
        char *iface = NULL;
        fd_set fdset;
        char *ifname = "puppet%d";

        int MASTER = 0;
              int MODE = 0,  DEBUG = 0;


        while ((c = getopt(argc, argv, "ms:c:i:I:hd")) != -1) {
                switch (c) {
                case 'h':
                        usage();
                case 'm':
                        MASTER=1;
                        break;
                case 'd':
                        DEBUG++;
                        break;
                case 's':
                        MODE = SERVER;
                        PORT = atoi(optarg);
                        break;
                case 'c':
                        MODE = CLIENT;
                        p = memchr(optarg,':',16);
                        if (!p) ERROR("invalid argument : [%s]\n",optarg);
                        *p = 0;
                        ip = optarg;
                        port = atoi(p+1);
                        PORT = 0;
                        break;
                case 'i':
                        iface = optarg;
                        break;
                case 'I':
                        ifname = optarg;
                        break;
                default:
                        usage();
                }
        }

        if (DEBUG) printf("MODE=%i iface=%s\n", MODE, iface);

        if (! (MODE && (MASTER || iface))) usage();


        if (MASTER) {
                /* Create virtual interface */
                if ( (fd = open("/dev/net/tun",O_RDWR)) < 0) PERROR("open");

                memset(&ifr, 0, sizeof(ifr));
                ifr.ifr_flags = IFF_TAP;
                strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
                if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) PERROR("ioctl");

                printf("Allocated interface %s. Configure and use it\n", ifr.ifr_name);
        }

        /* Socket for TCP connection between puppet and puppetmaster */
        s = socket(PF_INET, SOCK_STREAM, 0);  /* DGRAM could be better, but ssh only forward TCP */
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(INADDR_ANY);
        sin.sin_port = htons(PORT);
        if ( bind(s,(struct sockaddr *)&sin, sizeof(sin)) < 0) PERROR("bind");

        if (MODE == CLIENT) {
                sin2.sin_family = AF_INET;
                sin2.sin_port = htons(port);
                inet_aton(ip, &sin2.sin_addr);
                printf("Connecting to %s:%i...\n", inet_ntoa(sin2.sin_addr.s_addr), ntohs(sin2.sin_port));
                if (connect(s, (struct sockaddr *)&sin2, sizeof(sin2)) == -1) PERROR("connect");
        }
        else {
                printf("Waiting for connection on port %i...\n", PORT);
                if (listen(s, 1) == -1) PERROR("listen");
                sin2len = sizeof(sin2);
                s2 = accept(s, (struct sockaddr *)&sin2, &sin2len);
                if (s2 == -1) PERROR("accept");
                s = s2;
        }

        sinlen = sizeof(sin);
        getsockname(s, (struct sockaddr *)&sin, &sinlen);
        printf("Connected to %s:%i\n",inet_ntoa(sin2.sin_addr.s_addr), ntohs(sin2.sin_port));
        printf("Connected from %s:%i\n",inet_ntoa(sin.sin_addr.s_addr), ntohs(sin.sin_port));


        if (MASTER) {
                s2 = fd;
        }
        else { /* Packet socket on the puppet interface */

                SETBPFIPSRC(sin.sin_addr.s_addr);
                SETBPFIPDST(sin2.sin_addr.s_addr);
                SETBPFPORTSRC(sin.sin_port);
                SETBPFPORTDST(sin2.sin_port);

                s2 = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
                if (s2 == -1) PERROR("socket");

                if (setsockopt(s2, SOL_SOCKET, SO_ATTACH_FILTER, &the_filter, sizeof(the_filter))<0)
                        perror("setsockopt");


                     strncpy(ifr.ifr_name, iface, IF_NAMESIZE);
                if (ioctl(s2, SIOCGIFINDEX, &ifr) == -1) PERROR("ioctl");
                ifidx = ifr.ifr_ifindex;

                sll.sll_family = AF_PACKET;
                sll.sll_protocol = htons(ETH_P_ALL);
                sll.sll_ifindex = ifidx;

                if (bind(s2, (struct sockaddr *)&sll, sizeof(sll)) == -1) PERROR("bind");
        }


        /* Now we can go */

        while (1) {
                FD_ZERO(&fdset);
                FD_SET(s2, &fdset);
                FD_SET(s, &fdset);
                if (select(s+s2+1, &fdset, NULL, NULL, NULL) < 0) PERROR("select");
                if (FD_ISSET(s, &fdset)) {
                        if (DEBUG) write(1,">", 1);
                        l = 0;                      /* BEEUUURK! */
                        while (l < 2) {
                                if ((m = read(s, buf+l, 2-l)) == -1) PERROR("read(1)");
                                l += m;
                        }
                        n = *(short *)buf;
                        if (DEBUG) printf("%i\n",n);
                        if (n & 0x8000) { /* Command from the peer */
                                switch (n & 0x7fff) {
                                default:
                                        ERROR("unknown command\n");
                                }
                        }
                        else {  /* data */
                                l = 0;
                                while (l < n) {
                                        if ((m = read(s, buf+4+l, n-l)) == -1) PERROR("read(2)");
                                        l += m;
                                }
                                if (MASTER) {
                                        *(short *)buf = *(short *)(buf+16);
                                        if (write(s2, buf, n+4) == -1) PERROR("write");
                                }
                                else {
                                        if (send(s2, buf+4, n, 0) < 0) PERROR("send");
                                }
                        }
                }
                else {
                        if (DEBUG) write(1,"<", 1);
                        if (MASTER) {
                                l = read(s2, buf, sizeof(buf));
                                h = l-4;
                        }
                        else {
                                l = recv(s2, buf+4, sizeof(buf),0 );
                                h = l;
                        }

                        if (DEBUG) printf("%i\n",h);
                        if (send(s, (void *)&h, 2, 0) == -1) PERROR("send(1)");
                        if (send(s, buf+4, h, 0) == -1) PERROR("send(2)");
                }
        }
}


