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
#include <signal.h>
#include <setjmp.h>

#define MTU 1600

#define PERROR(x) do { perror(x); exit(1); } while (0)
#define PERROR2(x) do { perror(x); longjmp(env, JMP_ERROR); } while (0)
#define ERROR(x, args ...) do { fprintf(stderr,"ERROR:" x, ## args); exit(1); } while (0)

#define CLIENT 1
#define SERVER 2

#define JMP_NOJMP 0
#define JMP_PEERCLOSED 1
#define JMP_ERROR 2
#define JMP_INTR 3

#define CMD_CMD 0x8000
#define CMD_IFHWADDR 0x0001


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
        fprintf(stderr, "Usage: etherpuppet {-s port|-c targetip:port} [-b] -i iface\n"
                        "       etherpuppet -m {-s port|-c targetip:port} [-I ifname]\n"
                        " -s <port>      : listen on TCP port <port>\n"
                        " -c <IP>:<port> : connect to <IP>:<port>\n"
                        " -i <iface>     : vampirize interface <iface>\n"
                        " -I <ifname>    : choose the name of the virtual interface\n"
                        " -m             : master mode\n"
                        " -b             : do not use any BPF. Etherpuppet may see its own traffic!\n"
);
        exit(0);
}

jmp_buf env;

void sa_term(int sig, siginfo_t *si, void *ctx)
{
        longjmp(env,JMP_INTR);
}


int main(int argc, char *argv[])
{
        struct sockaddr_in sin, sin2;
        struct sockaddr_ll sll;
        struct ifreq ifr;
        int  s, s2, sinlen, sin2len, port, PORT, l, ifidx, m, n;
        short int h;

        struct sigaction sa;


        char c, *p, *ip;
        unsigned char buf[MTU+4];
        char *iface = NULL;
        fd_set readset;
        char *ifname_opt = "puppet%d";
        char ifname[IFNAMSIZ+1];

        int reuseaddr = 1;

        int MASTER = 0;
              int MODE = 0,  DEBUG = 0;
        int BPF = 1;

        sa.sa_sigaction = &sa_term;
        sigemptyset(&sa.sa_mask);
        sigaddset(&sa.sa_mask, SIGTERM);
        sigaddset(&sa.sa_mask, SIGINT);
        sa.sa_flags = SA_SIGINFO | SA_ONESHOT | SA_RESTART;

        while ((c = getopt(argc, argv, "ms:c:i:I:hdb")) != -1) {
                switch (c) {
                case 'h':
                        usage();
                case 'm':
                        MASTER=1;
                        break;
                case 'b':
                        BPF=0;
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
                        ifname_opt = optarg;
                        break;
                default:
                        usage();
                }
        }

        if (DEBUG) printf("MODE=%i iface=%s\n", MODE, iface);

        if (! (MODE && (MASTER || iface))) usage();



        /* Socket for TCP connection between puppet and puppetmaster */
        s = socket(PF_INET, SOCK_STREAM, 0);  /* DGRAM could be better, but ssh only forward TCP */
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(INADDR_ANY);
        sin.sin_port = htons(PORT);
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr));

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
                close(s);
                s = s2;
        }

        sinlen = sizeof(sin);
        getsockname(s, (struct sockaddr *)&sin, &sinlen);
        printf("I am %s:%i\n",inet_ntoa(sin.sin_addr.s_addr), ntohs(sin.sin_port));
        printf("Peer is %s:%i\n",inet_ntoa(sin2.sin_addr.s_addr), ntohs(sin2.sin_port));


        if (MASTER) {
                /* Create virtual interface */
                if ( (s2 = open("/dev/net/tun",O_RDWR)) < 0) PERROR("open");

                memset(&ifr, 0, sizeof(ifr));
                ifr.ifr_flags = IFF_TAP;
                strncpy(ifr.ifr_name, ifname_opt, IFNAMSIZ);
                if (ioctl(s2, TUNSETIFF, (void *)&ifr) < 0) PERROR("ioctl");
                memset(ifname,0,IFNAMSIZ+1);
                strncpy(ifname, ifr.ifr_name, IFNAMSIZ);

                printf("Allocated interface %s. Configure and use it\n", ifname);
        }
        else { /* Packet socket on the puppet interface */


                s2 = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
                if (s2 == -1) PERROR("socket");



                if (BPF) {
                        SETBPFIPSRC(sin.sin_addr.s_addr);
                        SETBPFIPDST(sin2.sin_addr.s_addr);
                        SETBPFPORTSRC(sin.sin_port);
                        SETBPFPORTDST(sin2.sin_port);
                        if (setsockopt(s2, SOL_SOCKET, SO_ATTACH_FILTER, &the_filter, sizeof(the_filter))<0)
                                PERROR("setsockopt");
                        printf("BPF installed\n");
                }


                     strncpy(ifr.ifr_name, iface, IF_NAMESIZE);
                if (ioctl(s2, SIOCGIFINDEX, &ifr) == -1) PERROR("ioctl");
                ifidx = ifr.ifr_ifindex;

                sll.sll_family = AF_PACKET;
                sll.sll_protocol = htons(ETH_P_ALL);
                sll.sll_ifindex = ifidx;

                if (bind(s2, (struct sockaddr *)&sll, sizeof(sll)) == -1) PERROR("bind");
        }


        /* Now we can go */


        switch (setjmp(env)) {
        case JMP_NOJMP:

                if (sigaction(SIGTERM, &sa, NULL) == -1) PERROR2("sigaction");
                if (sigaction(SIGINT, &sa, NULL) == -1) PERROR2("sigaction");

                printf("Communication established!\n");

                if (!MASTER) {
                        unsigned short cmd = CMD_IFHWADDR | CMD_CMD;
                        memset(&ifr, 0, sizeof(ifr));
                        strncpy(ifr.ifr_name, iface, IFNAMSIZ);
                        ioctl(s, SIOCGIFHWADDR, &ifr);
                        send(s, &cmd, 2, 0);
                        send(s, ifr.ifr_hwaddr.sa_data, 6, 0);
                }
                while (1) {
                        FD_ZERO(&readset);
                        FD_SET(s2, &readset);
                        FD_SET(s, &readset);
                        if (select(s+s2+1, &readset, NULL, NULL,  NULL) < 0) PERROR2("select");

                        if (FD_ISSET(s, &readset)) {
                                if (DEBUG) write(1,">", 1);
                                l = 0;                      /* BEEUUURK! */
                                while (l < 2) {
                                        if ((m = read(s, buf+l, 2-l)) == -1) PERROR2("read(1)");
                                        if (m == 0) longjmp(env, JMP_PEERCLOSED);
                                        l += m;
                                }
                                n = *(short *)buf;
                                if (DEBUG) printf("%i\n",n);
                                if (n & CMD_CMD) { /* Command from the peer */
                                        switch (n & 0x7fff) {
                                        case CMD_IFHWADDR:
                                                recv(s, buf, 6, 0);
                                                printf("Set %s mac address to %02x:%02x:%02x:%02x:%02x:%02x\n",ifname,buf[0],buf[1],buf[2],buf[3],buf[4],buf[5]);
                                                memset(&ifr, 0, sizeof(ifr));
                                                strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
                                                memcpy(ifr.ifr_hwaddr.sa_data, buf, 6);
                                                ioctl(s, SIOCSIFHWADDR, &ifr);
                                                break;
                                        default:
                                                ERROR("unknown command\n");
                                        }
                                }
                                else {  /* data */
                                        if (n > MTU) n = MTU;
                                        l = 0;
                                        while (l < n) {
                                                if ((m = read(s, buf+4+l, n-l)) == -1) PERROR2("read(2)");
                                                l += m;
                                        }
                                        if (MASTER)
                                                *(short *)buf = *(short *)(buf+16);
                                        if (write(s2, MASTER ? buf : buf+4, MASTER ? n+4 : n) == -1) PERROR2("write");
                                }
                        }
                        if (FD_ISSET(s2, &readset)) {
                                if (DEBUG) write(1,"<", 1);
                                if ((l = read(s2, MASTER ? buf : buf+4, MTU)) == -1) PERROR2("read(0)");
                                h = MASTER ? l-4 : l;

                                if (DEBUG) printf("%i\n",h);
                                if (send(s, (void *)&h, 2, 0) == -1) PERROR2("send(1)");
                                if (send(s, buf+4, h, 0) == -1) PERROR2("send(2)");
                        }
                }
        case JMP_ERROR:
                printf("Catched error\n");
                break;
        case JMP_INTR:
                printf("Catched TERM/INT signal\n");
                break;
        case JMP_PEERCLOSED:
                printf("Connection reset by peer\n");
                break;
        default:
                printf("Something weird happend...\n");
        }

        printf("Gracefull exit\n");
        shutdown(s,SHUT_RDWR);
        close(s);
        close(s2);
}


