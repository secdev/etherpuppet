/*
 * etherpuppet.c --- (PoC) schizophrenize an interface for it to order to
                     its master (etherpuppetmaster)
 *  more informations at http://www.secdev.org/projects/etherpuppet.html
 *
 * Copyright (C) 2003  Philippe Biondi <phil@secdev.org>
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



#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_ether.h>

#define PERROR(x) do { perror(x); exit(1); } while (0)
#define ERROR(x, args ...) do { fprintf(stderr,"ERROR:" x, ## args); exit(1); } while (0)

#define CLIENT 1
#define SERVER 2

void usage()
{
        fprintf(stderr, "Usage: etherpuppet {-s port|-c targetip:port} -i iface\n");
        exit(0);
}

int main(int argc, char *argv[])
{
        struct sockaddr_in sin, sin2;
        struct sockaddr_ll sll;
        struct ifreq ifr;
        int fd, s, s2, sin2len, port, PORT, l, ifidx, m, n;
        short int h;

        char c, *p, *ip;
        char buf[1500];
        char *iface = NULL;
        fd_set fdset;



        int MODE = 0,  DEBUG = 0;

        while ((c = getopt(argc, argv, "s:c:i:hd")) != -1) {
                switch (c) {
                case 'h':
                        usage();
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
                default:
                        usage();
                }
        }

        if (DEBUG) printf("MODE=%i iface=%s\n", MODE, iface);

        if (! (MODE && iface)) usage();


        /* Socket for TCP connection with puppet master */
        s = socket(PF_INET, SOCK_STREAM, 0);  /* DGRAM would be better, but ssh only forward TCP */
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(INADDR_ANY);
        sin.sin_port = htons(PORT);
        if ( bind(s,(struct sockaddr *)&sin, sizeof(sin)) < 0) PERROR("bind");


        if (MODE == CLIENT) {
                sin2.sin_family = AF_INET;
                sin2.sin_port = htons(port);
                inet_aton(ip, &sin2.sin_addr);
                if (connect(s, (struct sockaddr *)&sin2, sizeof(sin2)) == -1) PERROR("connect");
        }
        else {
                if (listen(s, 1) == -1) PERROR("listen");
                sin2len = sizeof(sin2);
                s2 = accept(s, (struct sockaddr *)&sin2, &sin2len);
                if (s2 == -1) PERROR("accept");
                s = s2;
        }
        printf("Connected to %s:%i\n",inet_ntoa(sin2.sin_addr.s_addr), ntohs(sin2.sin_port));


        /* Packet socket on the puppet interface */
        s2 = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (s2 == -1) PERROR("socket");

             strncpy(ifr.ifr_name, iface, IF_NAMESIZE);
        if (ioctl(s2, SIOCGIFINDEX, &ifr) == -1) PERROR("ioctl");
        ifidx = ifr.ifr_ifindex;

        sll.sll_family = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL);
        sll.sll_ifindex = ifidx;

        if (bind(s2, (struct sockaddr *)&sll, sizeof(sll)) == -1) PERROR("bind");


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
                        if (n & 0x8000) { /* Command from the master */
                                switch (n & 0x7fff) {
                                default:
                                        ERROR("unknown command\n");
                                }
                        }
                        else {  /* data */
                                l = 0;
                                while (l < n) {
                                        if ((m = read(s, buf+l, n-l)) == -1) PERROR("read(2)");
                                        l += m;
                                }
                                if (send(s2, buf, n, 0) < 0) PERROR("send");
                        }
                }
                else {
                        if (DEBUG) write(1,"<", 1);
                        l = recv(s2, buf, sizeof(buf),0 );
                        h = l;
                        if (DEBUG) printf("%i\n",h);

                        if (send(s, (void *)&h, 2, 0) == -1) PERROR("send(1)");
                        if (send(s, buf, l,0 ) == -1) PERROR("send(2)");
                }
        }
}


