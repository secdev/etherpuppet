/*
 * etherpuppet.c --- (PoC) schizophrenize an interface for it to obey to its master
 *  more informations at http://www.secdev.org/projects/etherpuppet
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


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <asm/types.h>
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
#include <net/if_arp.h>
#include <linux/if_ether.h>  /* for ETH_P_ALL */
#include <signal.h>
#include <setjmp.h>
#include <netdb.h>
#include <linux/filter.h>
#include <arpa/inet.h>
#include <strings.h>




#define VERSION "v0.4"

#define PROTOVERSION 0x13370104

#define MTU 1600

#define PERROR(x) do { perror(x); exit(1); } while (0)
#define PERROR2(x) do { perror(x); longjmp(env, JMP_ERROR); } while (0)
#define PERROR3(x) do { perror("(trying to continue) " x); } while (0)
#define ERROR(x, args...) do { fprintf(stderr,"ERROR: " x, ## args); exit(1); } while (0)

#define CLIENT 1
#define SERVER 2

#define JMP_NOJMP 0
#define JMP_PEERCLOSED 1
#define JMP_ERROR 2
#define JMP_INTR 3

#define CMD_CMD 0x8000
#define CMD_IFREQ 0x0001
#define CMD_CONF_FINISHED 0x0002


#define SETBPF(x,y,val) do { the_BPF[(x)].k = (val); the_BPF[(y)].k = (val); } while(0)
#define SETBPFIPSRC(val) SETBPF(14,25,val)
#define SETBPFIPDST(val) SETBPF(5,16,val)
#define SETBPFPORTSRC(val) SETBPF(12,23,val)
#define SETBPFPORTDST(val) SETBPF(10,21,val)

#define GETBPF(x) (the_BPF[(x)].k)
#define GETBPFIPSRC GETBPF(14)
#define GETBPFIPDST GETBPF(5)
#define GETBPFPORTSRC GETBPF(12)
#define GETBPFPORTDST GETBPF(10)

#define QUAD(x) (((x) >> 24)&0xff),(((x) >> 16)&0xff),(((x) >> 8)&0xff),((x)&0xff)




#define DESCRIBE_BPF "%i.%i.%i.%i:%i <-> %i.%i.%i.%i:%i\n", QUAD(GETBPFIPSRC),GETBPFPORTSRC,QUAD(GETBPFIPDST),GETBPFPORTDST

int ifclone_get_ioctl[] = {
        SIOCGIFHWADDR,
//        SIOCGIFMETRIC,
        SIOCGIFMTU,
        SIOCGIFADDR,
        SIOCGIFDSTADDR,
        SIOCGIFBRDADDR,
        SIOCGIFNETMASK };
int ifclone_set_ioctl[] = {
        SIOCSIFHWADDR,
//        SIOCSIFMETRIC,
        SIOCSIFMTU,
        SIOCSIFADDR,
        SIOCSIFDSTADDR,
        SIOCSIFBRDADDR,
        SIOCSIFNETMASK };


enum {
        BPF_NONE,
        BPF_AUTO,
        BPF_SSH,
        BPF_MANUAL
};

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



#define NETIFNAMSIZ 16
struct netifreq {
        char name[NETIFNAMSIZ];
        union {
                struct netsockaddr {
                        uint16_t family;
                        char data[14];
                } addr;
                uint32_t mtu;
        } ifru;
};


void hton_ifreq(int req, struct ifreq *ifr, struct netifreq *nifr)
{
        bzero(nifr->name, NETIFNAMSIZ);
        memcpy(nifr->name, ifr->ifr_ifrn.ifrn_name, NETIFNAMSIZ < IFNAMSIZ ? NETIFNAMSIZ : IFNAMSIZ);
        if ((req == SIOCGIFMTU) || (req == SIOCGIFMTU)) {
                nifr->ifru.mtu = htonl(ifr->ifr_ifru.ifru_mtu);
        }
        else {
                nifr->ifru.addr.family = htons(ifr->ifr_ifru.ifru_addr.sa_family);
                memcpy(nifr->ifru.addr.data, ifr->ifr_ifru.ifru_addr.sa_data, 14);
        }
}

void ntoh_ifreq(int req, struct netifreq *nifr, struct ifreq *ifr)
{
        bzero(ifr->ifr_ifrn.ifrn_name, IFNAMSIZ);
        memcpy(ifr->ifr_ifrn.ifrn_name, nifr->name, NETIFNAMSIZ < IFNAMSIZ ? NETIFNAMSIZ : IFNAMSIZ);
        if ((req == SIOCGIFMTU) || (req == SIOCGIFMTU)) {
                ifr->ifr_ifru.ifru_mtu = ntohl(nifr->ifru.mtu);
        }
        else {
                ifr->ifr_ifru.ifru_addr.sa_family = ntohs(nifr->ifru.addr.family);
                memcpy(ifr->ifr_ifru.ifru_addr.sa_data, nifr->ifru.addr.data, 14);
        }
}


int sane(unsigned char x)
{
        return ((x >= 0x20) && (x < 0x80));
}

void hexdump(void *buf, int len)
{
        unsigned char *b = buf;
        int i,j;

        for (i=0; i < (len+15)/16*16; i++) {
                if (i < len) printf("%02x ",b[i]); else printf("   ");
                if (i%8 == 7) printf(" ");
                if (i%16 == 15) {
                        for (j=i-15; (j < i) && (j < len); j++)
                                printf("%c", sane(b[j]) ? b[j] : '.');
                        printf("\n");
                }
        }
}



void usage()
{
        fprintf(stderr, "Usage: etherpuppet {-s port|-c targetip:port} [-B|-S|-M <arg>] [-C] -i iface\n"
                        "       etherpuppet -m {-s port|-c targetip:port} [-I ifname]\n"
                        "-s <port>        : listen on TCP port <port>\n"
                        "-c <IP>:<port>   : connect to <IP>:<port>\n"
                        "-i <iface>       : vampirize interface <iface>\n"
                        "-I <ifname>      : choose the name of the virtual interface\n"
                        "-m               : master mode\n"
                        "-B               : do not use any BPF. Etherpuppet may see its own traffic!\n"
                        "-S               : build BPF filter with SSH_CONNECTION environment variable\n"
                        "-M src:sp,dst:dp : BPF filter manual configuration\n"
                        "-C               : don't copy real interface parameters to virtual interface\n"
                        "-u               : set interface up when parameters have been copied\n"
                        "-U <shell cmd>   : run <shell cmd> when interface has been configured\n"
                        "-d               : increase debug level (can be used more than once)\n" );
        exit(0);
}

void version()
{
        fprintf(stderr,
                "EtherPuppet %s\n"
                "(c) 2004 Philippe Biondi <phil@secdev.org>\n"
                "More informations: http://www.secdev.org/projects/etherpuppet\n", VERSION);
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
        struct netifreq nifr;
        int netreq;
        int  s, s2, port, PORT, l, ifidx, m, n, v;
        socklen_t sinlen, sin2len, sll_len;
        short sll_hatype;
        struct hostent *host;

        struct sigaction sa;


        int c;
        char *p, *ip, *manual_bpf_arg;
        unsigned char buf[MTU+4];
        char *iface = NULL;
        fd_set readset;
        char *ifname_opt = "puppet%d";
        char ifname[IFNAMSIZ+1];

        int reuseaddr = 1;
        int req;

        int MASTER = 0, CONFIG = 1;
        int MODE = 0,  DEBUG = 0;
        int PPP = 0;
        int UP_IFACE = 0;

        int BPF = BPF_AUTO;
        char *UP_SCRIPT = NULL;

        sa.sa_sigaction = &sa_term;
        sigemptyset(&sa.sa_mask);
        sigaddset(&sa.sa_mask, SIGTERM);
        sigaddset(&sa.sa_mask, SIGINT);
        sa.sa_flags = SA_SIGINFO | SA_ONESHOT | SA_RESTART;

        while ((c = getopt(argc, argv, "ms:c:i:I:hdBSMCvuU:")) != -1) {
                switch (c) {
                case 'v':
                        version();
                case 'h':
                        usage();
                case 'm':
                        MASTER=1;
                        break;
                case 'B':
                        BPF = BPF_NONE;
                        break;
                case 'S':
                        BPF = BPF_SSH;
                        break;
                case 'M':
                        BPF = BPF_MANUAL;
                        manual_bpf_arg = optarg;
                        break;
                case 'd':
                        DEBUG++;
                        break;
                case 'C':
                        CONFIG = 0;
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
                case 'u':
                        UP_IFACE = 1;
                        break;
                case 'U':
                        UP_SCRIPT = optarg;
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
                host = gethostbyname(ip);
                if (!host) ERROR("can't resolve [%s]\n",ip);
                sin2.sin_addr = *(struct in_addr *)host->h_addr;
                printf("Connecting to %s:%i...\n", inet_ntoa(sin2.sin_addr), ntohs(sin2.sin_port));
                if (connect(s, (struct sockaddr *)&sin2, sizeof(sin2)) == -1) PERROR("connect");
                v = htonl(PROTOVERSION);
                if (send(s, &v, sizeof(l), 0) == -1) PERROR("send PROTOVERSION");
        }
        else {
                printf("Waiting for connection on port %i...\n", PORT);
                if (listen(s, 1) == -1) PERROR("listen");
                sin2len = sizeof(sin2);
                s2 = accept(s, (struct sockaddr *)&sin2, &sin2len);
                if (s2 == -1) PERROR("accept");
                close(s);
                s = s2;
                if (recv(s, &v, sizeof(l), 0) == -1) PERROR("recv PROTOVERSION");
                v = ntohl(v);
                if (v != PROTOVERSION)
                        ERROR("Protocol version mismatch local=%08x (%i.%i) remote=%08x (%i.%i)\n",
                              PROTOVERSION, (PROTOVERSION >> 8) & 0xff, PROTOVERSION & 0xff,
                               v, (v>>8)&0xff, v&0xff);
                else
                        printf("Protocol version ok. local=%08x (%i.%i) remote=%08x (%i.%i)\n",
                              PROTOVERSION, (PROTOVERSION >> 8) & 0xff, PROTOVERSION & 0xff,
                              v, (v>>8)&0xff, v&0xff);


        }

        sinlen = sizeof(sin);
        getsockname(s, (struct sockaddr *)&sin, &sinlen);
        printf("I am %s:%i\n",inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
        printf("Peer is %s:%i\n",inet_ntoa(sin2.sin_addr), ntohs(sin2.sin_port));


        if (MASTER) {
                /* Create virtual interface */
                if ( (s2 = open("/dev/net/tun",O_RDWR)) < 0) PERROR("open");

                l = recv(s, &sll_hatype, sizeof(sll_hatype),0);
                if (l == -1) PERROR("recv linktype");
                sll_hatype = ntohs(sll_hatype);

                switch (sll_hatype) {
                case 1:
                        printf("Remote linktype is %i (Ethernet)\n", sll_hatype);
                        break;
                case 512:
                        printf("Remote linktype is %i (PPP)\n", sll_hatype);
                        PPP = 1;
                        break;
                default:
                        printf("Remote linktype %i is unknown. Using Ethernet.\n", sll_hatype);
                }

                memset(&ifr, 0, sizeof(ifr));
                if (PPP)
                        ifr.ifr_flags = IFF_TUN;
                else
                        ifr.ifr_flags = IFF_TAP;
                strncpy(ifr.ifr_name, ifname_opt, IFNAMSIZ);
                if (ioctl(s2, TUNSETIFF, (void *)&ifr) < 0) PERROR("ioctl TUNSETIFF");
                memset(ifname,0,IFNAMSIZ+1);
                strncpy(ifname, ifr.ifr_name, IFNAMSIZ);

                printf("Allocated interface is [%s]\n", ifname);
        }
        else { /* Packet socket on the puppet interface */


                s2 = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
                if (s2 == -1) PERROR("socket");


                switch(BPF) {
                case BPF_AUTO:
                        SETBPFIPSRC(ntohl(sin.sin_addr.s_addr));
                        SETBPFIPDST(ntohl(sin2.sin_addr.s_addr));
                        SETBPFPORTSRC(ntohs(sin.sin_port));
                        SETBPFPORTDST(ntohs(sin2.sin_port));
                        if (setsockopt(s2, SOL_SOCKET, SO_ATTACH_FILTER, &the_filter, sizeof(the_filter))<0)
                                PERROR("setsockopt");
                        break;
                case BPF_SSH:
                        do {
                                struct in_addr ip;
                                char *p,*cnx;

                                cnx = getenv("SSH_CONNECTION");
                                if (!cnx) ERROR("can't find SSH_CONNECTION environment variable. Is it the right session ?\n");

                                if (! (p = index(cnx, ' ')) ) break;
                                *p=0;
                                if (!inet_aton(cnx, &ip)) break;
                                SETBPFIPSRC(ntohl(ip.s_addr));
                                cnx = p+1;
                                if (! (p = index(cnx, ' ')) ) break;
                                *p=0;
                                SETBPFPORTSRC(atoi(cnx));
                                cnx = p+1;
                                if (! (p = index(cnx, ' ')) ) break;
                                *p=0;
                                if (!inet_aton(cnx, &ip)) break;
                                SETBPFIPDST(ntohl(ip.s_addr));
                                cnx = p+1;
                                SETBPFPORTDST(atoi(cnx));

                                goto parse_ok1;
                        } while(0);
                        ERROR("can't parse SSH_CONNECTION environment variable!\n");
                parse_ok1:
                        break;

                case BPF_MANUAL:
                        do {
                                struct in_addr ip;
                                char *p,*cnx;

                                cnx = strdup(manual_bpf_arg);

                                if (! (p = index(cnx, ':')) ) break;
                                *p=0;
                                if (!inet_aton(cnx, &ip)) break;
                                SETBPFIPSRC(ntohl(ip.s_addr));
                                cnx = p+1;
                                if (! (p = index(cnx, ',')) ) break;
                                *p=0;
                                SETBPFPORTSRC(atoi(cnx));
                                cnx = p+1;
                                if (! (p = index(cnx, ':')) ) break;
                                *p=0;
                                if (!inet_aton(cnx, &ip)) break;
                                SETBPFIPDST(ntohl(ip.s_addr));
                                cnx = p+1;
                                SETBPFPORTDST(atoi(cnx));
                                free(cnx);

                                goto parse_ok2;
                        } while(0);
                        ERROR("can't parse -M argument [%s] !\n", manual_bpf_arg);
                parse_ok2:
                        break;

                }

                if (BPF != BPF_NONE) printf("BPF filters out " DESCRIBE_BPF);


                     strncpy(ifr.ifr_name, iface, IFNAMSIZ);
                if (ioctl(s2, SIOCGIFINDEX, &ifr) == -1) PERROR("ioctl SIOCGIFINDEX");
                ifidx = ifr.ifr_ifindex;

                sll.sll_family = AF_PACKET;
                sll.sll_protocol = htons(ETH_P_ALL);
                sll.sll_ifindex = ifidx;

                if (bind(s2, (struct sockaddr *)&sll, sizeof(sll)) == -1) PERROR("bind");

                sll_len = sizeof(sll);
                if (getsockname(s2, (struct sockaddr *)&sll, &sll_len) == -1) PERROR("getsockname");
                printf("Sending remote linktype: %i\n", sll.sll_hatype);
                if (sll.sll_hatype == 512) {
                        printf("PPP mode\n");
                        PPP = 1;
                }

                sll_hatype = htons(sll.sll_hatype);
                send(s, &sll_hatype, sizeof(sll_hatype),0);
        }


        /* Now we can go */


        switch (setjmp(env)) {
        case JMP_NOJMP:

                if (sigaction(SIGTERM, &sa, NULL) == -1) PERROR2("sigaction");
                if (sigaction(SIGINT, &sa, NULL) == -1) PERROR2("sigaction");

                printf("Communication established!\n");

                if (!MASTER && CONFIG) {
                        int ireq;
                        unsigned short cmd;


                        /* Send interface parameters */
                        cmd = htons(CMD_CMD | CMD_IFREQ);
                        for(ireq = 0; ireq < sizeof(ifclone_get_ioctl)/sizeof(int); ireq++) {
                                memset(&ifr, 0, sizeof(ifr));
                                strncpy(ifr.ifr_name, iface, IFNAMSIZ);
                                req = ifclone_set_ioctl[ireq];
                                if (ioctl(s, ifclone_get_ioctl[ireq], &ifr) == -1)
                                        PERROR2("ioctl get");
                                send(s, &cmd, 2, 0);
                                netreq = htonl(req);
                                send(s, &netreq, 4, 0);
                                if ((req != SIOCSIFHWADDR) && (req != SIOCSIFMTU))
                                        ifr.ifr_addr.sa_family = AF_INET;
                                hton_ifreq(req, &ifr, &nifr);
                                send(s, (void *)&nifr, sizeof(struct netifreq), 0);
                        }
                        cmd = htons(CMD_CMD | CMD_CONF_FINISHED);
                        send(s, &cmd, 2, 0);
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
                                        if ((m = read(s, buf+l, 2-l)) == -1) PERROR2("read length");
                                        if (m == 0) longjmp(env, JMP_PEERCLOSED);
                                        l += m;
                                }
                                n = ntohs(*(short *)buf);
                                if (DEBUG >= 2) printf("Received a %i %s\n", n&0x7fff,
                                                       n&0x8000 ? "command":"byte packet");
                                if (n & CMD_CMD) { /* Command from the peer */
                                        switch (n & 0x7fff) {
                                        case CMD_IFREQ:
                                                recv(s, &netreq, 4, 0);
                                                req = ntohl(netreq);
                                                recv(s, &nifr, sizeof(struct netifreq), 0);
                                                ntoh_ifreq(req, &nifr, &ifr);
                                                if (CONFIG) {
                                                        strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
                                                        if (ioctl(s, req, &ifr) == -1)
                                                                PERROR3("ioctl set");
                                                }
                                                printf("Configure request [%04x] %s\n",
                                                       req, CONFIG ? "applied" : "ignored");
                                                break;
                                        case CMD_CONF_FINISHED:
                                                if (UP_IFACE) {
                                                        strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
                                                        if (ioctl(s, SIOCGIFFLAGS, &ifr) == -1)
                                                                PERROR3("ioctl get flags");
                                                        ifr.ifr_ifru.ifru_flags |= IFF_UP;
                                                        if (ioctl(s, SIOCSIFFLAGS, &ifr) == -1)
                                                                PERROR3("ioctl set flags");
                                                }
                                                if (UP_SCRIPT)
                                                        system(UP_SCRIPT);
                                                break;
                                        default:
                                                ERROR("unknown command\n");
                                        }
                                }
                                else {  /* data */
                                        if (n > MTU) {
                                                printf("WARNING: truncated packet (%i > %i) .  This should not happen\n", n, MTU);
                                                n = MTU;
                                        }
                                        l = 0;
                                        while (l < n) {
                                                if ((m = read(s, buf+2+l, n-l)) == -1) PERROR2("read packet data");
                                                l += m;
                                        }
                                        if (DEBUG >= 5) hexdump(buf+2, l);
                                        if (MASTER) {
                                                if (DEBUG >= 3) printf("Protocol = %04x\n",ntohs(*(short *)(buf+2)));
                                                if (write(s2, buf , n+2) == -1)
                                                        PERROR3("write");
                                        }
                                        else {
                                                bzero(&sll, sizeof(sll));
                                                sll.sll_family = AF_PACKET;
                                                sll.sll_protocol = *(short *)(buf+2); /* htons(ntohs()) = Id */
                                                if (DEBUG >= 3) printf("Protocol = %04x\n",ntohs(sll.sll_protocol));
                                                sll.sll_ifindex = ifidx;
                                                if (sendto(s2, buf+4, n-2, 0, (struct sockaddr *)&sll, sizeof(sll)) == -1) PERROR2("sendto");
                                        }
                                }
                        }
                        if (FD_ISSET(s2, &readset)) {
                                if (DEBUG) write(1,"<", 1);
                                if (MASTER) {
                                        l = read(s2, buf, MTU);
                                        if (l == -1) PERROR3("read");
                                        l -= 2;
                                }
                                else {
                                        sll_len = sizeof(sll);
                                        l = recvfrom(s2, buf+4, MTU, 0, (struct sockaddr *)&sll, &sll_len);
                                        *(short *)(buf+2) = sll.sll_protocol; /* htons(ntohs()) = Id */
                                        if (DEBUG > 4) printf("Protocol = %04x\n", ntohs(sll.sll_protocol));
                                        if (l == -1) PERROR3("recvfrom");
                                        l += 2;
                                }
                                *(short *)buf = htons(l);

                                if (send(s, buf, l+2, 0) == -1) PERROR2("send");
                                if (DEBUG >= 3) printf("Sending %i bytes:\n", l);
                                if (DEBUG >= 5) hexdump(buf+2, l);
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
                printf("Something weird happened...\n");
        }

        printf("Gracefull exit\n");
        shutdown(s,SHUT_RDWR);
        close(s);
        close(s2);
        return 0;
}


