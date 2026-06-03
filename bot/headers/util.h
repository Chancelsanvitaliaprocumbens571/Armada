#pragma once

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/select.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

static inline void *_memcpy(void *dst, const void *src, size_t n) {
    return memcpy(dst, src, n);
}
#define util_memcpy(dst, src, n) memcpy(dst, src, n)

static inline void *_memset(void *dst, int c, size_t n) {
    return memset(dst, c, n);
}

static inline size_t _strlen(const char *s) {
    return strlen(s);
}
#define util_strlen(s) strlen(s)

static inline int _atoi(const char *s) {
    return atoi(s);
}
#define util_atoi(s, base) ((int)strtol((s), NULL, (base)))
#define util_zero(dst, n) memset(dst, 0, n)
#define util_strcpy(dst, src) strcpy(dst, src)
#define util_local_addr() _local_addr()

/* Case-insensitive substring search — returns offset past match or -1 */
static inline int util_stristr(const char *haystack, int haystack_len, const char *needle) {
    int nlen = (int)strlen(needle);
    int i, j;
    for (i = 0; i <= haystack_len - nlen; i++) {
        int match = 1;
        for (j = 0; j < nlen; j++) {
            char a = haystack[i+j], b = needle[j];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) { match = 0; break; }
        }
        if (match) return i + nlen;
    }
    return -1;
}

/* Convert hex string "4142" -> "AB" */
static inline char *hex_to_text(const char *hex) {
    size_t len = strlen(hex);
    size_t out_len = len / 2;
    char *out = (char *)calloc(out_len + 1, 1);
    size_t i;
    if (!out) return NULL;
    for (i = 0; i < out_len; i++) {
        unsigned int byte;
        char tmp[3] = { hex[i*2], hex[i*2+1], 0 };
        sscanf(tmp, "%02x", &byte);
        out[i] = (char)byte;
    }
    return out;
}

/* Get local IP address */
static inline uint32_t _local_addr(void) {
    int fd;
    struct sockaddr_in sa, la;
    socklen_t la_len = sizeof(la);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 0;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(53);
    sa.sin_addr.s_addr = inet_addr("8.8.8.8");

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return 0;
    }
    if (getsockname(fd, (struct sockaddr *)&la, &la_len) < 0) {
        close(fd);
        return 0;
    }
    close(fd);
    return la.sin_addr.s_addr;
}

/* TCP handshake helper used by tcp_brazilian_handshake.c and udp_bypass.c */
static inline int tcp_handshake(int port, int fd, uint32_t dst_addr, uint32_t src_addr, uint32_t seq) {
    struct sockaddr_in addr;
    fd_set wfds;
    struct timeval tv;
    (void)src_addr;
    (void)seq;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = dst_addr;

    /* Non-blocking connect */
    fcntl(fd, F_SETFL, O_NONBLOCK);
    connect(fd, (struct sockaddr *)&addr, sizeof(addr));

    tv.tv_sec = 5;
    tv.tv_usec = 0;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);

    if (select(fd + 1, NULL, &wfds, NULL, &tv) > 0) {
        int err = 0;
        socklen_t len = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
        return err;
    }
    return -1;
}
