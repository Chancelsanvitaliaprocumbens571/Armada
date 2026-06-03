#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

static int _rand_init = 0;

static inline void _rand_ensure(void) {
    if (!_rand_init) {
        srand((unsigned)time(NULL) ^ (unsigned)getpid());
        _rand_init = 1;
    }
}

static inline uint32_t rand_next(void) {
    _rand_ensure();
    return ((uint32_t)rand() << 16) ^ (uint32_t)rand();
}

static inline uint32_t rand_next_range(uint32_t min, uint32_t max) {
    if (min >= max) return min;
    _rand_ensure();
    return min + (rand_next() % (max - min + 1));
}

static inline void rand_str(char *buf, int len) {
    int i;
    _rand_ensure();
    for (i = 0; i < len; i++)
        buf[i] = (char)(rand_next() & 0xFF);
}

static inline void rand_bytes(uint8_t *buf, int len) {
    rand_str((char *)buf, len);
}

static inline void rand_init(void) {
    _rand_ensure();
}

static inline void rand_alphastr(uint8_t *buf, int len) {
    int i;
    _rand_ensure();
    for (i = 0; i < len; i++)
        buf[i] = 'a' + (uint8_t)(rand_next() % 26);
}
