#pragma once
#include <stdint.h>

/* AES S-Box and round constants (FIPS 197) — shared by crypto.c and ssh.c */
extern const uint8_t _aA7wX2u[256];
extern const uint8_t _gt8ZM5S[11];

static inline uint8_t aes_xtime(uint8_t a) {
    return (uint8_t)((a << 1) ^ ((a & 0x80) ? 0x1b : 0));
}
