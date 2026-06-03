#pragma once
#include <stdint.h>

/* AES S-Box and round constants (FIPS 197) — shared by crypto.c and ssh.c */
extern const uint8_t AES_SBOX[256];
extern const uint8_t AES_RCON[11];

static inline uint8_t aes_xtime(uint8_t a) {
    return (uint8_t)((a << 1) ^ ((a & 0x80) ? 0x1b : 0));
}
