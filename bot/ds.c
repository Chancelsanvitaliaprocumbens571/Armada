/* ds.c — Dynamic string, byte buffer, string array + globals */

#include "bot.h"

/* ======================================================================
   DYNAMIC STRING
   ====================================================================== */

void ds_init(dstr* s) { s->buf = NULL; s->len = 0; s->cap = 0; }

void ds_free(dstr* s) { free(s->buf); s->buf = NULL; s->len = 0; s->cap = 0; }

static void _oY5qq5e(dstr* s, size_t need) {
    char *tmp;
    if (need + 1 <= s->cap) return;
    size_t nc = s->cap ? s->cap * 2 : 32;
    while (nc < need + 1) nc *= 2;
    tmp = (char*)realloc(s->buf, nc);
    if (!tmp) return;
    s->buf = tmp;
    s->cap = nc;
}

void ds_set(dstr* s, const char* str) {
    size_t n = str ? strlen(str) : 0;
    _oY5qq5e(s, n);
    if (n) memcpy(s->buf, str, n);
    s->buf[n] = '\0';
    s->len = n;
}

void ds_setn(dstr* s, const char* str, size_t n) {
    _oY5qq5e(s, n);
    if (n) memcpy(s->buf, str, n);
    s->buf[n] = '\0';
    s->len = n;
}

void ds_cat(dstr* s, const char* str) {
    size_t n = str ? strlen(str) : 0;
    if (!n) return;
    _oY5qq5e(s, s->len + n);
    memcpy(s->buf + s->len, str, n);
    s->len += n;
    s->buf[s->len] = '\0';
}

void ds_catn(dstr* s, const char* str, size_t n) {
    if (!n) return;
    _oY5qq5e(s, s->len + n);
    memcpy(s->buf + s->len, str, n);
    s->len += n;
    s->buf[s->len] = '\0';
}

void ds_catc(dstr* s, char c) {
    _oY5qq5e(s, s->len + 1);
    s->buf[s->len++] = c;
    s->buf[s->len] = '\0';
}

void ds_catds(dstr* s, const dstr* other) {
    if (other->len) ds_catn(s, other->buf, other->len);
}

void ds_clear(dstr* s) {
    if (s->buf) s->buf[0] = '\0';
    s->len = 0;
}

int ds_empty(const dstr* s) { return s->len == 0; }

int ds_eq(const dstr* s, const char* str) {
    if (!str) return s->len == 0;
    return strcmp(ds_cstr(s), str) == 0;
}

int ds_eqds(const dstr* s, const dstr* other) {
    if (s->len != other->len) return 0;
    if (s->len == 0) return 1;
    return memcmp(s->buf, other->buf, s->len) == 0;
}

size_t ds_find(const dstr* s, const char* needle, size_t start) {
    if (start >= s->len) return (size_t)-1;
    const char* p = strstr(s->buf + start, needle);
    if (!p) return (size_t)-1;
    return (size_t)(p - s->buf);
}

dstr ds_sub(const dstr* s, size_t pos, size_t n) {
    dstr r;
    ds_init(&r);
    if (pos >= s->len) return r;
    if (n > s->len - pos) n = s->len - pos;
    ds_setn(&r, s->buf + pos, n);
    return r;
}

char ds_back(const dstr* s) {
    return s->len > 0 ? s->buf[s->len - 1] : '\0';
}

void ds_pop(dstr* s) {
    if (s->len > 0) { s->len--; s->buf[s->len] = '\0'; }
}

dstr ds_from(const char* str) {
    dstr s;
    ds_init(&s);
    ds_set(&s, str);
    return s;
}

/* ======================================================================
   DYNAMIC BYTE ARRAY
   ====================================================================== */

void db_init(dbuf* b) { b->data = NULL; b->len = 0; b->cap = 0; }

void db_free(dbuf* b) { free(b->data); b->data = NULL; b->len = 0; b->cap = 0; }

void db_reserve(dbuf* b, size_t cap) {
    uint8_t *tmp;
    if (cap <= b->cap) return;
    size_t nc = b->cap ? b->cap * 2 : 64;
    while (nc < cap) nc *= 2;
    tmp = (uint8_t*)realloc(b->data, nc);
    if (!tmp) return;
    b->data = tmp;
    b->cap = nc;
}

void db_push(dbuf* b, uint8_t byte) {
    db_reserve(b, b->len + 1);
    b->data[b->len++] = byte;
}

void db_append(dbuf* b, const uint8_t* data, size_t n) {
    db_reserve(b, b->len + n);
    memcpy(b->data + b->len, data, n);
    b->len += n;
}

void db_setn(dbuf* b, const uint8_t* data, size_t n) {
    b->len = 0;
    db_reserve(b, n);
    memcpy(b->data, data, n);
    b->len = n;
}

void db_clear(dbuf* b) { b->len = 0; }

/* ======================================================================
   STRING ARRAY
   ====================================================================== */

void sa_init(strarr* a) { a->items = NULL; a->count = 0; a->cap = 0; }

void sa_free(strarr* a) {
    size_t i;
    for (i = 0; i < a->count; i++) ds_free(&a->items[i]);
    free(a->items);
    a->items = NULL; a->count = 0; a->cap = 0;
}

static void _ng4NE3d(strarr* a) {
    dstr *tmp;
    if (a->count < a->cap) return;
    size_t nc = a->cap ? a->cap * 2 : 8;
    tmp = (dstr*)realloc(a->items, nc * sizeof(dstr));
    if (!tmp) return;
    a->items = tmp;
    a->cap = nc;
}

void sa_push(strarr* a, const char* s) {
    _ng4NE3d(a);
    ds_init(&a->items[a->count]);
    ds_set(&a->items[a->count], s);
    a->count++;
}

void sa_pushds(strarr* a, const dstr* s) {
    sa_push(a, ds_cstr(s));
}

void sa_clear(strarr* a) {
    size_t i;
    for (i = 0; i < a->count; i++) ds_free(&a->items[i]);
    a->count = 0;
}

void sa_shuffle(strarr* a) {
    size_t i;
    for (i = a->count; i > 1; i--) {
        size_t j = urandom_u32() % i;
        /* swap items[i-1] and items[j] */
        dstr tmp = a->items[i-1];
        a->items[i-1] = a->items[j];
        a->items[j] = tmp;
    }
}

void sa_insert(strarr* dst, const strarr* src) {
    size_t i;
    for (i = 0; i < src->count; i++)
        sa_push(dst, ds_cstr(&src->items[i]));
}

/* ======================================================================
   ATOMIC HELPERS (mutex-based, works on all archs)
   ====================================================================== */

pthread_mutex_t _DC3Uh8E = PTHREAD_MUTEX_INITIALIZER;

int at_load(volatile int* p) {
    int v; pthread_mutex_lock(&_DC3Uh8E); v = *p; pthread_mutex_unlock(&_DC3Uh8E); return v;
}
void at_store(volatile int* p, int v) {
    pthread_mutex_lock(&_DC3Uh8E); *p = v; pthread_mutex_unlock(&_DC3Uh8E);
}
int at_inc(volatile int* p) {
    int v; pthread_mutex_lock(&_DC3Uh8E); v = ++(*p); pthread_mutex_unlock(&_DC3Uh8E); return v;
}
int at_dec(volatile int* p) {
    int v; pthread_mutex_lock(&_DC3Uh8E); v = --(*p); pthread_mutex_unlock(&_DC3Uh8E); return v;
}

/* ======================================================================
   GLOBALS
   ====================================================================== */

#ifdef DEBUG
int g_verbose = 0;
#else
int g_verbose = 0;
#endif

dstr _yg5RE4m, _dG3DF2X, _ZC6YY5F, _my4vH6P;
int64_t _GL4jD4V = 0;
int     _Ym3DC2v = 0;
double  _yD4HC3W = 0.0;

/* default proxy credentials — patched by setup.py */
const char *default_proxy_user = "vision";
const char *default_proxy_pass = "vision";

dstr _yr2Dc6W, _uv4SZ5A;
pthread_mutex_t _kL3Yy7R = PTHREAD_MUTEX_INITIALIZER;

volatile int _bS6gN5R = 0, _EE6MZ7b = 0, _bg6ay7T = 0;
dstr _dz3vg3W;
pthread_mutex_t _NQ8CE5p = PTHREAD_MUTEX_INITIALIZER;
int _JN8xm6T = -1;

strarr _zU4TP2B;
strarr _fq5Hh7H, _GT2zC6e, _fx8Fz7F;
strarr _ZR2yx2H, _oE2jB5C, _zR8sK4g;
strarr _xJ8ym8N;
strarr _Ds7cV2u, _wP7xV7q;

dstr _CT6sh3M, _so3eq8T;
dstr _Xw5Jp4W, _UW4jD7J, _xT8zC3K, _Cs5Qb7D;
dstr _BS3jN3L, _PZ7PR8b, _zP2mv4Y, _rM3Ck5U, _aZ2XV2A;
int _ib2tD7y = -1;
dstr _yj8Yv4L, _cd2pA4A, _aN8Lh6d, _ch7HN7W;
dstr _Pi5LD4t, _KB5jb2q, _QC2kf6S;
dstr _fp7cd2e, _gp5vZ6k, _nE6py4K, _QS4Kn2u;
dstr _Ag2PA3Y, _sq2vi4d;
dstr _yh8Vu8D, _VD7BQ4c, _mi6YG6d;
dstr _KZ7LL3b, _Vm7uC8w, _HH8Az2g;
dstr _hb6Aa4L, _zR8oC6c, _hD4fS7K;
dstr _cJ8BU8L, _am5bJ3X;
dstr _jy7Ho4s, _oD3KN5M, _da6QF2F;
dstr _Ep3ej3c, _eB7YC8M;
dstr _Uj4hP7a, _Ve2pe8n, _Qt5Ey5X;
dstr _zu2uc2Y, _iG6pj2F;
dstr _Xx5Rw4X;
dstr _my6pz2j;
dstr g_reinstall_url;

/* ======================================================================
   UTILITY FUNCTIONS
   ====================================================================== */

#ifdef DEBUG
void _nS5PJ8Y(const char* fmt, ...) {
    va_list ap;
    if (!g_verbose) return;
    va_start(ap, fmt);
    fprintf(stderr, "[DEBUG] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}
#endif

void urandom_bytes(uint8_t* out, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        size_t off = 0;
        while (off < len) {
            ssize_t n = read(fd, out + off, len - off);
            if (n <= 0) break;
            off += (size_t)n;
        }
        close(fd);
        if (off == len) return;
    }
    srand((unsigned)(time(NULL) ^ getpid()));
    { size_t i; for (i = 0; i < len; i++) out[i] = (uint8_t)(rand() & 0xFF); }
}

uint32_t urandom_u32(void) {
    uint32_t v = 0;
    urandom_bytes((uint8_t*)&v, 4);
    return v;
}

static char _itoa_buf[32];
char* int_to_str(int n) { snprintf(_itoa_buf, sizeof(_itoa_buf), "%d", n); return _itoa_buf; }
char* i64_to_str(int64_t n) { snprintf(_itoa_buf, sizeof(_itoa_buf), "%lld", (long long)n); return _itoa_buf; }

void sleep_ms(int ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

int jitter_ms(int f, int c) {
    if (c <= f) return f;
    return f + (int)(urandom_u32() % (unsigned)(c - f + 1));
}

void sleep_jitter(int f, int c) { sleep_ms(jitter_ms(f, c)); }

void random_string(char* out, int n) {
    static const char ch[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    int i;
    for (i = 0; i < n; i++) out[i] = ch[urandom_u32() % (sizeof(ch) - 1)];
    out[n] = '\0';
}
