```
                                                _____                            .___       
                                               /  _  \_______  _____ _____     __| _/____   
                                              /  /_\  \_  __ \/     \\__  \   / __ |\__  \  
                                             /    |    \  | \/  Y Y  \/ __ \_/ /_/ | / __ \_
                                             \____|__  /__|  |__|_|  (____  /\____ |(____  /
                                                     \/            \/     \/      \/     \/
                                  1. a fleet of warships 2. a large force or group usually of moving things               
```

<p align="center">
  <img src="https://img.shields.io/badge/agent-Pure%20C-blue?style=flat-square" alt="Agent">
  <img src="https://img.shields.io/badge/C2-Go%20%2B%20Tor-green?style=flat-square" alt="C2">
  <img src="https://img.shields.io/badge/binary-~80KB%20static-red?style=flat-square" alt="Size">
  <img src="https://img.shields.io/badge/crypto-X25519%20%2B%20ChaCha20--Poly1305%20%2B%20AES--256-purple?style=flat-square" alt="Crypto">
  <img src="https://img.shields.io/badge/architectures-14-orange?style=flat-square" alt="Arch">
</p>

---

## Overview

> "This ELF binary is a sophisticated Linux botnet agent, likely a variant of the Mirai or Gafgyt families, featuring DDoS capabilities, credential brute-forcing, and rootkit functionality. It establishes persistence through multiple vectors: creating systemd services, modifying crontabs, and implementing an LD_PRELOAD rootkit by dropping a shared object to '/usr/lib/libproc.so' and modifying '/etc/ld.so.preload'. The sample contains a command-and-control (C2) dispatcher supporting commands for various DDoS attacks (TCP, UDP, HTTP, DNS floods), SOCKS proxying, and remote shell execution. It includes a built-in Telnet/SSH brute-forcer with a hardcoded credential list and anti-honeypot checks (searching for 'cowrie' and 'kippo' paths). Additionally, it attempts to disable system watchdogs and sets its OOM score to prevent termination by the kernel."

> -- VirusTotal AI Insights
---

## Setup

```bash
python3 setup.py
```

One wizard. Generates all crypto keys, obfuscates C2 through multiple encryption layers, configures credentials, cross-compiles 14 architectures, packs binaries. Deployed from zero in under 5 minutes.

---

## Capabilities

### Encryption & Transport

- **Custom protocol** -- X25519 ephemeral DH, HMAC-SHA256 key derivation, ChaCha20 stream cipher with per-direction keys
- **Dual-layer config encryption** -- AES-256-CTR outer + ChaCha20-Poly1305 AEAD inner, two independent key pairs
- **C2 address obfuscation** -- HMAC-SHA256 integrity + ChaCha20 + XOR rotation + Base64, nested inside dual-layer blob
- **~600 lines of pure C crypto** -- ChaCha20, Poly1305, AES-256, SHA-256, HMAC-SHA256, X25519

### Stealth & Evasion

- **LD_PRELOAD rootkit** -- hooks `readdir`, `readdir64`, `stat`, `lstat`, `access`, `open`, `openat`, `fopen` to hide from `ps`, `top`, `netstat`, `ss`, `ls`, `find`
- **Process disguise** -- `argv[0]` + `prctl(PR_SET_NAME)` impersonates kernel threads from encrypted name pool
- **Double-fork daemon** -- fully orphaned, no controlling terminal, OOM score -1000
- **Sandbox detection** -- nanosecond timing (CLOCK_MONOTONIC), syscall overhead measurement, /proc scanning for analysis tools

### Persistence

- **Triple-layer** -- systemd unit (auto-restart, stale binary re-download) + rc.local injection + cron (2h interval)
- **Rootkit reactivation** -- detects and re-enables existing LD_PRELOAD on startup
- **Smart re-download** -- only fetches loader if missing or older than 30 minutes

### Killer Module

- **Process scanning** -- pattern matching against `/proc/*/cmdline` and `/proc/*/exe`
- **Deleted binary detection** -- kills any process running from a `(deleted)` binary
- **Port reclamation** -- `/proc/net/tcp` inode tracing to PID, kill + bind to prevent restart

### Attack Engine (16 vectors)

| Layer | Vectors |
|-------|---------|
| **L4 UDP** | Raw UDP, UDP-Plain, VSE amplification, DNS amplification |
| **L4 TCP** | SYN, ACK, STOMP, XMAS, All-Flags, Fragmented, Micro-SYN, Asymmetric |
| **Tunnel** | GRE-IP, GRE-ETH (bypasses stateful DDoS filters) |
| **L7** | HTTP/HTTPS flood, OVH-targeted variant |

Full IP spoofing, TTL/TOS/DF manipulation, CIDR targeting, per-flag control. 15 concurrent attacks per node. Fork-isolated with duration timers.

### Scanners (3 modules)

| Scanner | Target | Method |
|---------|--------|--------|
| Telnet | Port 23 | 128 concurrent connections, weighted dictionary |
| SSH | Port 22 | Configurable combo lists |
| HTTP | Custom | Exploit payloads, response pattern matching |


All scanners feed into a **work-stealing job system** -- C2 distributes target lists across the fleet, tracks real-time progress, collects credentials, exports CSV.

### SOCKS5 Proxy

Full RFC 1928/1929 implementation. IPv4, IPv6, domain connect. Username/password auth. Bidirectional relay with idle timeouts. Direct listener mode or backconnect relay mode (bot IP never exposed to end user).

### C2 Server

- **Three interfaces** -- Bubble Tea TUI, web panel, telnet split console
- **Web panel** -- SSE streaming, live bot table, scan progress, attack history, webhooks (Discord/Telegram), CSV export
- **Tor hidden service** -- built-in daemon, persistent `.onion`, ed25519 keys
- **WebSocket shell** -- real-time bidirectional streaming with per-bot cwd tracking
- **Persistent task queue** -- auto-dispatched on connect with run-once tracking
- **Bot groups** -- tag and target commands by group
- **Relay network** -- backconnect SOCKS5 (Redis metrics, round-robin LB) + admin relay (hides C2 IP)

### C2 Resilience

- **Multi-address pool** -- up to 5 C2 addresses, Fisher-Yates shuffled per attempt
- **Exponential backoff** -- 1s quick -> 4s jitter -> 5s/10s/20s/30s cap
- **DGA fallback** -- 20 domains/day when hardcoded addresses exhausted, background primary retry
- **Dynamic pool expansion** -- loads additional entries after each failed round

---

## Security Researcher Analysis

This section documents Armada's design decisions from a technical analysis perspective -- what makes it resistant to common detection and reversal techniques, and where analysts should focus.

### Binary Analysis

```
  DISK                          MEMORY
  +------------------+          +------------------+
  | Static ELF       |          | Double-fork      |
  | ~80KB packed     |   --->   | daemon process   |
  | Stripped symbols  |          | argv[0] spoofed  |
  | No section hdrs  |          | OOM score -1000  |
  | No UPX signature |          | LD_PRELOAD hooks |
  +------------------+          +------------------+
         |                              |
         v                              v
  +------------------+          +------------------+
  | m30w packer      |          | All strings      |
  | Custom UPX fork  |          | decrypted at     |
  | upx -d fails     |          | runtime via      |
  | No magic bytes   |          | pthread_once()   |
  +------------------+          +------------------+
```

- **No symbols, no section headers** -- standard tools like `nm`, `objdump -t` yield nothing. IDA/Ghidra require manual function boundary identification.
- **m30w packer** -- modified UPX with signature bytes removed. `upx -d` fails, Detect-It-Easy shows no known packer. Manual unpacking required (breakpoint on `mprotect` or dump from `/proc/pid/mem`).
- **Lazy decryption** -- config strings encrypted at rest, decrypted once on first access via `pthread_once()`. Memory dump before C2 connection yields partial config only.

### Network Fingerprinting

```
  HANDSHAKE FLOW:
  
  Client --> Server:  "VPE2" || nonce(32) || x25519_pub(32)     [68 bytes]
  Server --> Client:  nonce(32) || x25519_pub(32)               [64 bytes]
  
  DERIVED KEYS:
  session   = HMAC-SHA256(magic, client_nonce || server_nonce || shared_secret)
  c2s_key   = HMAC-SHA256(session, "c2s")
  s2c_key   = HMAC-SHA256(session, "s2c")  
  hmac_key  = HMAC-SHA256(session, "hmac")
  
  POST-HANDSHAKE:
  All frames ChaCha20 encrypted + HMAC authenticated
  No plaintext protocol identifiers after initial "VPE2" tag
```

- **Forward secrecy** -- ephemeral X25519 per session. Compromising the static magic code allows active MITM but does not decrypt recorded traffic.
- **No TLS** -- custom protocol means no JA3/JA4 fingerprint, no certificate to pivot on. Detection requires signature on the 68-byte handshake pattern or traffic analysis (fixed initial sizes + encrypted payload).
- **Tor transport** -- when running over `.onion`, standard network monitoring sees only Tor traffic. No clearnet C2 indicator.

### Sandbox Evasion

```
  +-- timing_check() ----+     +-- /proc scan ----------+
  |                       |     |                         |
  | nanosleep(50ns)       |     | for each /proc/PID:    |
  | measure actual delay  |     |   read cmdline          |
  | threshold: 500us      |     |   match against         |
  | 2/3 rounds must fail  |     |   encrypted name list   |
  |                       |     |   (VMware, QEMU, etc)   |
  | getpid() x50          |     |                         |
  | measure overhead      |     | skip self + parent PID  |
  | threshold: 1ms        |     |                         |
  | catches ptrace/strace |     |                         |
  +-----------------------+     +-------------------------+
           |                              |
           v                              v
       FAIL = exit(0)              FAIL = exit(0)
       silently                    silently
```

- **Two-stage detection** -- timing runs first (cheap, no I/O). Process scan runs second. Either stage failing causes silent exit with code 0 (no crash, no suspicious error).
- **Timing thresholds** -- calibrated to pass on real hardware under normal load but catch VM overhead and tracing tools. nanosleep delta >500us or getpid batch >1ms = sandbox.
- **Encrypted indicator list** -- sandbox process names (VMware, QEMU, VirtualBox, Cuckoo, etc.) stored encrypted, decrypted at runtime. Static analysis of the binary does not reveal what it scans for.

### Persistence Recovery Matrix

```
  REMOVAL METHOD          WHAT SURVIVES              RECOVERY TIME
  +-----------------+     +--------------------+     +-------------+
  | Kill process    | --> | systemd restarts   | --> | ~5 seconds  |
  | Remove binary   | --> | cron re-downloads  | --> | ~2 hours    |
  | Delete cron     | --> | systemd + rc.local | --> | next boot   |
  | Delete unit     | --> | cron + rc.local    | --> | ~2 hours    |
  | Delete rc.local | --> | systemd + cron     | --> | ~5 sec/2h   |
  | Remove rootkit  | --> | persist re-enables | --> | next start  |
  | Remove all 3    | --> | running process    | --> | still alive |
  +-----------------+     +--------------------+     +-------------+
  
  Full cleanup requires: kill process + remove binary + delete all
  three persistence mechanisms + remove rootkit -- in one operation,
  before any recovery timer fires.
```

### Rootkit Hook Coverage

```
  TOOL        USES            HOOKED?    RESULT
  ps          readdir /proc   YES        bot PID hidden
  top         readdir /proc   YES        bot PID hidden
  htop        readdir /proc   YES        bot PID hidden
  ls          readdir         YES        bot files hidden
  find        stat/lstat      YES        bot paths return ENOENT
  cat         open/fopen      YES        rootkit files return ENOENT
  netstat     open /proc/net  YES        bot ports hidden
  ss          open /proc/net  YES        bot ports hidden
  stat        stat            YES        bot paths return ENOENT
  strace      (tracing)       DETECTED   timing check catches it
```

---

## Supported Architectures

| # | Architecture | Toolchain | Binary |
|---|-------------|-----------|--------|
| 1 | x86_64 | Native GCC | `redis-daemon` |
| 2 | i586 | GCC 4.1.2 / uClibc | `redis-proxyd` |
| 3 | i486 | GCC 4.1.2 / uClibc | `redis-initd` |
| 4 | MIPS (BE) | GCC 4.1.2 / uClibc | `redis-credentiald` |
| 5 | MIPSEL (LE) | GCC 4.1.2 / uClibc | `redis-composd` |
| 6 | ARMv4l | GCC 4.1.2 / uClibc | `redis-conteinerd` |
| 7 | ARMv5l | GCC 4.1.2 / uClibc | `redis-conteinerd-shim` |
| 8 | ARMv6l | GCC 4.1.2 / uClibc | `redis-runcd` |
| 9 | ARMv7l | GCC 4.1.2 / uClibc | `redis-buildxd` |
| 10 | PowerPC | GCC 4.1.2 / uClibc | `redis-scoutd` |
| 11 | SH4 | GCC 4.1.2 / uClibc | `redis-sbomd` |
| 12 | ARC700 | GCC / uClibc | `redis-swarmd` |
| 13 | m68k | GCC 4.1.2 / uClibc | `redis-scand` |
| 14 | SPARC | GCC 4.1.2 / uClibc | `redis-machined` |

Static-linked, stripped, packed with **m30w** (custom UPX fork -- zero UPX fingerprint, defeats `upx -d` and all signature scanners).

---

## Protocol Reference

### VPE2 Handshake

```
  Bot                                          CNC
   |                                            |
   |--- "VPE2" + client_nonce (32B) ----------->|
   |           + client_x25519_pub (32B)        |
   |                                            |
   |<---------- server_nonce (32B) -------------|
   |            + server_x25519_pub (32B)       |
   |                                            |
   |  shared = X25519(priv, their_pub)          |
   |  session = HMAC(magic, nonces + shared)    |
   |  c2s/s2c/hmac keys derived                 |
   |                                            |
   |<======== ChaCha20 + HMAC frames ========>  |
```

### Config Encryption

```
  Plaintext --> ChaCha20-Poly1305 AEAD (key2) --> AES-256-CTR (key1) --> hex --> config.c
```

### Command Frame

```
  +------+----------+------------+------------------+
  | 0xFF | cmd_id   | arg_len    | args             |
  | (1B) | (1B)     | (2B, BE)   | (N bytes)        |
  +------+----------+------------+------------------+
```

### Command Table

| ID | Command | Description |
|----|---------|-------------|
| `0x01` | `!shell` | Blocking shell execution |
| `0x02` | `!stream` | Real-time streaming exec |
| `0x03` | `!detach` | Background/daemon exec |
| `0x04` | `!info` | System info query |
| `0x05` | `!socks` | Start SOCKS5 proxy |
| `0x06` | `!stopsocks` | Stop SOCKS5 proxy |
| `0x0B` | `!attack` | Launch DDoS attack |
| `0x0C` | `!stopattack` | Stop all attacks |
| `0x0E` | `!kill` | Self-destruct |
| `0x14` | `!zyxel` | Zyxel scanner |
| `0x1C` | `!download` | Download + execute |
| `0x20` | `!ssh` | SSH scanner |
| `0x22` | `!http` | HTTP exploit scanner |
| `0x24` | `!redis` | Redis scanner |
| `0x26` | `!pgsql` | PostgreSQL scanner |
| `0x28` | `!mysql` | MySQL scanner |
| `0x0D` | `!reinstall` | Mass reinstall |

---

## Crypto Stack

| Primitive | Standard | Purpose |
|-----------|----------|---------|
| X25519 | Curve25519 | Ephemeral key exchange, forward secrecy |
| ChaCha20 | RFC 8439 | Transport cipher, config inner layer |
| Poly1305 | RFC 8439 | AEAD tag on config blobs |
| AES-256 | FIPS 197 | Config outer layer (CTR mode) |
| SHA-256 | FIPS 180-4 | Key derivation, integrity, auth |
| HMAC-SHA256 | RFC 2104 | VPE2 keys, frame authentication |

All implemented in pure C. Zero external libraries. ~600 lines total.

---

## Build Modes

| Mode | Flags | Size | Includes |
|------|-------|------|----------|
| **Full** | *(none)* | ~120KB | DDoS + scanners + SOCKS + shell + rootkit + persist |
| **No Attack** | `NO_ATTACK=1` | ~100KB | Scanners + SOCKS + shell + rootkit + persist |
| **No Selfrep** | `NO_SELFREP=1` | ~105KB | DDoS + SOCKS + shell + rootkit + persist |
| **Minimal** | Both flags | ~80KB | SOCKS + shell + rootkit + persist |

---

## Project Structure

```
armada/
+-- bot/                    Pure C agent
|   +-- headers/            Type definitions, protocol wire format
|   +-- main.c              Entry, init, reconnection state machine
|   +-- connection.c        VPE2 handshake, C2 command loop
|   +-- commands.c          30+ command handlers
|   +-- config.c            60+ encrypted config blobs, lazy decryption
|   +-- crypto.c            AES-256, ChaCha20-Poly1305, SHA-256, X25519
|   +-- rootkit.c           LD_PRELOAD .so: readdir/stat/open hooks
|   +-- persist.c           systemd + rc.local + cron
|   +-- opsec.c             Sandbox, spoof, killer, OOM, daemon
|   +-- socks.c             SOCKS5 + relay backconnect
|   +-- attack.c            Attack dispatcher, CIDR, fork mgmt
|   +-- attack_method.c     16 DDoS vectors (raw sockets, GRE)
|   +-- telnet.c            Telnet scanner (128 concurrent)
|   +-- ssh.c               SSH credential scanner
|   +-- scanner_*.c         HTTP, Redis, PostgreSQL, MySQL scanners
|   +-- zyxel.c             Zyxel exploit scanner
|
+-- cnc/                    C2 server (Go)
|   +-- main.go             Multi-port listener, config
|   +-- connection.go       VPE2 accept, auth, ping/pong
|   +-- cmd.go              Binary command encoder, broadcast
|   +-- ui.go               Bubble Tea TUI dashboard
|   +-- web.go              Web panel, REST API, SSE, webhooks
|   +-- websocket.go        Real-time shell over WebSocket
|   +-- scanner_jobs.go     Work-stealing scan queue
|   +-- tor.go              Tor hidden service lifecycle
|   +-- relay/              Backconnect SOCKS5 relay
|   +-- admin_relay/        Transparent TCP forwarder
|   +-- web/                Frontend (dashboard + app.js)
|
+-- scanListen/             Standalone credential collector
+-- tools/                  Build scripts, m30w packer, DGA predictor
+-- setup.py                Interactive setup wizard
```

Cause boats needs captains   

---

