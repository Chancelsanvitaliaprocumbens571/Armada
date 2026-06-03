package main

// ============================================================================
// HTTP / HTTPS PROXY SUPPORT
//
// Same port as SOCKS5 (1080). Protocol is auto-detected by the first byte:
//   0x05 → SOCKS5  (existing path)
//   other → HTTP proxy (this file)
//
// Supports:
//   CONNECT host:port HTTP/1.1   — HTTPS tunneling (curl -x http://...)
//   GET http://host/path HTTP/1.1 — plain HTTP proxying
//   POST/PUT/etc                  — same as GET
//
// Authentication: Proxy-Authorization: Basic base64(user:pass)
//   Same Redis credentials as SOCKS5 (pbuy:creds:<user> / pbuy:quota:<userID>)
// ============================================================================

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// bufConn wraps net.Conn with a bufio.Reader so bytes peeked for protocol
// detection are not lost when the connection is handed to HTTP or SOCKS5 handlers.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

// ── Auth helpers ─────────────────────────────────────────────────────────────

// parseProxyAuth decodes "Proxy-Authorization: Basic <b64>" → username, password.
func parseProxyAuth(r *http.Request) (username, password string, ok bool) {
	auth := r.Header.Get("Proxy-Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func proxyAuthError(conn net.Conn) {
	conn.Write([]byte(
		"HTTP/1.1 407 Proxy Authentication Required\r\n" +
			"Proxy-Authenticate: Basic realm=\"proxy\"\r\n" +
			"Proxy-Connection: close\r\n" +
			"Connection: close\r\n" +
			"Content-Length: 0\r\n\r\n"))
	conn.Close()
}

func proxyBadGateway(conn net.Conn) {
	conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
	conn.Close()
}

// ── Bot tunnel ───────────────────────────────────────────────────────────────

// openBotTunnel picks a bot matching the filter, establishes a SOCKS5-authenticated
// data channel, and sends a SOCKS5 CONNECT to the target host:port.
// Returns the bot conn ready for raw bidirectional bridging.
func openBotTunnel(host string, port uint16, f *ProxyFilter) (net.Conn, error) {
	var b *bot
	if f != nil {
		b = pickBotWithFilter(f)
	} else {
		b = pickBot()
	}
	if b == nil {
		return nil, fmt.Errorf("no bots available")
	}

	sessionID := fmt.Sprintf("%d", atomic.AddInt64(&sessionCounter, 1))
	ch := make(chan net.Conn, 1)

	pendingSessionsMu.Lock()
	pendingSessions[sessionID] = ch
	pendingSessionsMu.Unlock()

	b.mu.Lock()
	_, err := b.ctrl.Write([]byte("RELAY_NEW:" + sessionID + "\n"))
	b.mu.Unlock()
	if err != nil {
		pendingSessionsMu.Lock()
		delete(pendingSessions, sessionID)
		pendingSessionsMu.Unlock()
		return nil, fmt.Errorf("signal bot: %w", err)
	}

	select {
	case dataConn := <-ch:
		if err := botSocks5Handshake(dataConn, host, port); err != nil {
			dataConn.Close()
			return nil, err
		}
		return dataConn, nil
	case <-time.After(15 * time.Second):
		pendingSessionsMu.Lock()
		delete(pendingSessions, sessionID)
		pendingSessionsMu.Unlock()
		return nil, fmt.Errorf("bot data channel timeout")
	}
}

// botSocks5Handshake authenticates to the bot's SOCKS5 server and issues a
// CONNECT to the target. On success the conn is ready for raw data.
func botSocks5Handshake(conn net.Conn, host string, port uint16) error {
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetDeadline(time.Time{})

	// Greeting: offer userpass auth
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		return fmt.Errorf("bot greeting: %w", err)
	}
	choice := make([]byte, 2)
	if _, err := io.ReadFull(conn, choice); err != nil || choice[0] != 0x05 || choice[1] != 0x02 {
		return fmt.Errorf("bot method choice unexpected")
	}

	// Userpass auth
	user := []byte(defaultBotUser)
	pass := []byte(defaultBotPass)
	pkt := make([]byte, 3+len(user)+len(pass))
	pkt[0] = 0x01
	pkt[1] = byte(len(user))
	copy(pkt[2:], user)
	pkt[2+len(user)] = byte(len(pass))
	copy(pkt[3+len(user):], pass)
	if _, err := conn.Write(pkt); err != nil {
		return fmt.Errorf("bot auth send: %w", err)
	}
	result := make([]byte, 2)
	if _, err := io.ReadFull(conn, result); err != nil || result[1] != 0x00 {
		return fmt.Errorf("bot auth failed")
	}

	// SOCKS5 CONNECT to target (ATYP=0x03 domain name)
	hostB := []byte(host)
	req := make([]byte, 7+len(hostB))
	req[0] = 0x05 // VER
	req[1] = 0x01 // CMD CONNECT
	req[2] = 0x00 // RSV
	req[3] = 0x03 // ATYP domain
	req[4] = byte(len(hostB))
	copy(req[5:], hostB)
	req[5+len(hostB)] = byte(port >> 8)
	req[6+len(hostB)] = byte(port & 0xff)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("CONNECT send: %w", err)
	}

	// Read SOCKS5 response header (4 bytes)
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return fmt.Errorf("CONNECT resp header: %w", err)
	}
	if hdr[1] != 0x00 {
		return fmt.Errorf("CONNECT failed (REP=0x%02x)", hdr[1])
	}
	// Drain BND_ADDR + BND_PORT
	switch hdr[3] {
	case 0x01:
		io.ReadFull(conn, make([]byte, 6)) // IPv4 (4) + port (2)
	case 0x03:
		lb := make([]byte, 1)
		io.ReadFull(conn, lb)
		io.ReadFull(conn, make([]byte, int(lb[0])+2))
	case 0x04:
		io.ReadFull(conn, make([]byte, 18)) // IPv6 (16) + port (2)
	}

	return nil
}

// ── HTTP proxy entry point ────────────────────────────────────────────────────

// handleHTTPProxyClient handles inbound HTTP or HTTPS proxy requests.
// Auth is enforced on EVERY request — keep-alive connections cannot bypass it.
// CONNECT tunnels are one-shot (close after tunnel ends); plain HTTP uses
// a per-request loop so each request is individually authenticated.
func handleHTTPProxyClient(conn net.Conn, br *bufio.Reader) {
	defer conn.Close()

	for {
		conn.SetDeadline(time.Now().Add(30 * time.Second))

		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}

		// Re-authenticate on every request — no session carry-over
		username, password, ok := parseProxyAuth(req)
		if !ok {
			proxyAuthError(conn)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

		creds, err := CheckCredentials(ctx, username, password)
		if err != nil {
			cancel()
			atomic.AddInt64(&statAuthFailures, 1)
			log.Printf("[RELAY] HTTP proxy auth failed from %s: %v", conn.RemoteAddr(), err)
			proxyAuthError(conn)
			return
		}

		// Atomically pre-reserve quota to prevent concurrent-connection bypass
		const reserveBytes = int64(256 * 1024) // 256 KB
		remaining, reserveErr := ReserveQuota(ctx, creds.UserID, reserveBytes)
		cancel()
		if reserveErr != nil {
			log.Printf("[RELAY] HTTP quota check error for %s: %v", creds.UserID, reserveErr)
			conn.Write([]byte("HTTP/1.1 503 Service Unavailable\r\nProxy-Connection: close\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))
			return
		}
		if remaining < 0 {
			RefundQuota(context.Background(), creds.UserID, reserveBytes)
			log.Printf("[RELAY] HTTP quota exhausted for %s (remaining: %d)", creds.UserID, remaining)
			conn.Write([]byte("HTTP/1.1 403 Forbidden\r\nProxy-Connection: close\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))
			return
		}
		// Refund reservation — actual deduction happens per-byte in bridgeWithQuota
		RefundQuota(context.Background(), creds.UserID, reserveBytes)

		conn.SetDeadline(time.Time{})

		if req.Method == http.MethodConnect {
			// CONNECT = raw tunnel; always one-shot, connection ends after tunnel
			httpsConnect(conn, br, req, creds)
			return
		}

		// Plain HTTP: forward request, then loop to handle next request
		// (still re-authenticates on the next iteration)
		if !httpForward(conn, br, req, creds) {
			return
		}
	}
}

// httpsConnect handles CONNECT tunneling (used for HTTPS).
// br is the buffered reader wrapping conn — after reading the CONNECT request,
// br may hold the start of the TLS ClientHello in its buffer.  We must drain
// it through bridgeWithQuota or that data is silently lost and the TLS
// handshake never completes (PR_END_OF_FILE_ERROR in clients).
func httpsConnect(conn net.Conn, br *bufio.Reader, req *http.Request, creds *UserCreds) {
	host, portStr, err := net.SplitHostPort(req.Host)
	if err != nil {
		host = req.Host
		portStr = "443"
	}
	if portStr == "" {
		portStr = "443"
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	atomic.AddInt64(&statTotalSessions, 1)
	atomic.AddInt64(&statActiveSessions, 1)
	defer atomic.AddInt64(&statActiveSessions, -1)

	dataConn, err := openBotTunnel(host, uint16(port), creds.Filter)
	if err != nil {
		log.Printf("[RELAY] HTTPS CONNECT %s failed: %v", req.Host, err)
		atomic.AddInt64(&statFailedSessions, 1)
		proxyBadGateway(conn)
		return
	}

	// Confirm tunnel to client.
	// Wrap conn+br so any TLS ClientHello bytes already buffered by br
	// (read-ahead from the same TCP segment as the CONNECT request) are
	// forwarded to the bot and not silently dropped.
	conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	log.Printf("[RELAY] HTTPS CONNECT %s — bridging", req.Host)

	clientConn := &bufConn{Conn: conn, r: br}
	bridgeWithQuota(clientConn, dataConn, creds.UserID)
}

// httpForward handles plain HTTP requests (GET, POST, etc.).
// Returns true if the connection can be reused (keep-alive), false if it should close.
// Note: auth is re-checked by the caller (handleHTTPProxyClient) on every request.
func httpForward(conn net.Conn, br *bufio.Reader, req *http.Request, creds *UserCreds) bool {
	// Determine target host:port
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if host == "" {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
		return false
	}
	if !strings.Contains(host, ":") {
		host += ":80"
	}
	h, portStr, _ := net.SplitHostPort(host)
	var port int = 80
	fmt.Sscanf(portStr, "%d", &port)

	atomic.AddInt64(&statTotalSessions, 1)
	atomic.AddInt64(&statActiveSessions, 1)
	defer atomic.AddInt64(&statActiveSessions, -1)

	dataConn, err := openBotTunnel(h, uint16(port), creds.Filter)
	if err != nil {
		log.Printf("[RELAY] HTTP forward %s failed: %v", host, err)
		atomic.AddInt64(&statFailedSessions, 1)
		proxyBadGateway(conn)
		return false
	}

	// Strip proxy-specific headers and rewrite URL to relative form
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")
	req.RequestURI = req.URL.RequestURI() // convert absolute → relative
	req.URL.Host = ""
	req.URL.Scheme = ""

	if err := req.Write(dataConn); err != nil {
		dataConn.Close()
		return false
	}

	log.Printf("[RELAY] HTTP %s %s — bridging", req.Method, host)
	bridgeWithQuota(conn, dataConn, creds.UserID)
	// After bridge ends connection is closed by bridgeWithQuota — stop loop
	return false
}
