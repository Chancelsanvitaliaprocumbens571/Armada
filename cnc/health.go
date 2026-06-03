package main

import (
	"sync"
	"time"
)

// In-memory reconnect tracker for health scoring
var (
	botReconnects     = make(map[string]int)
	botReconnectsLock sync.Mutex
)

// RecordBotReconnect increments reconnect count for a bot
func RecordBotReconnect(botID string) {
	botReconnectsLock.Lock()
	botReconnects[botID]++
	botReconnectsLock.Unlock()
}

// GetBotReconnectCount returns how many times a bot has reconnected
func GetBotReconnectCount(botID string) int {
	botReconnectsLock.Lock()
	defer botReconnectsLock.Unlock()
	return botReconnects[botID]
}

// CalculateHealthScore returns a 0-100 health score for a connected bot.
func CalculateHealthScore(bot *BotConnection) int {
	score := 0

	// Ping freshness (40 points)
	sincePing := time.Since(bot.lastPing)
	switch {
	case sincePing < 30*time.Second:
		score += 40
	case sincePing < 60*time.Second:
		score += 35
	case sincePing < 120*time.Second:
		score += 25
	case sincePing < 300*time.Second:
		score += 15
	}

	// Uptime (20 points)
	uptime := time.Since(bot.connectedAt)
	switch {
	case uptime > 24*time.Hour:
		score += 20
	case uptime > 6*time.Hour:
		score += 15
	case uptime > 1*time.Hour:
		score += 10
	case uptime > 10*time.Minute:
		score += 5
	default:
		score += 2
	}

	// RAM (15 points)
	switch {
	case bot.ram >= 2048:
		score += 15
	case bot.ram >= 1024:
		score += 12
	case bot.ram >= 512:
		score += 9
	case bot.ram >= 256:
		score += 6
	default:
		score += 3
	}

	// CPU cores (10 points)
	switch {
	case bot.cpuCores > 4:
		score += 10
	case bot.cpuCores > 2:
		score += 8
	case bot.cpuCores > 1:
		score += 5
	default:
		score += 3
	}

	// Stability (15 points)
	reconnects := GetBotReconnectCount(bot.botID)
	switch {
	case reconnects == 0:
		score += 15
	case reconnects == 1:
		score += 12
	case reconnects <= 3:
		score += 8
	case reconnects <= 5:
		score += 4
	}

	return score
}
