package main

// ============================================================================
// RESIDENTIAL PROXY TARGETING
//
// Username format (Oxylabs-style):
//   <baseuser>[-<param>-<value>]...
//
// Supported params:
//   country-XX        ISO 2-letter country code  (e.g. country-US, country-TR)
//   city-XX           City, lowercased no spaces  (e.g. city-newyork)
//   state-XX          Region/state code           (e.g. state-CA)
//   isp-XX            ISP partial match           (e.g. isp-comcast)
//   asn-XXXX          ASN number                  (e.g. asn-7922)
//   session-XXXX      Sticky session key          (same IP for 10 min per key)
//
// Examples:
//   alice                             → any bot, rotating
//   alice-country-US                  → any US bot, rotating
//   alice-country-US-city-chicago     → US Chicago, rotating
//   alice-country-TR-session-s1       → Turkish sticky session
//   alice-session-mykey               → any bot, sticky
//
// Selection performance:
//   No filter              O(1) — round-robin on botSlice
//   Country-only filter    O(1) — geoByCountry index lookup
//   City/ISP/ASN filter    O(n_country) — scan within the country's bot slice
// ============================================================================

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ProxyFilter holds targeting parameters parsed from a proxy username.
type ProxyFilter struct {
	Country  string // "US", "TR" (uppercase, ISO 3166-1 alpha-2)
	Region   string // "CA", "NY" (uppercase)
	City     string // lowercased, spaces removed
	ISP      string // lowercased partial match
	ASN      string // numeric only, e.g. "7922"
	Session  string // sticky session key (empty = rotating)
	BaseUser string // credential key for Redis lookup
	UserID   string // resolved user ID (set after auth, scopes session keys)
}

// ParseProxyUser splits a proxy username into base credential + targeting filters.
func ParseProxyUser(username string) *ProxyFilter {
	f := &ProxyFilter{}
	parts := strings.Split(username, "-")
	keywords := map[string]bool{
		"country": true, "city": true, "region": true,
		"state": true, "isp": true, "asn": true, "session": true,
	}
	var base []string
	i := 0
	for i < len(parts) {
		kw := strings.ToLower(parts[i])
		if keywords[kw] && i+1 < len(parts) {
			switch kw {
			case "country":
				f.Country = strings.ToUpper(parts[i+1])
				i += 2
			case "city":
				f.City = strings.ToLower(parts[i+1])
				i += 2
			case "region", "state":
				f.Region = strings.ToUpper(parts[i+1])
				i += 2
			case "isp":
				f.ISP = strings.ToLower(parts[i+1])
				i += 2
			case "asn":
				f.ASN = strings.TrimPrefix(strings.ToUpper(parts[i+1]), "AS")
				i += 2
			case "session":
				// session value may contain dashes — consume rest of parts
				f.Session = strings.Join(parts[i+1:], "-")
				i = len(parts)
			}
		} else {
			base = append(base, parts[i])
			i++
		}
	}
	f.BaseUser = strings.Join(base, "-")
	return f
}

// ── Geo index (country → bot slice) ──────────────────────────────────────────
//
// Maintained alongside botSlice.  When a bot's geo resolves (async), it is
// inserted here.  When a bot disconnects, it is removed.  The country slice
// grows/shrinks with swap-remove (O(1) on disconnect per-country).

var (
	geoByCountry   = make(map[string][]*bot) // "US" → []*bot
	geoIndexMu     sync.RWMutex
)

// addBotToGeoIndex is called from the GeoIP worker goroutine after geo resolves.
func addBotToGeoIndex(b *bot) {
	b.geoMu.RLock()
	country := ""
	if b.geo != nil {
		country = b.geo.Country
	}
	b.geoMu.RUnlock()
	if country == "" {
		return
	}
	geoIndexMu.Lock()
	geoByCountry[country] = append(geoByCountry[country], b)
	geoIndexMu.Unlock()
}

// removeBotFromGeoIndex is called when a bot disconnects.
func removeBotFromGeoIndex(b *bot) {
	b.geoMu.RLock()
	country := ""
	if b.geo != nil {
		country = b.geo.Country
	}
	b.geoMu.RUnlock()
	if country == "" {
		return
	}
	geoIndexMu.Lock()
	s := geoByCountry[country]
	for i, sb := range s {
		if sb == b {
			s[i] = s[len(s)-1]
			s[len(s)-1] = nil
			geoByCountry[country] = s[:len(s)-1]
			break
		}
	}
	geoIndexMu.Unlock()
}

// ── Sticky sessions ───────────────────────────────────────────────────────────

const stickySessionTTL = 10 * time.Minute

// stickyEntry stores the bot's public IP (not a *bot pointer).
// Oxylabs-style: if the bot disconnects and reconnects with the same IP,
// the session is automatically resumed — no pointer invalidation issues.
type stickyEntry struct {
	botIP   string
	expires time.Time
}

var (
	stickySessions   = make(map[string]*stickyEntry)
	stickySessionsMu sync.Mutex
)

// findBotByIP returns the first live bot whose geo.IP matches ip.
func findBotByIP(ip string) *bot {
	botsMu.RLock()
	defer botsMu.RUnlock()
	for _, b := range botSlice {
		b.geoMu.RLock()
		match := b.geo != nil && b.geo.IP == ip
		b.geoMu.RUnlock()
		if match {
			return b
		}
	}
	return nil
}

func getSessionBot(key string) *bot {
	stickySessionsMu.Lock()
	e, ok := stickySessions[key]
	if !ok {
		stickySessionsMu.Unlock()
		return nil
	}
	if time.Now().After(e.expires) {
		delete(stickySessions, key)
		stickySessionsMu.Unlock()
		return nil
	}
	e.expires = time.Now().Add(stickySessionTTL) // sliding TTL
	ip := e.botIP
	stickySessionsMu.Unlock()

	// Resolve IP → live bot (survives bot reconnects with same IP)
	return findBotByIP(ip)
}

func setSessionBot(key string, b *bot) {
	b.geoMu.RLock()
	ip := ""
	if b.geo != nil {
		ip = b.geo.IP
	}
	b.geoMu.RUnlock()

	// If geo hasn't resolved yet, fall back to the raw connection address
	// (host part only, strip port).
	if ip == "" {
		host, _, err := net.SplitHostPort(b.addr)
		if err == nil {
			ip = host
		} else {
			ip = b.addr
		}
	}
	if ip == "" {
		return // can't pin without an IP
	}

	stickySessionsMu.Lock()
	stickySessions[key] = &stickyEntry{botIP: ip, expires: time.Now().Add(stickySessionTTL)}
	stickySessionsMu.Unlock()
}

// removeSessionsForBot is a no-op with IP-based sticky sessions.
// Sessions survive bot reconnects as long as the IP remains the same.
func removeSessionsForBot(_ *bot) {}

// ── Bot selection ─────────────────────────────────────────────────────────────

// pickBotWithFilter selects a bot matching the targeting filter.
//
// Complexity:
//   No filter              → O(1)  round-robin on botSlice
//   Country-only           → O(1)  index lookup + round-robin
//   Country + city/ISP/ASN → O(n_country) scan (much smaller than n_total)
//   No country, other dims → O(n_total) scan (rare; advise using country too)
// sessionKey returns the cache key for a sticky session, scoped to the user
// so that different users cannot share each other's sticky sessions.
func sessionKey(f *ProxyFilter) string {
	if f.UserID != "" {
		return f.UserID + ":" + f.Session
	}
	// Fallback: scope by base username if UserID not resolved
	return f.BaseUser + ":" + f.Session
}

func pickBotWithFilter(f *ProxyFilter) *bot {
	// 1. Sticky session hit — return same bot immediately
	if f.Session != "" {
		if b := getSessionBot(sessionKey(f)); b != nil {
			return b
		}
	}

	var selected *bot

	switch {
	case f.Country == "" && f.City == "" && f.Region == "" && f.ISP == "" && f.ASN == "":
		// ── No geo filter: O(1) ──────────────────────────────────────────────
		selected = pickBot()

	case f.City == "" && f.Region == "" && f.ISP == "" && f.ASN == "":
		// ── Country-only filter: O(1) ────────────────────────────────────────
		geoIndexMu.RLock()
		slice := geoByCountry[f.Country]
		n := uint64(len(slice))
		if n > 0 {
			idx := atomic.AddUint64(&botRR, 1) % n
			selected = slice[idx]
		}
		geoIndexMu.RUnlock()

	default:
		// ── Multi-dim filter: O(n_country) or O(n_total) ────────────────────
		// Build pool: prefer country slice if country is specified.
		var pool []*bot
		if f.Country != "" {
			geoIndexMu.RLock()
			cs := geoByCountry[f.Country]
			if len(cs) > 0 {
				pool = make([]*bot, len(cs))
				copy(pool, cs)
			}
			geoIndexMu.RUnlock()
		} else {
			botsMu.RLock()
			pool = make([]*bot, len(botSlice))
			copy(pool, botSlice)
			botsMu.RUnlock()
		}

		// Filter within pool
		candidates := pool[:0] // reuse same backing array
		for _, b := range pool {
			b.geoMu.RLock()
			geo := b.geo
			b.geoMu.RUnlock()
			if geo != nil && geoMatches(geo, f) {
				candidates = append(candidates, b)
			}
		}
		if len(candidates) > 0 {
			idx := atomic.AddUint64(&botRR, 1) % uint64(len(candidates))
			selected = candidates[idx]
		}
	}

	// 2. Register sticky session for future requests (scoped to this user)
	if selected != nil && f.Session != "" {
		setSessionBot(sessionKey(f), selected)
	}
	return selected
}

// geoMatches returns true if the geo satisfies all non-empty filter fields.
func geoMatches(geo *GeoInfo, f *ProxyFilter) bool {
	if f.Country != "" && !strings.EqualFold(geo.Country, f.Country) {
		return false
	}
	if f.Region != "" && !strings.EqualFold(geo.Region, f.Region) {
		return false
	}
	if f.City != "" {
		norm := strings.ToLower(strings.ReplaceAll(geo.City, " ", ""))
		if !strings.Contains(norm, f.City) {
			return false
		}
	}
	if f.ISP != "" && !strings.Contains(strings.ToLower(geo.ISP), f.ISP) {
		return false
	}
	if f.ASN != "" && geo.ASN != f.ASN {
		return false
	}
	return true
}
