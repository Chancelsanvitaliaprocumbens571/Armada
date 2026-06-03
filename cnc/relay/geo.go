package main

// ============================================================================
// GeoIP — MaxMind GeoLite2 local database (zero HTTP, zero Redis, <1 ms)
//
// Two free MMDB files from MaxMind (https://dev.maxmind.com/geoip/geolite2-free-geolocation-data):
//   GeoLite2-City.mmdb  → country, region, city
//   GeoLite2-ASN.mmdb   → ASN number + ISP/org name
//
// Both are kept open and memory-mapped at process start.
// If the ASN database is absent, ISP/ASN fields are simply empty.
// Relay restarts re-lookup all bots in < 1 ms each — no persistence needed.
// ============================================================================

import (
	"fmt"
	"log"
	"net"
	"sync/atomic"

	"github.com/oschwald/maxminddb-golang"
)

// GeoInfo is the geolocation data attached to each bot.
type GeoInfo struct {
	IP          string
	Country     string // "US"
	CountryName string // "United States"
	Region      string // "NY"
	RegionName  string // "New York"
	City        string // "New York City"
	ISP         string // "Comcast Cable Communications" (from ASN DB)
	ASN         string // "7922"
}

// mmdbCity holds parsed fields from GeoLite2-City.mmdb.
type mmdbCity struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Subdivisions []struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
}

// mmdbASN holds parsed fields from GeoLite2-ASN.mmdb.
type mmdbASN struct {
	Number uint32 `maxminddb:"autonomous_system_number"`
	Org    string `maxminddb:"autonomous_system_organization"`
}

var (
	cityDB *maxminddb.Reader // GeoLite2-City.mmdb
	asnDB  *maxminddb.Reader // GeoLite2-ASN.mmdb (optional)

	statGeoLookups int64 // total lookups performed
	statGeoMisses  int64 // IPs not found in DB
)

// InitGeoDBs opens the MaxMind MMDB files.
// cityPath is required; asnPath is optional (pass "" to skip ISP/ASN data).
func InitGeoDBs(cityPath, asnPath string) error {
	if cityPath == "" {
		return fmt.Errorf("city DB path is empty")
	}
	r, err := maxminddb.Open(cityPath)
	if err != nil {
		return fmt.Errorf("open city DB %q: %w", cityPath, err)
	}
	cityDB = r
	log.Printf("[GEO] GeoLite2-City loaded from %s", cityPath)

	if asnPath != "" {
		r2, err := maxminddb.Open(asnPath)
		if err != nil {
			log.Printf("[GEO] WARNING: cannot open ASN DB %q: %v (ISP/ASN targeting disabled)", asnPath, err)
		} else {
			asnDB = r2
			log.Printf("[GEO] GeoLite2-ASN loaded from %s", asnPath)
		}
	}
	return nil
}

// LookupGeo resolves the geolocation of an IP address synchronously.
// Returns nil if the city database is not loaded or the IP is not found.
func LookupGeo(ip string) *GeoInfo {
	if cityDB == nil {
		return nil
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil
	}

	atomic.AddInt64(&statGeoLookups, 1)

	var city mmdbCity
	if err := cityDB.Lookup(parsed, &city); err != nil {
		atomic.AddInt64(&statGeoMisses, 1)
		return nil
	}

	g := &GeoInfo{
		IP:          ip,
		Country:     city.Country.ISOCode,
		CountryName: city.Country.Names["en"],
		City:        city.City.Names["en"],
	}
	if len(city.Subdivisions) > 0 {
		g.Region = city.Subdivisions[0].ISOCode
		g.RegionName = city.Subdivisions[0].Names["en"]
	}

	// ASN / ISP (optional second DB)
	if asnDB != nil {
		var asn mmdbASN
		if err := asnDB.Lookup(parsed, &asn); err == nil && asn.Number > 0 {
			g.ASN = fmt.Sprintf("%d", asn.Number)
			g.ISP = asn.Org
		}
	}

	return g
}

// LookupGeoAsync runs LookupGeo in a goroutine, populates b.geo,
// and inserts the bot into the geo country index.
func LookupGeoAsync(b *bot, ip string) {
	go func() {
		g := LookupGeo(ip)
		if g == nil {
			return
		}
		b.geoMu.Lock()
		b.geo = g
		b.geoMu.Unlock()
		addBotToGeoIndex(b)
		log.Printf("[GEO] %s (%s): %s/%s/%s ISP:%s ASN:%s",
			b.id, ip, g.Country, g.RegionName, g.City, g.ISP, g.ASN)
	}()
}
