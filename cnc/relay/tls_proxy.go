package main

// ============================================================================
// TLS PROXY SUPPORT
//
// Adds HTTPS-proxy (SSL-tunnel) mode to the existing proxy port.
//
// Protocol detection in handleProxyClient (main.go):
//   0x05 → SOCKS5
//   0x16 → TLS ClientHello → handshake → re-detect inner protocol
//   other → plain HTTP proxy
//
// Certificate:
//   -cert / -key flags load a PEM file pair.
//   If omitted (or loading fails), a self-signed ECDSA-P256 cert is generated
//   at startup (valid 10 years, in-memory only).
//
// Client usage:
//   curl -x https://user:pass@host:1080 https://target/   (self-signed: add -k)
//   Firefox/Chrome: set proxy to https://host:1080
// ============================================================================

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"time"
)

// proxyTLSConfig is set once at startup; nil means TLS proxy is disabled.
var proxyTLSConfig *tls.Config

// InitProxyTLS sets up TLS for the proxy port.
// certFile / keyFile may be empty strings — a self-signed cert is used then.
func InitProxyTLS(certFile, keyFile string) {
	var cert tls.Certificate
	var err error

	if certFile != "" && keyFile != "" {
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Printf("[TLS] Cannot load cert %q / key %q: %v — falling back to self-signed", certFile, keyFile, err)
			cert = selfSignedCert()
		} else {
			log.Printf("[TLS] Proxy TLS: loaded cert %s", certFile)
		}
	} else {
		cert = selfSignedCert()
		log.Printf("[TLS] Proxy TLS: using self-signed certificate (clients must use -k / accept untrusted)")
	}

	proxyTLSConfig = &tls.Config{
		Certificates:             []tls.Certificate{cert},
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
	}
}

// selfSignedCert generates an in-memory ECDSA P-256 self-signed certificate.
func selfSignedCert() tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("[TLS] Failed to generate ECDSA key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"Relay Proxy"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatalf("[TLS] Failed to create certificate: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		log.Fatalf("[TLS] Failed to marshal key: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatalf("[TLS] Failed to load self-signed cert: %v", err)
	}
	return cert
}
