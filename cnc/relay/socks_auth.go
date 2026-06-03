package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"
)

const (
	socks5Version   = 0x05
	authUserPass    = 0x02
	authNoAcceptable = 0xFF
	authSuccess     = 0x00
	authFailure     = 0x01
)

// Socks5Authenticate performs SOCKS5 username/password sub-negotiation,
// verifies credentials against Redis, and checks the user has remaining quota.
// On success the connection is ready to receive the SOCKS5 CONNECT request.
func Socks5Authenticate(conn net.Conn) (*UserCreds, error) {
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	defer conn.SetDeadline(time.Time{})

	// Read VER + NMETHODS
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	if header[0] != socks5Version {
		return nil, fmt.Errorf("not SOCKS5 (got 0x%02x)", header[0])
	}
	nmethods := int(header[1])
	if nmethods == 0 {
		conn.Write([]byte{socks5Version, authNoAcceptable})
		return nil, fmt.Errorf("no auth methods offered")
	}

	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return nil, fmt.Errorf("read methods: %w", err)
	}

	// Require username/password auth (0x02)
	hasUserPass := false
	for _, m := range methods {
		if m == authUserPass {
			hasUserPass = true
			break
		}
	}
	if !hasUserPass {
		conn.Write([]byte{socks5Version, authNoAcceptable})
		return nil, fmt.Errorf("client did not offer username/password auth")
	}
	if _, err := conn.Write([]byte{socks5Version, authUserPass}); err != nil {
		return nil, err
	}

	// Read sub-negotiation: VER ULEN USER PLEN PASS
	subVer := make([]byte, 1)
	if _, err := io.ReadFull(conn, subVer); err != nil || subVer[0] != 0x01 {
		return nil, fmt.Errorf("bad sub-negotiation version")
	}

	ulenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, ulenBuf); err != nil {
		return nil, err
	}
	username := make([]byte, ulenBuf[0])
	if _, err := io.ReadFull(conn, username); err != nil {
		return nil, err
	}

	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, plenBuf); err != nil {
		return nil, err
	}
	password := make([]byte, plenBuf[0])
	if _, err := io.ReadFull(conn, password); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Verify credentials
	creds, err := CheckCredentials(ctx, string(username), string(password))
	if err != nil {
		atomic.AddInt64(&statAuthFailures, 1)
		conn.Write([]byte{0x01, authFailure})
		return nil, fmt.Errorf("auth failed for %q: %w", string(username), err)
	}

	// Atomically pre-reserve a small quota block to prevent concurrent
	// connections from all passing the quota check before any deduction occurs.
	// If the reservation drives the balance negative, quota is exhausted.
	const reserveBytes = int64(256 * 1024) // 256 KB reservation per connection
	remaining, err := ReserveQuota(ctx, creds.UserID, reserveBytes)
	if err != nil {
		// Redis error — fail closed (deny connection) to prevent free usage
		conn.Write([]byte{0x01, authFailure})
		return nil, fmt.Errorf("quota check failed for %s: %w", creds.UserID, err)
	}
	if remaining < 0 {
		// Quota exhausted — refund the reservation and reject
		RefundQuota(context.Background(), creds.UserID, reserveBytes)
		conn.Write([]byte{0x01, authFailure})
		return nil, fmt.Errorf("quota exhausted for user %s (remaining: %d)", creds.UserID, remaining)
	}
	// Refund the reservation — actual usage is deducted per-byte during bridging
	RefundQuota(context.Background(), creds.UserID, reserveBytes)

	conn.Write([]byte{0x01, authSuccess})
	return creds, nil
}
