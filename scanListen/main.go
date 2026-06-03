package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	outputFile    string
	listenPort    int
	fileMutex     sync.Mutex
	credentials   = make(map[string]bool)
	credMutex     sync.RWMutex
	totalReceived int64
	uniqueCount   int64
)

func main() {
	flag.StringVar(&outputFile, "o", "credentials.txt", "Output file for credentials")
	flag.IntVar(&listenPort, "p", 9090, "Port to listen on")
	flag.Parse()

	loadExistingCredentials()

	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", listenPort))
	if err != nil {
		log.Fatalf("Failed to start listener: %v", err)
	}
	defer listener.Close()

	log.Printf("Scan listener started on port %d", listenPort)
	log.Printf("Saving credentials to: %s", outputFile)
	log.Printf("Loaded %d existing credentials", len(credentials))
	log.Println("Waiting for connections...")

	go printStats()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func loadExistingCredentials() {
	file, err := os.Open(outputFile)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		log.Printf("Warning: Could not load existing credentials: %v", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			credentials[line] = true
		}
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	log.Printf("[+] New connection from: %s", remoteAddr)

	reader := bufio.NewReader(conn)

	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Minute))

		line, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("[-] Connection closed: %s", remoteAddr)
			return
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		totalReceived++

		parsed := parseCred(line)
		if parsed == "" {
			log.Printf("[!] Invalid format from %s: %s", remoteAddr, line)
			continue
		}

		credMutex.RLock()
		exists := credentials[parsed]
		credMutex.RUnlock()

		if exists {
			log.Printf("[=] Duplicate: %s", parsed)
			continue
		}

		credMutex.Lock()
		credentials[parsed] = true
		uniqueCount++
		credMutex.Unlock()

		if err := saveCredential(parsed); err != nil {
			log.Printf("[!] Failed to save: %v", err)
			continue
		}

		log.Printf("[*] NEW: %s", parsed)
	}
}

func parseCred(line string) string {
	// Format: IP:PORT USER:PASS (from scanner)
	if strings.Contains(line, " ") {
		spaceParts := strings.SplitN(line, " ", 2)
		if len(spaceParts) == 2 && strings.Contains(spaceParts[0], ":") && strings.Contains(spaceParts[1], ":") {
			return line
		}
	}

	// Format: IP:PORT:USER:PASS
	parts := strings.SplitN(line, ":", 4)
	if len(parts) == 4 {
		return fmt.Sprintf("%s:%s %s:%s", parts[0], parts[1], parts[2], parts[3])
	}

	return ""
}

func saveCredential(cred string) error {
	fileMutex.Lock()
	defer fileMutex.Unlock()

	f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(cred + "\n")
	return err
}

func printStats() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		credMutex.RLock()
		unique := len(credentials)
		credMutex.RUnlock()
		log.Printf("[STATS] Total received: %d | Unique saved: %d", totalReceived, unique)
	}
}
