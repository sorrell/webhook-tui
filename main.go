package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	"github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/reflow/wrap"
	_ "modernc.org/sqlite"
)

var (
	dbPath               = filepath.Join(os.Getenv("HOME"), ".webhook-tui", "webhooks.db")
	db                   *sql.DB
	pageSize             = 20
	defaultTunnelTimeout = 30 * time.Minute
)

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("205")).
			Background(lipgloss.Color("235")).
			Padding(0, 1)

	infoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241"))

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("82"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196"))

	highlightStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("212"))

	selectedStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("205")).
			Padding(0, 1)

	webhookItemStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("240")).
				Padding(0, 1).
				MarginBottom(1)

	webhookSelectedStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("205")).
				Padding(0, 1).
				MarginBottom(1)

	headerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("39")).
			Bold(true)

	bodyStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("252"))

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241")).
			Italic(true)
)

// WebhookPayload represents an incoming webhook
type WebhookPayload struct {
	ID        int               `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body"`
	BodyJSON  interface{}       `json:"body_json,omitempty"`
}

// State represents the current view/state of the application
type State int

const (
	StateSetup State = iota
	StateRunning
	StateDetail
)

// ViewMode represents how webhooks are displayed
type ViewMode int

const (
	ViewModeList ViewMode = iota
	ViewModeTable
)

// Model is the main application model
type Model struct {
	state          State
	portInput      textinput.Model
	subdomainInput textinput.Model
	timeoutInput   textinput.Model
	focusedInput   int
	spinner        spinner.Model
	viewport       viewport.Model
	viewportReady  bool

	publicIP           string
	fetchingIP         bool
	tunnelURL          string
	tunnelRunning      bool
	tunnelExpired      bool // true when auto-shutdown occurred
	tunnelError        string
	serverRunning      bool
	requestedPort      string
	requestedSubdomain string
	tunnelTimeout      time.Duration // how long before auto-shutdown
	tunnelStartTime    time.Time     // when tunnel was started

	webhooks       []WebhookPayload
	webhooksMu     sync.Mutex
	selectedIdx    int
	webhookChan    chan WebhookPayload
	viewMode       ViewMode

	// Pagination
	currentPage    int
	totalPages     int
	totalWebhooks  int

	width          int
	height         int

	tunnelCmd      *exec.Cmd
}

// Messages
type publicIPMsg string
type publicIPErrMsg error
type tunnelStartedMsg struct {
	url string
	cmd *exec.Cmd
}
type tunnelErrorMsg string
type serverStartedMsg struct{}
type webhookReceivedMsg WebhookPayload
type webhooksLoadedMsg struct {
	webhooks      []WebhookPayload
	totalCount    int
	currentPage   int
}
type dbErrorMsg string
type tunnelExpiredMsg struct{}

func initDB() error {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return err
	}

	var err error
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS webhooks (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			method TEXT,
			path TEXT,
			headers TEXT,
			body TEXT,
			body_json TEXT
		)
	`)
	return err
}

func saveWebhookToDB(payload WebhookPayload) error {
	if db == nil {
		return fmt.Errorf("database not initialized")
	}

	headersJSON, _ := json.Marshal(payload.Headers)
	bodyJSON := ""
	if payload.BodyJSON != nil {
		b, _ := json.Marshal(payload.BodyJSON)
		bodyJSON = string(b)
	}

	// Store timestamp in RFC3339 format for consistent parsing
	_, err := db.Exec(`
		INSERT INTO webhooks (timestamp, method, path, headers, body, body_json)
		VALUES (?, ?, ?, ?, ?, ?)
	`, payload.Timestamp.Format(time.RFC3339), payload.Method, payload.Path, string(headersJSON), payload.Body, bodyJSON)

	return err
}

func loadWebhooksFromDB(page int) tea.Cmd {
	return func() tea.Msg {
		if db == nil {
			return dbErrorMsg("Database not initialized")
		}

		// Get total count
		var totalCount int
		err := db.QueryRow("SELECT COUNT(*) FROM webhooks").Scan(&totalCount)
		if err != nil {
			return dbErrorMsg(fmt.Sprintf("Failed to count webhooks: %v", err))
		}

		offset := page * pageSize
		rows, err := db.Query(`
			SELECT id, timestamp, method, path, headers, body, body_json
			FROM webhooks
			ORDER BY id DESC
			LIMIT ? OFFSET ?
		`, pageSize, offset)
		if err != nil {
			return dbErrorMsg(fmt.Sprintf("Failed to load webhooks: %v", err))
		}
		defer rows.Close()

		var webhooks []WebhookPayload
		for rows.Next() {
			var w WebhookPayload
			var headersJSON, bodyJSON string
			var timestamp string

			err := rows.Scan(&w.ID, &timestamp, &w.Method, &w.Path, &headersJSON, &w.Body, &bodyJSON)
			if err != nil {
				continue
			}

			// Try multiple timestamp formats
			for _, format := range []string{
				time.RFC3339,
				"2006-01-02T15:04:05Z07:00",
				"2006-01-02 15:04:05",
				"2006-01-02T15:04:05",
			} {
				if t, err := time.Parse(format, timestamp); err == nil {
					w.Timestamp = t
					break
				}
			}
			json.Unmarshal([]byte(headersJSON), &w.Headers)
			if bodyJSON != "" {
				json.Unmarshal([]byte(bodyJSON), &w.BodyJSON)
			}

			webhooks = append(webhooks, w)
		}

		return webhooksLoadedMsg{
			webhooks:    webhooks,
			totalCount:  totalCount,
			currentPage: page,
		}
	}
}

func initialModel() Model {
	portInput := textinput.New()
	portInput.Placeholder = "8098"
	portInput.Focus()
	portInput.CharLimit = 5
	portInput.Width = 20

	subdomainInput := textinput.New()
	subdomainInput.Placeholder = "my-webhook-listener"
	subdomainInput.CharLimit = 50
	subdomainInput.Width = 30

	timeoutInput := textinput.New()
	timeoutInput.Placeholder = "30"
	timeoutInput.CharLimit = 4
	timeoutInput.Width = 10

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	return Model{
		state:          StateSetup,
		portInput:      portInput,
		subdomainInput: subdomainInput,
		timeoutInput:   timeoutInput,
		focusedInput:   0,
		spinner:        s,
		fetchingIP:     true,
		webhooks:       make([]WebhookPayload, 0),
		webhookChan:    make(chan WebhookPayload, 100),
		viewMode:       ViewModeTable, // Table view by default
		currentPage:    0,
		tunnelTimeout:  defaultTunnelTimeout,
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		textinput.Blink,
		m.spinner.Tick,
		fetchPublicIP,
		loadWebhooksFromDB(0), // Load previous webhooks on startup
	)
}

// Commands
func fetchPublicIP() tea.Msg {
	resp, err := http.Get("https://api.ipify.org")
	if err != nil {
		// Try backup service
		resp, err = http.Get("https://ifconfig.me/ip")
		if err != nil {
			return publicIPErrMsg(err)
		}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return publicIPErrMsg(err)
	}

	return publicIPMsg(strings.TrimSpace(string(body)))
}

func startTunnel(port, subdomain string) tea.Cmd {
	return func() tea.Msg {
		args := []string{"localtunnel", "--port", port}
		if subdomain != "" {
			args = append(args, "--subdomain", subdomain)
		}

		cmd := exec.Command("npx", args...)
		// Set process group so we can kill all children on exit
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return tunnelErrorMsg(fmt.Sprintf("Failed to create stdout pipe: %v", err))
		}

		if err := cmd.Start(); err != nil {
			return tunnelErrorMsg(fmt.Sprintf("Failed to start localtunnel: %v", err))
		}

		// Read the URL from stdout
		buf := make([]byte, 1024)
		n, err := stdout.Read(buf)
		if err != nil {
			return tunnelErrorMsg(fmt.Sprintf("Failed to read tunnel URL: %v", err))
		}

		output := string(buf[:n])
		// Parse out the URL from localtunnel output
		// Output typically looks like: "your url is: https://xxx.loca.lt"
		url := output
		if idx := strings.Index(output, "https://"); idx != -1 {
			url = strings.TrimSpace(output[idx:])
			if newline := strings.Index(url, "\n"); newline != -1 {
				url = url[:newline]
			}
		}

		return tunnelStartedMsg{url: url, cmd: cmd}
	}
}

func (m *Model) startWebhookServer() tea.Cmd {
	return func() tea.Msg {
		port := m.portInput.Value()
		if port == "" {
			port = "8098"
		}

		webhookChan := m.webhookChan
		counter := 0
		counterMu := &sync.Mutex{}

		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Failed to read body", http.StatusBadRequest)
				return
			}
			defer r.Body.Close()

			counterMu.Lock()
			counter++
			id := counter
			counterMu.Unlock()

			headers := make(map[string]string)
			for k, v := range r.Header {
				headers[k] = strings.Join(v, ", ")
			}

			payload := WebhookPayload{
				ID:        id,
				Timestamp: time.Now(),
				Method:    r.Method,
				Path:      r.URL.Path,
				Headers:   headers,
				Body:      string(body),
			}

			// Try to parse body as JSON for pretty display
			var jsonBody interface{}
			if err := json.Unmarshal(body, &jsonBody); err == nil {
				payload.BodyJSON = jsonBody
			}

			// Save to database
			saveWebhookToDB(payload)

			select {
			case webhookChan <- payload:
			default:
				// Channel full, drop oldest
			}

			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		})

		go func() {
			if err := http.ListenAndServe(":"+port, nil); err != nil {
				// Server error - in production we'd send this as a message
			}
		}()

		return serverStartedMsg{}
	}
}

func waitForWebhook(ch chan WebhookPayload) tea.Cmd {
	return func() tea.Msg {
		payload := <-ch
		return webhookReceivedMsg(payload)
	}
}

func scheduleTunnelExpiration(timeout time.Duration) tea.Cmd {
	return tea.Tick(timeout, func(t time.Time) tea.Msg {
		return tunnelExpiredMsg{}
	})
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			if m.tunnelCmd != nil && m.tunnelCmd.Process != nil {
				// Kill the process group to also kill child processes
				syscall.Kill(-m.tunnelCmd.Process.Pid, syscall.SIGTERM)
				m.tunnelCmd.Process.Kill()
			}
			return m, tea.Quit

		case "tab", "shift+tab":
			if m.state == StateSetup {
				if msg.String() == "shift+tab" {
					m.focusedInput = (m.focusedInput + 2) % 3 // Go backwards
				} else {
					m.focusedInput = (m.focusedInput + 1) % 3
				}
				// Update focus states
				m.portInput.Blur()
				m.subdomainInput.Blur()
				m.timeoutInput.Blur()
				switch m.focusedInput {
				case 0:
					m.portInput.Focus()
				case 1:
					m.subdomainInput.Focus()
				case 2:
					m.timeoutInput.Focus()
				}
			}

		case "enter":
			if m.state == StateSetup {
				m.state = StateRunning
				port := m.portInput.Value()
				if port == "" {
					port = "8098"
				}
				subdomain := m.subdomainInput.Value()

				// Parse timeout (default 30 minutes)
				timeoutStr := m.timeoutInput.Value()
				if timeoutStr == "" {
					timeoutStr = "30"
				}
				if minutes, err := strconv.Atoi(timeoutStr); err == nil && minutes > 0 {
					m.tunnelTimeout = time.Duration(minutes) * time.Minute
				} else {
					m.tunnelTimeout = defaultTunnelTimeout
				}

				// Store for display
				m.requestedPort = port
				m.requestedSubdomain = subdomain
				cmds = append(cmds, startTunnel(port, subdomain))
				cmds = append(cmds, m.startWebhookServer())
			} else if m.state == StateRunning && len(m.webhooks) > 0 {
				m.state = StateDetail
				// Set viewport content for the selected webhook
				content := m.buildDetailContent()
				// Wrap content to viewport width so line count matches visual lines
				// Use hard wrap with ANSI awareness
				wrapped := wrapContent(content, m.viewport.Width)
				m.viewport.SetContent(wrapped)
				m.viewport.GotoTop()
			}

		case "esc":
			if m.state == StateDetail {
				m.state = StateRunning
			}

		case "up", "k":
			if m.state == StateRunning && m.selectedIdx > 0 {
				m.selectedIdx--
			} else if m.state == StateDetail {
				var cmd tea.Cmd
				m.viewport, cmd = m.viewport.Update(msg)
				cmds = append(cmds, cmd)
			}

		case "down", "j":
			if m.state == StateRunning && m.selectedIdx < len(m.webhooks)-1 {
				m.selectedIdx++
			} else if m.state == StateDetail {
				var cmd tea.Cmd
				m.viewport, cmd = m.viewport.Update(msg)
				cmds = append(cmds, cmd)
			}

		case "c":
			if m.state == StateRunning {
				m.webhooksMu.Lock()
				m.webhooks = make([]WebhookPayload, 0)
				m.selectedIdx = 0
				m.webhooksMu.Unlock()
			}

		case "t":
			if m.state == StateRunning {
				if m.viewMode == ViewModeList {
					m.viewMode = ViewModeTable
				} else {
					m.viewMode = ViewModeList
				}
			}

		case "l":
			if m.state == StateRunning {
				cmds = append(cmds, loadWebhooksFromDB(0))
			}

		case "r":
			// Reconnect tunnel
			if m.state == StateRunning && (m.tunnelExpired || !m.tunnelRunning) {
				m.tunnelExpired = false
				m.tunnelError = ""
				cmds = append(cmds, startTunnel(m.requestedPort, m.requestedSubdomain))
			}

		case "n", "right":
			if m.state == StateRunning && m.currentPage < m.totalPages-1 {
				m.currentPage++
				cmds = append(cmds, loadWebhooksFromDB(m.currentPage))
			}

		case "p", "left":
			if m.state == StateRunning && m.currentPage > 0 {
				m.currentPage--
				cmds = append(cmds, loadWebhooksFromDB(m.currentPage))
			}

		case "pgup":
			if m.state == StateDetail {
				m.viewport.HalfViewUp()
			}

		case "pgdown":
			if m.state == StateDetail {
				m.viewport.HalfViewDown()
			}

		case "ctrl+f":
			if m.state == StateDetail {
				m.viewport.ViewDown()
			}

		case "ctrl+b":
			if m.state == StateDetail {
				m.viewport.ViewUp()
			}

		case "ctrl+d":
			if m.state == StateDetail {
				m.viewport.HalfViewDown()
			}

		case "ctrl+u":
			if m.state == StateDetail {
				m.viewport.HalfViewUp()
			}

		case "G":
			if m.state == StateDetail {
				m.viewport.GotoBottom()
			} else if m.state == StateRunning && len(m.webhooks) > 0 {
				m.selectedIdx = len(m.webhooks) - 1
			}

		case "g":
			if m.state == StateDetail {
				m.viewport.GotoTop()
			} else if m.state == StateRunning && len(m.webhooks) > 0 {
				m.selectedIdx = 0
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		// Viewport height accounts for: header+blank (2) + blanks after viewport (2) + scroll indicator (1) + help (1) = 6 lines
		if !m.viewportReady {
			m.viewport = viewport.New(msg.Width-4, msg.Height-6)
			m.viewport.HighPerformanceRendering = false
			m.viewportReady = true
		} else {
			m.viewport.Width = msg.Width - 4
			m.viewport.Height = msg.Height - 6
		}

	case publicIPMsg:
		m.publicIP = string(msg)
		m.fetchingIP = false

	case publicIPErrMsg:
		m.publicIP = "Unable to fetch"
		m.fetchingIP = false

	case tunnelStartedMsg:
		m.tunnelURL = msg.url
		m.tunnelCmd = msg.cmd
		m.tunnelRunning = true
		m.tunnelExpired = false
		m.tunnelStartTime = time.Now()
		// Schedule auto-shutdown
		cmds = append(cmds, scheduleTunnelExpiration(m.tunnelTimeout))

	case tunnelExpiredMsg:
		if m.tunnelRunning && !m.tunnelExpired {
			// Kill the tunnel
			if m.tunnelCmd != nil && m.tunnelCmd.Process != nil {
				syscall.Kill(-m.tunnelCmd.Process.Pid, syscall.SIGTERM)
				m.tunnelCmd.Process.Kill()
			}
			m.tunnelRunning = false
			m.tunnelExpired = true
		}

	case tunnelErrorMsg:
		m.tunnelError = string(msg)

	case serverStartedMsg:
		m.serverRunning = true
		cmds = append(cmds, waitForWebhook(m.webhookChan))

	case webhookReceivedMsg:
		m.webhooksMu.Lock()
		m.webhooks = append([]WebhookPayload{WebhookPayload(msg)}, m.webhooks...)
		m.webhooksMu.Unlock()
		cmds = append(cmds, waitForWebhook(m.webhookChan))

	case webhooksLoadedMsg:
		m.webhooksMu.Lock()
		m.webhooks = msg.webhooks
		m.totalWebhooks = msg.totalCount
		m.currentPage = msg.currentPage
		m.totalPages = (msg.totalCount + pageSize - 1) / pageSize
		if m.totalPages == 0 {
			m.totalPages = 1
		}
		m.selectedIdx = 0
		m.webhooksMu.Unlock()

	case dbErrorMsg:
		// Could show error in UI, for now just ignore

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)
	}

	// Update ALL inputs - their internal Focus state controls which accepts keyboard input
	if m.state == StateSetup {
		var cmd tea.Cmd
		m.portInput, cmd = m.portInput.Update(msg)
		cmds = append(cmds, cmd)
		m.subdomainInput, cmd = m.subdomainInput.Update(msg)
		cmds = append(cmds, cmd)
		m.timeoutInput, cmd = m.timeoutInput.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m Model) View() string {
	var b strings.Builder

	// Title
	title := titleStyle.Render("🪝 Webhook Listener TUI")
	b.WriteString(title + "\n\n")

	switch m.state {
	case StateSetup:
		b.WriteString(m.viewSetup())
	case StateRunning:
		b.WriteString(m.viewRunning())
	case StateDetail:
		b.WriteString(m.viewDetail())
	}

	return b.String()
}

func (m Model) viewSetup() string {
	var b strings.Builder

	// Public IP section
	b.WriteString(headerStyle.Render("Public IP Address") + "\n")
	if m.fetchingIP {
		b.WriteString(m.spinner.View() + " Fetching...\n")
	} else {
		b.WriteString(highlightStyle.Render(m.publicIP) + "\n")
		b.WriteString(infoStyle.Render("(Use this for webhook authentication if needed)") + "\n")
	}
	b.WriteString("\n")

	// Port input
	b.WriteString(headerStyle.Render("Local Port") + "\n")
	if m.focusedInput == 0 {
		b.WriteString(selectedStyle.Render(m.portInput.View()) + "\n")
	} else {
		b.WriteString(m.portInput.View() + "\n")
	}
	b.WriteString(infoStyle.Render("Port for the local webhook server") + "\n\n")

	// Subdomain input
	b.WriteString(headerStyle.Render("Subdomain (optional)") + "\n")
	if m.focusedInput == 1 {
		b.WriteString(selectedStyle.Render(m.subdomainInput.View()) + "\n")
	} else {
		b.WriteString(m.subdomainInput.View() + "\n")
	}
	b.WriteString(infoStyle.Render("Custom subdomain for localtunnel (e.g., my-app → my-app.loca.lt)") + "\n\n")

	// Timeout input
	b.WriteString(headerStyle.Render("Tunnel Timeout (minutes)") + "\n")
	if m.focusedInput == 2 {
		b.WriteString(selectedStyle.Render(m.timeoutInput.View()) + "\n")
	} else {
		b.WriteString(m.timeoutInput.View() + "\n")
	}
	b.WriteString(infoStyle.Render("Auto-disconnect tunnel after this many minutes (default: 30)") + "\n\n")

	// Help
	b.WriteString(helpStyle.Render("Tab: switch fields • Enter: start • q: quit"))

	return b.String()
}

func (m Model) viewRunning() string {
	var b strings.Builder

	// Status section
	b.WriteString(headerStyle.Render("Status") + "\n")

	// Public IP
	b.WriteString(fmt.Sprintf("  Public IP: %s\n", highlightStyle.Render(m.publicIP)))

	// Server status
	if m.serverRunning {
		b.WriteString(fmt.Sprintf("  Server: %s on port %s\n", successStyle.Render("●"), m.requestedPort))
	} else {
		b.WriteString(fmt.Sprintf("  Server: %s Starting...\n", m.spinner.View()))
	}

	// Tunnel status
	if m.tunnelError != "" {
		b.WriteString(fmt.Sprintf("  Tunnel: %s %s\n", errorStyle.Render("✗"), m.tunnelError))
	} else if m.tunnelExpired {
		b.WriteString(fmt.Sprintf("  Tunnel: %s (auto-shutdown after %v) - press 'r' to reconnect\n",
			errorStyle.Render("● DISCONNECTED"), m.tunnelTimeout))
		b.WriteString(fmt.Sprintf("  Last URL: %s\n", infoStyle.Render(m.tunnelURL)))
	} else if m.tunnelRunning {
		// Calculate time remaining
		elapsed := time.Since(m.tunnelStartTime)
		remaining := m.tunnelTimeout - elapsed
		if remaining < 0 {
			remaining = 0
		}
		minutes := int(remaining.Minutes())
		seconds := int(remaining.Seconds()) % 60
		remainingStr := fmt.Sprintf("%02d:%02d", minutes, seconds)

		// Color the countdown based on time remaining
		countdownStyle := successStyle
		if remaining < 5*time.Minute {
			countdownStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("214")) // Orange/yellow
		}
		if remaining < 1*time.Minute {
			countdownStyle = errorStyle // Red
		}

		b.WriteString(fmt.Sprintf("  Tunnel: %s %s\n", successStyle.Render("●"), m.tunnelURL))
		b.WriteString(fmt.Sprintf("  Webhook URL: %s\n", highlightStyle.Render(m.tunnelURL+"/webhook")))
		b.WriteString(fmt.Sprintf("  Expires in: %s\n", countdownStyle.Render(remainingStr)))
	} else {
		subdomainInfo := ""
		if m.requestedSubdomain != "" {
			subdomainInfo = fmt.Sprintf(" (subdomain: %s)", m.requestedSubdomain)
		}
		b.WriteString(fmt.Sprintf("  Tunnel: %s Starting localtunnel...%s\n", m.spinner.View(), subdomainInfo))
	}
	b.WriteString("\n")

	// View mode indicator
	viewModeStr := "List"
	if m.viewMode == ViewModeTable {
		viewModeStr = "Table"
	}
	// Show total count if loaded from DB, otherwise show current count
	countStr := fmt.Sprintf("%d", len(m.webhooks))
	if m.totalWebhooks > 0 {
		countStr = fmt.Sprintf("%d total", m.totalWebhooks)
	}
	b.WriteString(headerStyle.Render(fmt.Sprintf("Webhooks (%s)", countStr)))

	// Pagination and view mode info
	pageInfo := ""
	if m.totalPages > 1 {
		pageInfo = fmt.Sprintf(" Page %d/%d |", m.currentPage+1, m.totalPages)
	}
	b.WriteString(infoStyle.Render(fmt.Sprintf("%s [%s]", pageInfo, viewModeStr)) + "\n")

	if len(m.webhooks) == 0 {
		b.WriteString(infoStyle.Render("  Waiting for webhooks...") + "\n")
	} else if m.viewMode == ViewModeTable {
		b.WriteString(m.renderTableView())
	} else {
		b.WriteString(m.renderListView())
	}

	// Help
	b.WriteString("\n" + helpStyle.Render("j/k: select • n/p: page • Enter: details • t: view • r: reconnect • l: load DB • c: clear • q: quit"))

	return b.String()
}

func (m Model) renderListView() string {
	var b strings.Builder

	maxShow := 10
	if len(m.webhooks) < maxShow {
		maxShow = len(m.webhooks)
	}

	for i := 0; i < maxShow; i++ {
		wh := m.webhooks[i]
		preview := truncate(wh.Body, 50)
		if preview == "" {
			preview = "(empty body)"
		}

		item := fmt.Sprintf("#%d %s %s %s\n    %s",
			wh.ID,
			wh.Timestamp.Format("15:04:05"),
			methodStyle(wh.Method),
			wh.Path,
			infoStyle.Render(preview),
		)

		if i == m.selectedIdx {
			b.WriteString(webhookSelectedStyle.Render(item) + "\n")
		} else {
			b.WriteString(webhookItemStyle.Render(item) + "\n")
		}
	}

	return b.String()
}

func (m Model) renderTableView() string {
	var b strings.Builder

	// Table header
	tableHeaderStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("39")).
		BorderStyle(lipgloss.NormalBorder()).
		BorderBottom(true).
		BorderForeground(lipgloss.Color("240"))

	// Column widths
	idW := 4
	timeW := 10
	methodW := 8
	pathW := 20
	bodyW := 40

	header := fmt.Sprintf("%-*s %-*s %-*s %-*s %-*s",
		idW, "ID",
		timeW, "Time",
		methodW, "Method",
		pathW, "Path",
		bodyW, "Body Preview",
	)
	b.WriteString(tableHeaderStyle.Render(header) + "\n")

	// Table rows
	maxShow := 15
	if len(m.webhooks) < maxShow {
		maxShow = len(m.webhooks)
	}

	for i := 0; i < maxShow; i++ {
		wh := m.webhooks[i]
		preview := truncate(wh.Body, bodyW-3)
		if preview == "" {
			preview = "(empty)"
		}
		path := truncate(wh.Path, pathW-3)

		row := fmt.Sprintf("%-*d %-*s %-*s %-*s %-*s",
			idW, wh.ID,
			timeW, wh.Timestamp.Format("15:04:05"),
			methodW, wh.Method,
			pathW, path,
			bodyW, preview,
		)

		if i == m.selectedIdx {
			rowStyle := lipgloss.NewStyle().
				Background(lipgloss.Color("236")).
				Foreground(lipgloss.Color("212"))
			b.WriteString(rowStyle.Render(row) + "\n")
		} else {
			// Color-code method in row
			methodColored := methodStyle(wh.Method)
			row = fmt.Sprintf("%-*d %-*s %s%s %-*s %-*s",
				idW, wh.ID,
				timeW, wh.Timestamp.Format("15:04:05"),
				methodColored, strings.Repeat(" ", methodW-len(wh.Method)),
				pathW, path,
				bodyW, preview,
			)
			b.WriteString(row + "\n")
		}
	}

	return b.String()
}

func (m Model) buildDetailContent() string {
	var b strings.Builder

	if m.selectedIdx >= len(m.webhooks) {
		return "No webhook selected"
	}

	wh := m.webhooks[m.selectedIdx]

	// Metadata
	b.WriteString(fmt.Sprintf("%s %s\n",
		highlightStyle.Render("Method:"),
		methodStyle(wh.Method),
	))
	b.WriteString(fmt.Sprintf("%s %s\n", highlightStyle.Render("Path:"), wh.Path))
	b.WriteString(fmt.Sprintf("%s %s\n\n", highlightStyle.Render("Time:"), wh.Timestamp.Format(time.RFC3339)))

	// Headers
	b.WriteString(headerStyle.Render("Headers") + "\n")
	for k, v := range wh.Headers {
		b.WriteString(fmt.Sprintf("  %s: %s\n", highlightStyle.Render(k), v))
	}
	b.WriteString("\n")

	// Body
	b.WriteString(headerStyle.Render("Body") + "\n")
	if wh.BodyJSON != nil {
		prettyJSON, err := json.MarshalIndent(wh.BodyJSON, "", "  ")
		if err == nil {
			b.WriteString(bodyStyle.Render(string(prettyJSON)) + "\n")
		} else {
			b.WriteString(bodyStyle.Render(wh.Body) + "\n")
		}
	} else if wh.Body != "" {
		b.WriteString(bodyStyle.Render(wh.Body) + "\n")
	} else {
		b.WriteString(infoStyle.Render("(empty)") + "\n")
	}

	return b.String()
}

func (m Model) viewDetail() string {
	var b strings.Builder

	if m.selectedIdx >= len(m.webhooks) {
		return "No webhook selected"
	}

	wh := m.webhooks[m.selectedIdx]

	// Header
	b.WriteString(headerStyle.Render(fmt.Sprintf("Webhook #%d Details", wh.ID)) + "\n\n")

	// Viewport with scrollable content
	b.WriteString(m.viewport.View() + "\n\n")

	// Scroll indicator
	scrollPercent := int(m.viewport.ScrollPercent() * 100)
	scrollInfo := infoStyle.Render(fmt.Sprintf("─── %d%% ───", scrollPercent))
	b.WriteString(scrollInfo + "\n")

	// Help
	b.WriteString(helpStyle.Render("↑/↓/j/k: scroll • ^f/^b/^d/^u: page • g/G: top/bottom • Esc: back • q: quit"))

	return b.String()
}

// wrapContent wraps text to the specified width while preserving ANSI escape codes
func wrapContent(content string, width int) string {
	// wrap.String is ANSI-aware and will hard-wrap at the specified width
	return wrap.String(content, width)
}

func methodStyle(method string) string {
	switch method {
	case "GET":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("82")).Render("GET")
	case "POST":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Render("POST")
	case "PUT":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Render("PUT")
	case "DELETE":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("DELETE")
	case "PATCH":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("141")).Render("PATCH")
	default:
		return method
	}
}

func truncate(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func main() {
	// Initialize database
	if err := initDB(); err != nil {
		fmt.Printf("Failed to initialize database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running program: %v\n", err)
		os.Exit(1)
	}
}
