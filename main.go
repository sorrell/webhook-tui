package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

	// JSON syntax highlighting styles
	jsonKeyStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("81")) // cyan

	jsonStringStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("114")) // green

	jsonNumberStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("222")) // yellow

	jsonBoolStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("212")) // magenta

	jsonNullStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("244")) // gray

	jsonBracketStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("252")) // light gray

	lineNumberStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("239")) // dim gray

	searchHighlightStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("226")). // yellow background
				Foreground(lipgloss.Color("0"))    // black text
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

// SessionConfig represents saved session settings
type SessionConfig struct {
	ID         int
	LastUsed   time.Time
	Port       string
	Subdomain  string
	TimeoutMin int
	ForwardURL string
	Provider   string
}

// Tunnel provider identifiers
const (
	providerCloudflared = "cloudflared"
	providerLocaltunnel = "localtunnel"
)

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
	provider           string        // tunnel provider: cloudflared or localtunnel
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

	// Detail view options
	showRawBody      bool
	statusMsg        string // temporary flash message

	// Search in detail view
	searchMode       bool
	searchInput      textinput.Model
	searchQuery      string
	searchMatches    []int  // line numbers with matches
	searchMatchIdx   int    // current match index
	detailContent    string // raw content for searching
	detailGutterWidth int   // gutter width for line numbers

	// Forwarding
	forwardURL       string
	forwardURLInput  textinput.Model
	forwardStatus    map[int]string // webhookID -> status string

	// Recent sessions
	recentSessions   []SessionConfig
	selectedSession  int  // -1 = none selected
	sessionsFocused  bool // sessions list has keyboard focus (StateSetup only)

	// Signature verification
	signatureMode    bool
	signatureStep    int    // 0=entering secret, 1=choosing algorithm, 2=showing result
	secretInput      textinput.Model
	signatureAlgo    string // detected or selected algorithm
	signatureResult  string // result message to display
	signatureHeader  string // header name containing the signature
	signatureValue   string // expected signature value from header
	algoChoices      []string
	algoSelectedIdx  int
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
type clearStatusMsg struct{}
type forwardResultMsg struct {
	webhookID  int
	statusCode int
	err        error
}

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
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS sessions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			last_used DATETIME DEFAULT CURRENT_TIMESTAMP,
			port TEXT NOT NULL,
			subdomain TEXT,
			timeout_min INTEGER DEFAULT 30,
			forward_url TEXT,
			UNIQUE(port, subdomain, timeout_min, forward_url)
		)
	`)
	if err != nil {
		return err
	}

	// Idempotent migration: add provider column if missing. SQLite returns
	// "duplicate column name" when it already exists; that's fine.
	if _, err := db.Exec(`ALTER TABLE sessions ADD COLUMN provider TEXT DEFAULT 'localtunnel'`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column") {
		return err
	}
	return nil
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

func saveSession(port, subdomain string, timeoutMin int, forwardURL, provider string) {
	if db == nil {
		return
	}
	now := time.Now().Format(time.RFC3339)
	db.Exec(`
		INSERT INTO sessions (port, subdomain, timeout_min, forward_url, provider, last_used)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(port, subdomain, timeout_min, forward_url)
		DO UPDATE SET last_used = ?, provider = ?
	`, port, subdomain, timeoutMin, forwardURL, provider, now, now, provider)
}

func loadRecentSessions() []SessionConfig {
	if db == nil {
		return nil
	}
	rows, err := db.Query(`
		SELECT id, last_used, port, subdomain, timeout_min, forward_url, COALESCE(provider, 'localtunnel')
		FROM sessions
		ORDER BY last_used DESC
		LIMIT 5
	`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var sessions []SessionConfig
	for rows.Next() {
		var s SessionConfig
		var lastUsed, subdomain, forwardURL, provider string
		if err := rows.Scan(&s.ID, &lastUsed, &s.Port, &subdomain, &s.TimeoutMin, &forwardURL, &provider); err != nil {
			continue
		}
		s.Subdomain = subdomain
		s.ForwardURL = forwardURL
		s.Provider = provider
		if t, err := time.Parse(time.RFC3339, lastUsed); err == nil {
			s.LastUsed = t
		}
		sessions = append(sessions, s)
	}
	return sessions
}

func initialModel() Model {
	portInput := textinput.New()
	portInput.Placeholder = "8098"
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

	searchInput := textinput.New()
	searchInput.Placeholder = ""
	searchInput.CharLimit = 100
	searchInput.Width = 30
	searchInput.Prompt = "/"

	forwardURLInput := textinput.New()
	forwardURLInput.Placeholder = "https://localhost:3000/webhook"
	forwardURLInput.CharLimit = 200
	forwardURLInput.Width = 50

	secretInput := textinput.New()
	secretInput.Placeholder = "Enter webhook secret"
	secretInput.EchoMode = textinput.EchoPassword
	secretInput.CharLimit = 256
	secretInput.Width = 40
	secretInput.Prompt = "Secret: "

	recent := loadRecentSessions()
	hasSessions := len(recent) > 0

	m := Model{
		state:          StateSetup,
		provider:       providerCloudflared,
		portInput:      portInput,
		subdomainInput: subdomainInput,
		timeoutInput:   timeoutInput,
		focusedInput:   0,
		spinner:        s,
		fetchingIP:     true,
		webhooks:       make([]WebhookPayload, 0),
		webhookChan:    make(chan WebhookPayload, 100),
		viewMode:       ViewModeTable,
		currentPage:    0,
		tunnelTimeout:  defaultTunnelTimeout,
		searchInput:     searchInput,
		secretInput:     secretInput,
		forwardURLInput: forwardURLInput,
		forwardStatus:   make(map[int]string),
		recentSessions:  recent,
		selectedSession: -1,
	}
	if hasSessions {
		m.sessionsFocused = true
		m.selectedSession = 0
	} else {
		m.portInput.Focus()
	}
	return m
}

func (m Model) Init() tea.Cmd {
	cmds := []tea.Cmd{
		textinput.Blink,
		m.spinner.Tick,
		fetchPublicIP,
		loadWebhooksFromDB(0), // Load previous webhooks on startup
	}
	// If flags skipped setup, start tunnel and server immediately
	if m.state == StateRunning {
		cmds = append(cmds, startTunnel(m.requestedPort, m.requestedSubdomain, m.provider))
		cmds = append(cmds, m.startWebhookServer())
	}
	return tea.Batch(cmds...)
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

func startTunnel(port, subdomain, provider string) tea.Cmd {
	return func() tea.Msg {
		switch provider {
		case providerCloudflared, "":
			return startCloudflaredTunnel(port)
		case providerLocaltunnel:
			return startLocaltunnel(port, subdomain)
		default:
			return tunnelErrorMsg(fmt.Sprintf("Unknown tunnel provider: %s", provider))
		}
	}
}

func startLocaltunnel(port, subdomain string) tea.Msg {
	args := []string{"--yes", "localtunnel", "--port", port}
	if subdomain != "" {
		args = append(args, "--subdomain", subdomain)
	}

	cmd := exec.Command("npx", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return tunnelErrorMsg(fmt.Sprintf("Failed to create stdout pipe: %v", err))
	}

	if err := cmd.Start(); err != nil {
		return tunnelErrorMsg(fmt.Sprintf("Failed to start localtunnel: %v", err))
	}

	// localtunnel prints: "your url is: https://xxx.loca.lt"
	buf := make([]byte, 1024)
	n, err := stdout.Read(buf)
	if err != nil {
		return tunnelErrorMsg(fmt.Sprintf("Failed to read tunnel URL: %v", err))
	}

	output := string(buf[:n])
	url := output
	if idx := strings.Index(output, "https://"); idx != -1 {
		url = strings.TrimSpace(output[idx:])
		if newline := strings.Index(url, "\n"); newline != -1 {
			url = url[:newline]
		}
	}

	return tunnelStartedMsg{url: url, cmd: cmd}
}

var cloudflaredURLRe = regexp.MustCompile(`https://[a-zA-Z0-9-]+\.trycloudflare\.com`)

func startCloudflaredTunnel(port string) tea.Msg {
	target := "http://localhost:" + port

	// Prefer a system-installed cloudflared (faster than npx). Fall back to
	// `npx --yes cloudflared` which auto-downloads the binary via the
	// `cloudflared` npm package on first run.
	var cmd *exec.Cmd
	if path, err := exec.LookPath("cloudflared"); err == nil {
		cmd = exec.Command(path, "tunnel", "--url", target, "--no-autoupdate")
	} else {
		cmd = exec.Command("npx", "--yes", "cloudflared", "tunnel", "--url", target, "--no-autoupdate")
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return tunnelErrorMsg(fmt.Sprintf("Failed to create stdout pipe: %v", err))
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return tunnelErrorMsg(fmt.Sprintf("Failed to create stderr pipe: %v", err))
	}

	if err := cmd.Start(); err != nil {
		return tunnelErrorMsg(fmt.Sprintf("Failed to start cloudflared: %v", err))
	}

	// cloudflared writes its banner to stderr; scan both pipes for the URL.
	urlCh := make(chan string, 2)
	scan := func(r io.Reader) {
		s := bufio.NewScanner(r)
		s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for s.Scan() {
			if m := cloudflaredURLRe.FindString(s.Text()); m != "" {
				select {
				case urlCh <- m:
				default:
				}
				// Keep draining so the pipe doesn't block the child.
			}
		}
	}
	go scan(stdout)
	go scan(stderr)

	// First run via npx may download the binary; give it room.
	select {
	case url := <-urlCh:
		return tunnelStartedMsg{url: url, cmd: cmd}
	case <-time.After(90 * time.Second):
		_ = cmd.Process.Kill()
		return tunnelErrorMsg("Timed out waiting for cloudflared tunnel URL (90s). Try installing cloudflared directly: brew install cloudflared")
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

func forwardWebhook(forwardURL string, wh WebhookPayload) tea.Cmd {
	return func() tea.Msg {
		req, err := http.NewRequest(wh.Method, forwardURL+wh.Path, bytes.NewBufferString(wh.Body))
		if err != nil {
			return forwardResultMsg{webhookID: wh.ID, err: err}
		}
		for k, v := range wh.Headers {
			req.Header.Set(k, v)
		}
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return forwardResultMsg{webhookID: wh.ID, err: err}
		}
		defer resp.Body.Close()
		return forwardResultMsg{webhookID: wh.ID, statusCode: resp.StatusCode}
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Handle signature verification mode input first
		if m.signatureMode {
			switch m.signatureStep {
			case 0: // Entering secret
				switch msg.String() {
				case "enter":
					secret := m.secretInput.Value()
					computed, err := computeHMAC(m.signatureAlgo, secret, m.webhooks[m.selectedIdx].Body)
					if err != nil {
						m.signatureResult = errorStyle.Render("Error: " + err.Error())
					} else if hmac.Equal([]byte(computed), []byte(m.signatureValue)) {
						m.signatureResult = successStyle.Render("MATCH") +
							"\n  Computed: " + computed +
							"\n  Expected: " + m.signatureValue
					} else {
						m.signatureResult = errorStyle.Render("MISMATCH") +
							"\n  Computed: " + computed +
							"\n  Expected: " + m.signatureValue
					}
					m.signatureStep = 2
					m.secretInput.Blur()
					return m, nil
				case "esc":
					m.signatureMode = false
					m.secretInput.Blur()
					m.secretInput.SetValue("")
					return m, nil
				default:
					var cmd tea.Cmd
					m.secretInput, cmd = m.secretInput.Update(msg)
					return m, cmd
				}
			case 1: // Algorithm selection
				switch msg.String() {
				case "j", "down":
					if m.algoSelectedIdx < len(m.algoChoices)-1 {
						m.algoSelectedIdx++
					}
					return m, nil
				case "k", "up":
					if m.algoSelectedIdx > 0 {
						m.algoSelectedIdx--
					}
					return m, nil
				case "enter":
					m.signatureAlgo = m.algoChoices[m.algoSelectedIdx]
					m.signatureStep = 0
					m.secretInput.SetValue("")
					m.secretInput.Focus()
					return m, textinput.Blink
				case "esc":
					m.signatureMode = false
					return m, nil
				}
				return m, nil
			case 2: // Result display
				m.signatureMode = false
				m.secretInput.SetValue("")
				return m, nil
			}
		}

		// Handle search mode input first
		if m.searchMode {
			switch msg.String() {
			case "enter":
				// Execute search
				m.searchMode = false
				m.searchQuery = m.searchInput.Value()
				m.searchInput.Blur()
				if m.searchQuery != "" {
					m.findSearchMatches()
					m.updateDetailViewport() // Re-render with highlighting
					if len(m.searchMatches) > 0 {
						m.searchMatchIdx = 0
						m.viewport.SetYOffset(m.searchMatches[0])
					}
					cmds = append(cmds, tea.ClearScreen)
				}
				return m, tea.Batch(cmds...)
			case "esc":
				// Cancel search
				m.searchMode = false
				m.searchInput.Blur()
				m.searchInput.SetValue("")
				// Clear highlighting
				m.searchQuery = ""
				m.searchMatches = nil
				m.updateDetailViewport()
				cmds = append(cmds, tea.ClearScreen)
				return m, tea.Batch(cmds...)
			default:
				// Pass to search input
				var cmd tea.Cmd
				m.searchInput, cmd = m.searchInput.Update(msg)
				return m, cmd
			}
		}

		switch msg.String() {
		case "ctrl+t":
			if m.state == StateSetup {
				if m.provider == providerLocaltunnel {
					m.provider = providerCloudflared
				} else {
					m.provider = providerLocaltunnel
				}
				return m, nil
			}

		case "ctrl+c", "q":
			if m.tunnelCmd != nil && m.tunnelCmd.Process != nil {
				// Kill the process group to also kill child processes
				syscall.Kill(-m.tunnelCmd.Process.Pid, syscall.SIGTERM)
				m.tunnelCmd.Process.Kill()
			}
			return m, tea.Quit

		case "tab", "shift+tab":
			if m.state == StateSetup {
				hasSessions := len(m.recentSessions) > 0
				// Build a logical position: 0 = sessions (if any), then 1..N for the
				// four text inputs (offset by 1 when sessions exist).
				total := 4
				if hasSessions {
					total = 5
				}
				var pos int
				if m.sessionsFocused {
					pos = 0
				} else if hasSessions {
					pos = m.focusedInput + 1
				} else {
					pos = m.focusedInput
				}
				if msg.String() == "shift+tab" {
					pos = (pos + total - 1) % total
				} else {
					pos = (pos + 1) % total
				}
				m.portInput.Blur()
				m.subdomainInput.Blur()
				m.timeoutInput.Blur()
				m.forwardURLInput.Blur()
				if hasSessions && pos == 0 {
					m.sessionsFocused = true
					if m.selectedSession < 0 {
						m.selectedSession = 0
					}
				} else {
					m.sessionsFocused = false
					if hasSessions {
						pos--
					}
					m.focusedInput = pos
					switch m.focusedInput {
					case 0:
						m.portInput.Focus()
					case 1:
						m.subdomainInput.Focus()
					case 2:
						m.timeoutInput.Focus()
					case 3:
						m.forwardURLInput.Focus()
					}
				}
			}

		case "1", "2", "3", "4", "5":
			if m.state == StateSetup && m.sessionsFocused {
				idx := int(msg.String()[0]-'0') - 1
				if idx < len(m.recentSessions) {
					m.selectedSession = idx
					return m, nil
				}
			}

		case "enter":
			if m.state == StateSetup && m.sessionsFocused {
				if m.selectedSession >= 0 && m.selectedSession < len(m.recentSessions) {
					s := m.recentSessions[m.selectedSession]
					m.portInput.SetValue(s.Port)
					m.subdomainInput.SetValue(s.Subdomain)
					m.timeoutInput.SetValue(strconv.Itoa(s.TimeoutMin))
					m.forwardURLInput.SetValue(s.ForwardURL)
					if s.Provider != "" {
						m.provider = s.Provider
					}
				}
				m.sessionsFocused = false
				m.focusedInput = 0
				m.portInput.Blur()
				m.subdomainInput.Blur()
				m.timeoutInput.Blur()
				m.forwardURLInput.Blur()
				m.portInput.Focus()
				return m, nil
			}
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
				timeoutMin := 30
				if minutes, err := strconv.Atoi(timeoutStr); err == nil && minutes > 0 {
					m.tunnelTimeout = time.Duration(minutes) * time.Minute
					timeoutMin = minutes
				} else {
					m.tunnelTimeout = defaultTunnelTimeout
				}

				// Store for display
				m.requestedPort = port
				m.requestedSubdomain = subdomain
				m.forwardURL = strings.TrimSpace(m.forwardURLInput.Value())
				if m.provider == "" {
					m.provider = providerCloudflared
				}
				if m.provider == providerCloudflared {
					// Quick tunnels can't pick a subdomain.
					m.requestedSubdomain = ""
					subdomain = ""
				}

				saveSession(port, subdomain, timeoutMin, m.forwardURL, m.provider)

				cmds = append(cmds, startTunnel(port, subdomain, m.provider))
				cmds = append(cmds, m.startWebhookServer())
			} else if m.state == StateRunning && len(m.webhooks) > 0 {
				m.state = StateDetail
				// Set viewport content for the selected webhook
				content := m.buildDetailContent()
				// Calculate line number gutter width (4 digits + " │ " = 7 chars)
				m.detailGutterWidth = 4
				gutterTotal := m.detailGutterWidth + 3 // " │ "
				// Wrap content to viewport width minus gutter
				m.detailContent = wrapContent(content, m.viewport.Width-gutterTotal)
				// Clear any previous search
				m.searchQuery = ""
				m.searchMatches = nil
				m.searchMatchIdx = 0
				// Set viewport with line numbers
				m.updateDetailViewport()
				m.viewport.GotoTop()
			}

		case "esc":
			if m.state == StateDetail {
				m.state = StateRunning
				// Clear search when leaving detail view
				m.searchQuery = ""
				m.searchMatches = nil
				m.searchMatchIdx = 0
			}

		case "/":
			if m.state == StateDetail {
				m.searchMode = true
				m.searchInput.SetValue("")
				m.searchInput.Focus()
				return m, textinput.Blink
			}

		case "N":
			if m.state == StateDetail && len(m.searchMatches) > 0 {
				// Previous match
				m.searchMatchIdx = (m.searchMatchIdx - 1 + len(m.searchMatches)) % len(m.searchMatches)
				m.viewport.SetYOffset(m.searchMatches[m.searchMatchIdx])
				cmds = append(cmds, tea.ClearScreen)
			}

		case "up", "k":
			if m.state == StateSetup && m.sessionsFocused {
				if m.selectedSession > 0 {
					m.selectedSession--
				}
			} else if m.state == StateRunning && m.selectedIdx > 0 {
				m.selectedIdx--
			} else if m.state == StateDetail {
				m.viewport.LineUp(1)
				cmds = append(cmds, tea.ClearScreen)
			}

		case "down", "j":
			if m.state == StateSetup && m.sessionsFocused {
				if m.selectedSession < len(m.recentSessions)-1 {
					m.selectedSession++
				}
			} else if m.state == StateRunning && m.selectedIdx < len(m.webhooks)-1 {
				m.selectedIdx++
			} else if m.state == StateDetail {
				m.viewport.LineDown(1)
				cmds = append(cmds, tea.ClearScreen)
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
			if m.state == StateDetail {
				m.showRawBody = !m.showRawBody
				content := m.buildDetailContent()
				gutterTotal := m.detailGutterWidth + 3
				m.detailContent = wrapContent(content, m.viewport.Width-gutterTotal)
				m.updateDetailViewport()
				cmds = append(cmds, tea.ClearScreen)
			} else if m.state == StateRunning && (m.tunnelExpired || !m.tunnelRunning) {
				// Reconnect tunnel
				m.tunnelExpired = false
				m.tunnelError = ""
				cmds = append(cmds, startTunnel(m.requestedPort, m.requestedSubdomain, m.provider))
			}

		case "y":
			if m.state == StateDetail && m.selectedIdx < len(m.webhooks) {
				body := m.webhooks[m.selectedIdx].Body
				cmd := exec.Command("pbcopy")
				cmd.Stdin = strings.NewReader(body)
				if err := cmd.Run(); err == nil {
					m.statusMsg = successStyle.Render("Copied to clipboard!")
				} else {
					m.statusMsg = errorStyle.Render("Copy failed")
				}
				return m, tea.Tick(2*time.Second, func(t time.Time) tea.Msg {
					return clearStatusMsg{}
				})
			} else if m.state == StateRunning && m.tunnelURL != "" {
				cmd := exec.Command("pbcopy")
				cmd.Stdin = strings.NewReader(m.tunnelURL)
				if err := cmd.Run(); err == nil {
					m.statusMsg = successStyle.Render("Tunnel URL copied to clipboard!")
				} else {
					m.statusMsg = errorStyle.Render("Copy failed")
				}
				return m, tea.Tick(2*time.Second, func(t time.Time) tea.Msg {
					return clearStatusMsg{}
				})
			}

		case "f":
			if m.state == StateDetail && m.forwardURL != "" && m.selectedIdx < len(m.webhooks) {
				wh := m.webhooks[m.selectedIdx]
				m.forwardStatus[wh.ID] = "forwarding..."
				m.statusMsg = "Forwarding webhook #" + strconv.Itoa(wh.ID) + "..."
				return m, tea.Batch(
					forwardWebhook(m.forwardURL, wh),
					tea.Tick(2*time.Second, func(t time.Time) tea.Msg {
						return clearStatusMsg{}
					}),
				)
			} else if m.state == StateDetail && m.forwardURL == "" {
				m.statusMsg = errorStyle.Render("No forward URL configured")
				return m, tea.Tick(2*time.Second, func(t time.Time) tea.Msg {
					return clearStatusMsg{}
				})
			}

		case "s":
			if m.state == StateDetail && m.selectedIdx < len(m.webhooks) {
				wh := m.webhooks[m.selectedIdx]
				headerName, algo, sigValue := detectSignatureHeader(wh.Headers)
				if headerName == "" {
					m.signatureMode = true
					m.signatureStep = 2
					m.signatureResult = errorStyle.Render("No signature header found")
					return m, nil
				}
				m.signatureHeader = headerName
				m.signatureValue = sigValue
				m.signatureMode = true
				m.secretInput.SetValue("")
				if algo != "" {
					m.signatureAlgo = algo
					m.signatureStep = 0
					m.secretInput.Focus()
					return m, textinput.Blink
				}
				// Unknown algo — let user choose
				m.algoChoices = []string{"sha1", "sha256", "sha512"}
				m.algoSelectedIdx = 1 // default to sha256
				m.signatureStep = 1
				return m, nil
			}

		case "n":
			if m.state == StateDetail && len(m.searchMatches) > 0 {
				// Next search match
				m.searchMatchIdx = (m.searchMatchIdx + 1) % len(m.searchMatches)
				m.viewport.SetYOffset(m.searchMatches[m.searchMatchIdx])
				cmds = append(cmds, tea.ClearScreen)
			} else if m.state == StateRunning && m.currentPage < m.totalPages-1 {
				m.currentPage++
				cmds = append(cmds, loadWebhooksFromDB(m.currentPage))
			}

		case "right":
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
				cmds = append(cmds, tea.ClearScreen)
			}

		case "pgdown":
			if m.state == StateDetail {
				m.viewport.HalfViewDown()
				cmds = append(cmds, tea.ClearScreen)
			}

		case "ctrl+f":
			if m.state == StateDetail {
				m.viewport.ViewDown()
				cmds = append(cmds, tea.ClearScreen)
			}

		case "ctrl+b":
			if m.state == StateDetail {
				m.viewport.ViewUp()
				cmds = append(cmds, tea.ClearScreen)
			}

		case "ctrl+d":
			if m.state == StateDetail {
				m.viewport.HalfViewDown()
				cmds = append(cmds, tea.ClearScreen)
			}

		case "ctrl+u":
			if m.state == StateDetail {
				m.viewport.HalfViewUp()
				cmds = append(cmds, tea.ClearScreen)
			}

		case "G":
			if m.state == StateDetail {
				m.viewport.GotoBottom()
				cmds = append(cmds, tea.ClearScreen)
			} else if m.state == StateRunning && len(m.webhooks) > 0 {
				m.selectedIdx = len(m.webhooks) - 1
			}

		case "g":
			if m.state == StateDetail {
				m.viewport.GotoTop()
				cmds = append(cmds, tea.ClearScreen)
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
		payload := WebhookPayload(msg)
		m.webhooksMu.Lock()
		m.webhooks = append([]WebhookPayload{payload}, m.webhooks...)
		m.webhooksMu.Unlock()
		cmds = append(cmds, waitForWebhook(m.webhookChan))
		if m.forwardURL != "" {
			m.forwardStatus[payload.ID] = "forwarding..."
			cmds = append(cmds, forwardWebhook(m.forwardURL, payload))
		}

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

	case forwardResultMsg:
		if msg.err != nil {
			m.forwardStatus[msg.webhookID] = errorStyle.Render("✗ " + msg.err.Error())
		} else if msg.statusCode >= 200 && msg.statusCode < 300 {
			m.forwardStatus[msg.webhookID] = successStyle.Render(fmt.Sprintf("✓ %d", msg.statusCode))
		} else {
			m.forwardStatus[msg.webhookID] = errorStyle.Render(fmt.Sprintf("✗ %d", msg.statusCode))
		}
		// Refresh detail view if we're looking at this webhook
		if m.state == StateDetail && m.selectedIdx < len(m.webhooks) && m.webhooks[m.selectedIdx].ID == msg.webhookID {
			content := m.buildDetailContent()
			gutterTotal := m.detailGutterWidth + 3
			m.detailContent = wrapContent(content, m.viewport.Width-gutterTotal)
			m.updateDetailViewport()
		}

	case clearStatusMsg:
		m.statusMsg = ""

	case dbErrorMsg:
		// Could show error in UI, for now just ignore

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)
	}

	if m.state == StateSetup {
		prevPort := m.portInput.Value()
		prevSub := m.subdomainInput.Value()
		prevTimeout := m.timeoutInput.Value()
		prevFwd := m.forwardURLInput.Value()

		var cmd tea.Cmd
		m.portInput, cmd = m.portInput.Update(msg)
		cmds = append(cmds, cmd)
		m.subdomainInput, cmd = m.subdomainInput.Update(msg)
		cmds = append(cmds, cmd)
		m.timeoutInput, cmd = m.timeoutInput.Update(msg)
		cmds = append(cmds, cmd)
		m.forwardURLInput, cmd = m.forwardURLInput.Update(msg)
		cmds = append(cmds, cmd)

		if m.selectedSession >= 0 && (m.portInput.Value() != prevPort ||
			m.subdomainInput.Value() != prevSub || m.timeoutInput.Value() != prevTimeout ||
			m.forwardURLInput.Value() != prevFwd) {
			m.selectedSession = -1
		}
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

	// Recent sessions
	if len(m.recentSessions) > 0 {
		header := "Recent Sessions"
		if m.sessionsFocused {
			header += " (↑/↓ select • Enter loads)"
		}
		b.WriteString(headerStyle.Render(header) + "\n")
		for i, s := range m.recentSessions {
			arrow := "   "
			if m.sessionsFocused && m.selectedSession == i {
				arrow = " ▶ "
			}
			label := fmt.Sprintf(":%s", s.Port)
			if s.Subdomain != "" {
				label += fmt.Sprintf(" (%s)", s.Subdomain)
			}
			if s.ForwardURL != "" {
				label += fmt.Sprintf(" → %s", s.ForwardURL)
			}
			provLabel := s.Provider
			if provLabel == "" {
				provLabel = providerLocaltunnel
			}
			label += fmt.Sprintf(" [%dm, %s]", s.TimeoutMin, provLabel)
			if m.selectedSession == i {
				b.WriteString(fmt.Sprintf("%s%s\n", arrow, highlightStyle.Render(label)))
			} else {
				b.WriteString(fmt.Sprintf("%s%s\n", arrow, label))
			}
		}
		b.WriteString("\n")
	}

	// Public IP section
	b.WriteString(headerStyle.Render("Public IP Address") + "\n")
	if m.fetchingIP {
		b.WriteString(m.spinner.View() + " Fetching...\n")
	} else {
		b.WriteString(highlightStyle.Render(m.publicIP) + "\n")
		b.WriteString(infoStyle.Render("(Use this for webhook authentication if needed)") + "\n")
	}
	b.WriteString("\n")

	// Tunnel provider
	b.WriteString(headerStyle.Render("Tunnel Provider") + "\n")
	provider := m.provider
	if provider == "" {
		provider = providerCloudflared
	}
	b.WriteString(highlightStyle.Render(provider) + "\n")
	b.WriteString(infoStyle.Render("Ctrl+T toggles cloudflared ↔ localtunnel (cloudflared is recommended)") + "\n\n")

	// Port input
	b.WriteString(headerStyle.Render("Local Port") + "\n")
	if m.focusedInput == 0 {
		b.WriteString(selectedStyle.Render(m.portInput.View()) + "\n")
	} else {
		b.WriteString(m.portInput.View() + "\n")
	}
	b.WriteString(infoStyle.Render("Port for the local webhook server") + "\n\n")

	// Subdomain input
	subLabel := "Subdomain (optional)"
	if provider == providerCloudflared {
		subLabel = "Subdomain (ignored — cloudflared quick tunnels assign random)"
	}
	b.WriteString(headerStyle.Render(subLabel) + "\n")
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

	// Forward URL input
	b.WriteString(headerStyle.Render("Forward URL (optional)") + "\n")
	if m.focusedInput == 3 {
		b.WriteString(selectedStyle.Render(m.forwardURLInput.View()) + "\n")
	} else {
		b.WriteString(m.forwardURLInput.View() + "\n")
	}
	b.WriteString(infoStyle.Render("Forward received webhooks to this URL (e.g., http://localhost:3000)") + "\n\n")

	// Help
	if m.sessionsFocused {
		b.WriteString(helpStyle.Render("↑/↓: select session • Enter: load • Tab: fields • Ctrl+T: toggle provider • q: quit"))
	} else {
		b.WriteString(helpStyle.Render("Tab: switch fields • Enter: start • Ctrl+T: toggle provider • q: quit"))
	}

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

		providerLabel := m.provider
		if providerLabel == "" {
			providerLabel = providerCloudflared
		}
		b.WriteString(fmt.Sprintf("  Tunnel: %s %s %s\n", successStyle.Render("●"), m.tunnelURL, infoStyle.Render("("+providerLabel+")")))
		b.WriteString(fmt.Sprintf("  Webhook URL: %s\n", highlightStyle.Render(m.tunnelURL)))
		b.WriteString(fmt.Sprintf("  Expires in: %s\n", countdownStyle.Render(remainingStr)))
	} else {
		providerLabel := m.provider
		if providerLabel == "" {
			providerLabel = providerCloudflared
		}
		subdomainInfo := ""
		if m.provider == providerLocaltunnel && m.requestedSubdomain != "" {
			subdomainInfo = fmt.Sprintf(" (subdomain: %s)", m.requestedSubdomain)
		}
		b.WriteString(fmt.Sprintf("  Tunnel: %s Starting %s...%s\n", m.spinner.View(), providerLabel, subdomainInfo))
	}
	// Forward URL
	if m.forwardURL != "" {
		b.WriteString(fmt.Sprintf("  Forward: %s %s\n", successStyle.Render("●"), m.forwardURL))
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
	b.WriteString("\n" + helpStyle.Render("j/k: select • n/p: page • Enter: details • t: view • y: copy URL • r: reconnect • l: load DB • c: clear • q: quit"))
	if m.statusMsg != "" {
		b.WriteString("\n" + m.statusMsg)
	}

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

// detectSignatureHeader scans headers for known webhook signature patterns.
// Returns the header name, detected algorithm (or ""), and the signature value.
func detectSignatureHeader(headers map[string]string) (headerName, algo, sigValue string) {
	for k, v := range headers {
		lower := strings.ToLower(k)
		switch lower {
		case "x-hub-signature-256":
			if strings.HasPrefix(v, "sha256=") {
				return k, "sha256", strings.TrimPrefix(v, "sha256=")
			}
			return k, "sha256", v
		case "x-hub-signature":
			if strings.HasPrefix(v, "sha1=") {
				return k, "sha1", strings.TrimPrefix(v, "sha1=")
			}
			return k, "sha1", v
		}
	}
	// Fallback: look for any header containing "signature" (case-insensitive)
	for k, v := range headers {
		if strings.Contains(strings.ToLower(k), "signature") {
			// Try to parse "algo=hex" format
			if idx := strings.Index(v, "="); idx > 0 {
				prefix := strings.ToLower(v[:idx])
				switch prefix {
				case "sha1", "sha256", "sha512":
					return k, prefix, v[idx+1:]
				}
			}
			// Unknown format — return without algo
			return k, "", v
		}
	}
	return "", "", ""
}

// computeHMAC computes an HMAC using the given algorithm, secret, and body.
func computeHMAC(algo, secret, body string) (string, error) {
	var h func() hash.Hash
	switch algo {
	case "sha1":
		h = sha1.New
	case "sha256":
		h = sha256.New
	case "sha512":
		h = sha512.New
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", algo)
	}
	mac := hmac.New(h, []byte(secret))
	mac.Write([]byte(body))
	return hex.EncodeToString(mac.Sum(nil)), nil
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
	b.WriteString(fmt.Sprintf("%s %s\n", highlightStyle.Render("Time:"), wh.Timestamp.Format(time.RFC3339)))

	// Forward status
	if m.forwardURL != "" {
		status := m.forwardStatus[wh.ID]
		if status == "" {
			status = infoStyle.Render("not forwarded")
		}
		b.WriteString(fmt.Sprintf("%s %s\n", highlightStyle.Render("Forward:"), status))
	}
	b.WriteString("\n")

	// Headers
	b.WriteString(headerStyle.Render("Headers") + "\n")
	for k, v := range wh.Headers {
		b.WriteString(fmt.Sprintf("  %s: %s\n", highlightStyle.Render(k), v))
	}
	b.WriteString("\n")

	// Body
	b.WriteString(headerStyle.Render("Body") + "\n")
	if m.showRawBody {
		if wh.Body != "" {
			b.WriteString(bodyStyle.Render(wh.Body) + "\n")
		} else {
			b.WriteString(infoStyle.Render("(empty)") + "\n")
		}
	} else if wh.BodyJSON != nil {
		prettyJSON, err := json.MarshalIndent(wh.BodyJSON, "", "  ")
		if err == nil {
			b.WriteString(highlightJSON(string(prettyJSON)) + "\n")
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
	headerText := fmt.Sprintf("Webhook #%d Details", wh.ID)
	if m.showRawBody {
		headerText += " [RAW]"
	}
	b.WriteString(headerStyle.Render(headerText) + "\n\n")

	// Viewport with scrollable content
	b.WriteString(m.viewport.View() + "\n\n")

	// Scroll indicator with optional search info
	scrollPercent := int(m.viewport.ScrollPercent() * 100)
	var scrollInfo string
	if m.searchQuery != "" && len(m.searchMatches) > 0 {
		scrollInfo = infoStyle.Render(fmt.Sprintf("─── %d%% ─── match %d/%d for '%s' ───",
			scrollPercent, m.searchMatchIdx+1, len(m.searchMatches), m.searchQuery))
	} else if m.searchQuery != "" {
		scrollInfo = infoStyle.Render(fmt.Sprintf("─── %d%% ─── no matches for '%s' ───",
			scrollPercent, m.searchQuery))
	} else if m.statusMsg != "" {
		scrollInfo = infoStyle.Render(fmt.Sprintf("─── %d%% ─── ", scrollPercent)) + m.statusMsg + infoStyle.Render(" ───")
	} else {
		scrollInfo = infoStyle.Render(fmt.Sprintf("─── %d%% ───", scrollPercent))
	}
	b.WriteString(scrollInfo + "\n")

	// Help or modal input
	if m.signatureMode {
		switch m.signatureStep {
		case 0:
			b.WriteString(fmt.Sprintf("Verify Signature (%s: %s)\n", highlightStyle.Render(m.signatureHeader), m.signatureAlgo))
			b.WriteString(m.secretInput.View())
		case 1:
			b.WriteString(fmt.Sprintf("Verify Signature (%s) — Choose algorithm:\n", highlightStyle.Render(m.signatureHeader)))
			for i, choice := range m.algoChoices {
				cursor := "  "
				if i == m.algoSelectedIdx {
					cursor = "> "
					b.WriteString(highlightStyle.Render(cursor+choice) + "\n")
				} else {
					b.WriteString(cursor + choice + "\n")
				}
			}
		case 2:
			b.WriteString(m.signatureResult + "\n")
			b.WriteString(infoStyle.Render("Press any key to dismiss"))
		}
	} else if m.searchMode {
		b.WriteString(m.searchInput.View())
	} else {
		b.WriteString(helpStyle.Render("↑/↓/j/k: scroll • /: search • n/N: next/prev • g/G: top/bottom • r: raw • y: copy • f: forward • s: verify sig • Esc: back"))
	}

	return b.String()
}

// findSearchMatches finds all lines containing the search query
func (m *Model) findSearchMatches() {
	m.searchMatches = nil
	if m.searchQuery == "" || m.detailContent == "" {
		return
	}

	lines := strings.Split(m.detailContent, "\n")
	query := strings.ToLower(m.searchQuery)

	for i, line := range lines {
		// Strip ANSI codes for searching
		cleanLine := stripANSI(line)
		if strings.Contains(strings.ToLower(cleanLine), query) {
			m.searchMatches = append(m.searchMatches, i)
		}
	}
}

// updateDetailViewport updates the viewport content with line numbers and search highlighting
func (m *Model) updateDetailViewport() {
	if m.detailContent == "" {
		return
	}

	var content string
	if m.searchQuery != "" {
		content = highlightSearchMatches(m.detailContent, m.searchQuery)
	} else {
		content = m.detailContent
	}

	numbered := addLineNumbers(content, m.detailGutterWidth)
	m.viewport.SetContent(numbered)
}

// highlightSearchMatches highlights all occurrences of query in the content
func highlightSearchMatches(content, query string) string {
	if query == "" {
		return content
	}

	lines := strings.Split(content, "\n")
	var result strings.Builder

	for i, line := range lines {
		result.WriteString(highlightLineMatches(line, query))
		if i < len(lines)-1 {
			result.WriteString("\n")
		}
	}

	return result.String()
}

// highlightLineMatches highlights matches in a single line (case-insensitive)
func highlightLineMatches(line, query string) string {
	if query == "" {
		return line
	}

	lowerLine := strings.ToLower(stripANSI(line))
	lowerQuery := strings.ToLower(query)

	// If no match in this line, return as-is
	if !strings.Contains(lowerLine, lowerQuery) {
		return line
	}

	// For lines with ANSI codes, we need to be careful
	// Simple approach: find matches in clean text, then highlight in original
	// This is tricky with ANSI codes, so let's do a simpler approach:
	// Replace matches case-insensitively
	var result strings.Builder
	remaining := line

	for len(remaining) > 0 {
		// Find next match (case-insensitive) in the remaining string
		cleanRemaining := strings.ToLower(stripANSI(remaining))
		idx := strings.Index(cleanRemaining, lowerQuery)

		if idx == -1 {
			result.WriteString(remaining)
			break
		}

		// Find the actual position in the string with ANSI codes
		actualIdx := findActualIndex(remaining, idx)

		// Write everything before the match
		result.WriteString(remaining[:actualIdx])

		// Find the end of the match (accounting for ANSI codes)
		matchEnd := findActualIndex(remaining, idx+len(query))

		// Extract and highlight the match
		match := remaining[actualIdx:matchEnd]
		result.WriteString(searchHighlightStyle.Render(stripANSI(match)))

		remaining = remaining[matchEnd:]
	}

	return result.String()
}

// findActualIndex finds the actual byte index in a string with ANSI codes
// given a visual character index (ignoring ANSI codes)
func findActualIndex(s string, visualIdx int) int {
	ansiPattern := regexp.MustCompile(`\x1b\[[0-9;]*m`)

	actualIdx := 0
	visualCount := 0

	for actualIdx < len(s) && visualCount < visualIdx {
		// Check if we're at the start of an ANSI sequence
		if loc := ansiPattern.FindStringIndex(s[actualIdx:]); loc != nil && loc[0] == 0 {
			// Skip the ANSI sequence
			actualIdx += loc[1]
		} else {
			// Regular character
			actualIdx++
			visualCount++
		}
	}

	return actualIdx
}

// stripANSI removes ANSI escape codes from a string
func stripANSI(s string) string {
	ansiPattern := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	return ansiPattern.ReplaceAllString(s, "")
}

// wrapContent wraps text to the specified width while preserving ANSI escape codes
func wrapContent(content string, width int) string {
	// wrap.String is ANSI-aware and will hard-wrap at the specified width
	return wrap.String(content, width)
}

// highlightJSON applies syntax highlighting to JSON text
func highlightJSON(jsonStr string) string {
	var result strings.Builder
	lines := strings.Split(jsonStr, "\n")

	for i, line := range lines {
		result.WriteString(highlightJSONLine(line))
		if i < len(lines)-1 {
			result.WriteString("\n")
		}
	}

	return result.String()
}

// highlightJSONLine highlights a single line of JSON
func highlightJSONLine(line string) string {
	trimmed := strings.TrimSpace(line)
	indent := line[:len(line)-len(trimmed)]

	// Empty or whitespace-only line
	if trimmed == "" {
		return line
	}

	// Bracket-only lines
	if trimmed == "{" || trimmed == "}" || trimmed == "[" || trimmed == "]" ||
		trimmed == "{," || trimmed == "}," || trimmed == "[," || trimmed == "]," {
		bracket := strings.TrimSuffix(trimmed, ",")
		comma := ""
		if strings.HasSuffix(trimmed, ",") {
			comma = ","
		}
		return indent + jsonBracketStyle.Render(bracket) + comma
	}

	// Check if line has a key (starts with ")
	if strings.HasPrefix(trimmed, "\"") {
		colonIdx := strings.Index(trimmed, "\":")
		if colonIdx > 0 {
			// This is a key: value line
			key := trimmed[:colonIdx+1]
			rest := trimmed[colonIdx+2:] // skip ":

			var result strings.Builder
			result.WriteString(indent)
			result.WriteString(jsonKeyStyle.Render(key))
			result.WriteString(": ")

			value := strings.TrimSpace(rest)
			result.WriteString(highlightJSONValue(value))
			return result.String()
		}
	}

	// Array element (string, number, etc.)
	return indent + highlightJSONValue(trimmed)
}

// highlightJSONValue highlights a JSON value
func highlightJSONValue(value string) string {
	// Remove trailing comma for analysis
	hasComma := strings.HasSuffix(value, ",")
	cleanValue := strings.TrimSuffix(value, ",")
	comma := ""
	if hasComma {
		comma = ","
	}

	// String value
	if strings.HasPrefix(cleanValue, "\"") && strings.HasSuffix(cleanValue, "\"") {
		return jsonStringStyle.Render(cleanValue) + comma
	}

	// Boolean
	if cleanValue == "true" || cleanValue == "false" {
		return jsonBoolStyle.Render(cleanValue) + comma
	}

	// Null
	if cleanValue == "null" {
		return jsonNullStyle.Render(cleanValue) + comma
	}

	// Number (int or float)
	if regexp.MustCompile(`^-?\d+\.?\d*([eE][+-]?\d+)?$`).MatchString(cleanValue) {
		return jsonNumberStyle.Render(cleanValue) + comma
	}

	// Array/object start
	if cleanValue == "[" || cleanValue == "{" {
		return jsonBracketStyle.Render(cleanValue) + comma
	}

	// Default - return as-is
	return value
}

// addLineNumbers adds vim-style line numbers to content
func addLineNumbers(content string, gutterWidth int) string {
	lines := strings.Split(content, "\n")
	var result strings.Builder

	for i, line := range lines {
		lineNum := fmt.Sprintf("%*d", gutterWidth, i+1)
		result.WriteString(lineNumberStyle.Render(lineNum))
		result.WriteString(" │ ")
		result.WriteString(line)
		if i < len(lines)-1 {
			result.WriteString("\n")
		}
	}

	return result.String()
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
	port := flag.String("port", "", "Port for the webhook server (default: 8098)")
	subdomain := flag.String("subdomain", "", "Subdomain for the tunnel (localtunnel only)")
	fwd := flag.String("fwd", "", "URL to forward webhooks to")
	timeout := flag.Int("timeout", 0, "Tunnel timeout in minutes (default: 30)")
	tunnel := flag.String("tunnel", "", "Tunnel provider: cloudflared (default) or localtunnel")
	flag.Parse()

	switch *tunnel {
	case "", providerCloudflared, providerLocaltunnel:
		// valid
	default:
		fmt.Printf("Invalid -tunnel provider %q (expected cloudflared or localtunnel)\n", *tunnel)
		os.Exit(1)
	}

	// Initialize database
	if err := initDB(); err != nil {
		fmt.Printf("Failed to initialize database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	m := initialModel()

	// If any flags provided, skip setup and go straight to running
	if *port != "" || *subdomain != "" || *fwd != "" || *timeout != 0 || *tunnel != "" {
		if *port == "" {
			*port = "8098"
		}
		if *timeout <= 0 {
			*timeout = 30
		}
		provider := *tunnel
		if provider == "" {
			provider = providerCloudflared
		}
		if provider == providerCloudflared && *subdomain != "" {
			fmt.Println("Note: -subdomain is ignored when using cloudflared quick tunnels")
			*subdomain = ""
		}
		m.state = StateRunning
		m.portInput.SetValue(*port)
		m.subdomainInput.SetValue(*subdomain)
		m.requestedPort = *port
		m.requestedSubdomain = *subdomain
		m.provider = provider
		m.forwardURL = strings.TrimSpace(*fwd)
		m.tunnelTimeout = time.Duration(*timeout) * time.Minute
		saveSession(*port, *subdomain, *timeout, m.forwardURL, provider)
	}

	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running program: %v\n", err)
		os.Exit(1)
	}
}
