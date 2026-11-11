// Package tui implements the Bubble Tea interface.
package tui

import (
	"context"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"nettui/internal/creds"
	"nettui/internal/engine"
	"nettui/internal/model"
	"nettui/internal/netutil"
	"nettui/internal/priv"
)

// Config is the TUI configuration supplied by main.
type Config struct {
	Store        *creds.Store
	Exec         *priv.Exec
	PresetIface  string
	PresetTarget string
	Ports        string
	Concurrency  int
	MaxCreds     int
	Timeout      time.Duration
	AttemptDelay time.Duration
	DryRun       bool
	Verbose      bool
	ResultsDir   string
	CredsDir     string
}

type viewState int

const (
	viewConfirm viewState = iota
	viewIface
	viewPassword
	viewMain
)

type eventMsg struct {
	gen int
	ev  model.Event
}
type engineDoneMsg struct{ gen int }
type autoQuitMsg struct{ gen int }
type authResultMsg struct{ err error }

// Result describes how a TUI session ended. It is printed by main after the
// alternate screen is restored, so the user always gets a clear final status.
type Result struct {
	Completed  bool
	Canceled   bool
	Devices    int
	Findings   int
	ResultsDir string
	Duration   time.Duration
	Err        error
}

type Model struct {
	cfg Config

	state    viewState
	width    int
	height   int
	ifaces   []netutil.Iface
	ifacePos int

	password textinput.Model
	authErr  string

	ctx        context.Context
	cancel     context.CancelFunc
	engine     *engine.Engine
	events     chan model.Event
	gen        int
	paused     *atomic.Bool
	scanning   bool
	engineDone bool
	done       bool
	quitting   bool
	closing    bool
	startedAt  time.Time

	devices  []model.Device
	devPos   int
	detail   bool
	phase    model.Phase
	progress float64
	found    int
	logs     []string
	vp       viewport.Model
	err      error
}

var (
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	dimStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	okStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	warnStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	errStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	foundStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("48")).Bold(true)
	selectStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("212")).Bold(true)
	borderStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("238"))
)

// New builds the initial model.
func New(cfg Config) Model {
	pw := textinput.New()
	pw.Placeholder = "sudo password"
	pw.EchoMode = textinput.EchoPassword
	pw.EchoCharacter = '•'
	pw.CharLimit = 256

	vp := viewport.New(80, 10)
	vp.SetContent("Ready. Confirm authorization to start.")

	return Model{
		cfg:      cfg,
		state:    viewConfirm,
		password: pw,
		paused:   &atomic.Bool{},
		vp:       vp,
	}
}

// Run starts the Bubble Tea program. It returns a summary once the scan is
// finished (or interrupted) so the caller can print a final status.
func Run(cfg Config) (Result, error) {
	m := New(cfg)
	p := tea.NewProgram(m, tea.WithAltScreen())

	// Keep stray net/http diagnostics out of the alternate screen and away
	// from the shell prompt after exit.
	prevLog := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(prevLog)

	final, err := p.Run()
	res := Result{ResultsDir: cfg.ResultsDir}
	if fm, ok := final.(Model); ok {
		res.Completed = fm.done && !fm.quitting
		res.Canceled = fm.quitting || (!fm.done && err == nil)
		res.Devices = len(fm.devices)
		res.Findings = fm.found
		res.Err = fm.err
		if !fm.startedAt.IsZero() {
			res.Duration = time.Since(fm.startedAt)
		}
	}
	return res, err
}

func (m Model) Init() tea.Cmd {
	return nil
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.resize()
		return m, nil

	case authResultMsg:
		if msg.err != nil {
			m.authErr = msg.err.Error()
			m.state = viewPassword
			m.password.Focus()
			return m, textinput.Blink
		}
		m.authErr = ""
		m.password.SetValue("")
		m.addLog("info", "sudo credentials accepted")
		return m, m.startScan()

	case eventMsg:
		if msg.gen != m.gen {
			return m, nil
		}
		m.handleEvent(msg.ev)
		return m, m.waitEvent(msg.gen)

	case engineDoneMsg:
		if msg.gen != m.gen {
			return m, nil
		}
		m.engineDone = true
		m.scanning = false
		if m.done && !m.quitting {
			if m.closing {
				return m, nil
			}
			m.closing = true
			m.addLog("success", "all done - closing in 2s (press q to close now)")
			return m, tea.Tick(2*time.Second, func(time.Time) tea.Msg {
				return autoQuitMsg{gen: msg.gen}
			})
		}
		// Interrupted or failed: the engine is fully stopped now.
		return m, tea.Quit

	case autoQuitMsg:
		if msg.gen == m.gen {
			return m, tea.Quit
		}
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}

	var cmd tea.Cmd
	if m.state == viewPassword {
		m.password, cmd = m.password.Update(msg)
	}
	return m, cmd
}

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	switch m.state {
	case viewConfirm:
		switch key {
		case "y", "Y", "enter":
			return m, m.proceedAfterConfirm()
		case "n", "N", "q", "esc", "ctrl+c":
			return m, tea.Quit
		}
		return m, nil

	case viewIface:
		switch key {
		case "up", "k":
			if m.ifacePos > 0 {
				m.ifacePos--
			}
		case "down", "j":
			if m.ifacePos < len(m.ifaces)-1 {
				m.ifacePos++
			}
		case "enter":
			if len(m.ifaces) > 0 {
				chosen := m.ifaces[m.ifacePos]
				m.cfg.PresetIface = chosen.Name
				m.cfg.PresetTarget = chosen.Network.String()
				m.addLog("info", "selected %s (%s)", chosen.Name, chosen.Network)
				return m, m.authStep()
			}
		case "q", "esc", "ctrl+c":
			return m, tea.Quit
		}
		return m, nil

	case viewPassword:
		switch key {
		case "enter":
			pass := m.password.Value()
			m.authErr = ""
			exec := m.cfg.Exec
			return m, func() tea.Msg {
				return authResultMsg{err: exec.ValidateSudo(pass)}
			}
		case "esc":
			m.cfg.Exec.SetUnprivileged()
			m.addLog("warn", "continuing unprivileged: no arp-scan, no OS detection")
			m.state = viewMain
			return m, m.startScan()
		case "ctrl+c":
			return m, tea.Quit
		}
		var cmd tea.Cmd
		m.password, cmd = m.password.Update(msg)
		return m, cmd

	case viewMain:
		switch key {
		case "q", "ctrl+c":
			if m.closing {
				return m, tea.Quit
			}
			if !m.engineDone {
				if m.quitting {
					// Second press: force exit even if the engine is stuck.
					return m, tea.Quit
				}
				m.quitting = true
				if m.cancel != nil {
					m.cancel()
				}
				if m.engine != nil {
					m.engine.Flush()
				}
				m.addLog("warn", "stopping scan...")
				return m, nil
			}
			return m, tea.Quit
		case "up", "k":
			if m.devPos > 0 {
				m.devPos--
			}
		case "down", "j":
			if m.devPos < len(m.devices)-1 {
				m.devPos++
			}
		case "pgup":
			m.vp.ScrollUp(m.vp.Height / 2)
		case "pgdown":
			m.vp.ScrollDown(m.vp.Height / 2)
		case "enter":
			m.detail = !m.detail
		case "p":
			if m.scanning {
				paused := !m.paused.Load()
				m.paused.Store(paused)
				if paused {
					m.addLog("warn", "probing paused")
				} else {
					m.addLog("info", "probing resumed")
				}
			}
		case "s":
			if !m.scanning {
				return m, m.startScan()
			}
		case "e":
			dir := m.cfg.ResultsDir
			if err := exec.Command("xdg-open", dir).Start(); err != nil {
				m.addLog("warn", "cannot open %s: %v", dir, err)
			}
		}
		return m, nil
	}
	return m, nil
}

func (m *Model) handleEvent(ev model.Event) {
	switch ev.Type {
	case model.EvLog:
		m.addLog(ev.Level, "%s", ev.Message)
	case model.EvPhase:
		m.phase = ev.Phase
		if ev.Progress > 0 {
			m.progress = ev.Progress
		}
	case model.EvProgress:
		m.progress = ev.Progress
	case model.EvDevices:
		m.devices = ev.Devices
		if m.devPos >= len(m.devices) {
			m.devPos = max(0, len(m.devices)-1)
		}
	case model.EvFinding:
		m.found++
	case model.EvError:
		m.err = ev.Err
		if ev.Err != nil {
			m.addLog("error", "%v", ev.Err)
		}
	case model.EvDone:
		m.done = true
		m.scanning = false
		m.phase = model.PhaseDone
		m.progress = 1
		if ev.Devices != nil {
			m.devices = ev.Devices
			if m.devPos >= len(m.devices) {
				m.devPos = max(0, len(m.devices)-1)
			}
		}
		if ev.Message != "" {
			m.addLog("success", "%s", ev.Message)
		}
	}
}

func (m *Model) proceedAfterConfirm() tea.Cmd {
	if m.cfg.PresetIface != "" || m.cfg.PresetTarget != "" {
		return m.authStep()
	}
	ifaces, err := netutil.List()
	if err != nil {
		m.err = err
		m.addLog("error", "interface detection failed: %v", err)
		return nil
	}
	switch len(ifaces) {
	case 0:
		m.err = fmt.Errorf("no active IPv4 interfaces")
		m.addLog("error", "%v", m.err)
		return nil
	case 1:
		m.cfg.PresetIface = ifaces[0].Name
		m.cfg.PresetTarget = ifaces[0].Network.String()
		m.addLog("info", "using %s (%s)", ifaces[0].Name, ifaces[0].Network)
		return m.authStep()
	default:
		m.ifaces = ifaces
		m.ifacePos = 0
		m.state = viewIface
		return nil
	}
}

func (m *Model) authStep() tea.Cmd {
	switch m.cfg.Exec.Mode() {
	case priv.ModeRoot:
		return m.startScan()
	case priv.ModeSudo:
		if m.cfg.Exec.CheckCached() {
			m.cfg.Exec.SetPassword("")
			m.addLog("info", "sudo credentials already cached")
			return m.startScan()
		}
		m.state = viewPassword
		m.password.Focus()
		m.authErr = ""
		return textinput.Blink
	default:
		m.addLog("warn", "sudo is unavailable: running unprivileged")
		return m.startScan()
	}
}

func (m *Model) startScan() tea.Cmd {
	if m.cancel != nil {
		m.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.ctx = ctx
	m.cancel = cancel
	m.state = viewMain
	m.scanning = true
	m.engineDone = false
	m.done = false
	m.quitting = false
	m.closing = false
	m.err = nil
	m.devices = nil
	m.devPos = 0
	m.found = 0
	m.progress = 0
	m.phase = model.PhaseDiscover
	m.startedAt = time.Now()
	m.paused.Store(false)

	ch := make(chan model.Event, 2048)
	m.events = ch
	m.gen++
	gen := m.gen

	opts := engine.Options{
		Iface:        m.cfg.PresetIface,
		Target:       m.cfg.PresetTarget,
		Ports:        m.cfg.Ports,
		Concurrency:  m.cfg.Concurrency,
		MaxCreds:     m.cfg.MaxCreds,
		Timeout:      m.cfg.Timeout,
		AttemptDelay: m.cfg.AttemptDelay,
		DryRun:       m.cfg.DryRun,
		Verbose:      m.cfg.Verbose,
		ResultsDir:   m.cfg.ResultsDir,
		CredsDir:     m.cfg.CredsDir,
		Store:        m.cfg.Store,
		Exec:         m.cfg.Exec,
		Paused:       m.paused,
		Emit: func(ev model.Event) {
			select {
			case ch <- ev:
			case <-ctx.Done():
			}
		},
	}
	eng, err := engine.New(opts)
	if err != nil {
		m.err = err
		m.scanning = false
		m.addLog("error", "%v", err)
		return nil
	}
	m.engine = eng
	m.addLog("info", "scan started")
	go func() {
		eng.Run(ctx)
		close(ch)
	}()
	return m.waitEvent(gen)
}

func (m Model) waitEvent(gen int) tea.Cmd {
	ch := m.events
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return engineDoneMsg{gen: gen}
		}
		return eventMsg{gen: gen, ev: ev}
	}
}

func (m *Model) addLog(level, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	prefix := "  "
	switch level {
	case "warn":
		prefix = "! "
	case "error":
		prefix = "✗ "
	case "success":
		prefix = "✓ "
	case "debug":
		prefix = "· "
	}
	line := fmt.Sprintf("%s %s%s", time.Now().Format("15:04:05"), prefix, msg)
	m.logs = append(m.logs, line)
	if len(m.logs) > 2000 {
		m.logs = m.logs[len(m.logs)-2000:]
	}
	m.syncViewport()
}

func (m *Model) syncViewport() {
	if m.vp.Width <= 0 || m.vp.Height <= 0 {
		return
	}
	m.vp.SetContent(strings.Join(m.logs, "\n"))
	m.vp.GotoBottom()
}

func (m *Model) resize() {
	m.vp.Width = max(20, m.width-2)
	m.vp.Height = max(4, m.height/3)
	m.syncViewport()
}

// View renders the current state.
func (m Model) View() string {
	switch m.state {
	case viewConfirm:
		return m.viewConfirm()
	case viewIface:
		return m.viewIface()
	case viewPassword:
		return m.viewPassword()
	default:
		return m.viewMain()
	}
}

func (m Model) viewConfirm() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("net-dis"))
	b.WriteString("  ")
	b.WriteString(dimStyle.Render("local network default-credential audit"))
	b.WriteString("\n\n")
	b.WriteString("This tool discovers hosts on your local network, scans their services,\n")
	b.WriteString("and tries well-known default credentials over HTTP(S), SSH, Telnet,\n")
	b.WriteString("FTP, RTSP, SNMP, VNC, MQTT and IPP.\n\n")
	b.WriteString(warnStyle.Render("Only scan networks you own or have explicit permission to test.") + "\n\n")
	b.WriteString(okStyle.Render("[y]") + " I have permission, continue    " + errStyle.Render("[n]") + " quit\n")
	return lipgloss.NewStyle().Padding(1, 2).Render(b.String())
}

func (m Model) viewIface() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Select the network to scan") + "\n\n")
	for i, iface := range m.ifaces {
		cursor := "  "
		line := iface.String()
		if i == m.ifacePos {
			cursor = "› "
			line = selectStyle.Render(line)
		}
		b.WriteString(cursor + line + "\n")
	}
	b.WriteString("\n" + dimStyle.Render("↑/↓ select · enter confirm · q quit") + "\n")
	return lipgloss.NewStyle().Padding(1, 2).Render(b.String())
}

func (m Model) viewPassword() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("sudo authentication") + "\n\n")
	b.WriteString("arp-scan and OS detection need root privileges.\n")
	b.WriteString("The password is used in memory only and never written to disk.\n\n")
	b.WriteString(m.password.View() + "\n")
	if m.authErr != "" {
		b.WriteString("\n" + errStyle.Render("✗ "+m.authErr) + "\n")
	}
	b.WriteString("\n" + dimStyle.Render("enter continue · esc run unprivileged · ctrl+c quit") + "\n")
	return lipgloss.NewStyle().Padding(1, 2).Render(b.String())
}

func (m Model) viewMain() string {
	width := m.width
	if width <= 0 {
		width = 100
	}
	height := m.height
	if height <= 0 {
		height = 30
	}

	var b strings.Builder
	b.WriteString(m.headerView(width) + "\n")
	b.WriteString(m.renderTable(width, height) + "\n")

	bottomHeight := max(4, height/3)
	if m.detail {
		b.WriteString(borderStyle.Render(strings.Repeat("─", width)) + "\n")
		b.WriteString(m.detailView(width, bottomHeight))
	} else {
		b.WriteString(borderStyle.Render(strings.Repeat("─", width)) + "\n")
		b.WriteString(m.vp.View())
	}
	b.WriteString("\n" + dimStyle.Render(m.footer()) + "\n")
	return b.String()
}

func (m Model) headerView(width int) string {
	phase := m.phase.String()
	if m.done {
		phase = "Done"
	}
	percent := int(m.progress * 100)
	left := titleStyle.Render("net-dis") + "  " + dimStyle.Render(phase)
	right := fmt.Sprintf("%3d%%", percent)
	gap := width - lipgloss.Width(left) - len(right) - 2
	if gap < 1 {
		gap = 1
	}
	barWidth := max(10, width-30)
	filled := int(float64(barWidth) * m.progress)
	if filled > barWidth {
		filled = barWidth
	}
	bar := okStyle.Render(strings.Repeat("█", filled)) + dimStyle.Render(strings.Repeat("░", barWidth-filled))
	return left + strings.Repeat(" ", gap) + right + "\n" + bar
}

func (m Model) renderTable(width, height int) string {
	header := fmt.Sprintf("%-15s %-17s %-18s %-18s %-10s %5s", "IP", "MAC", "VENDOR", "PORTS", "STATUS", "FOUND")
	lines := []string{dimStyle.Render(truncate(header, width))}

	bottomHeight := max(4, height/3)
	visible := height - bottomHeight - 7
	if visible < 3 {
		visible = 3
	}

	if len(m.devices) == 0 {
		lines = append(lines, dimStyle.Render("  waiting for discovery results..."))
		return strings.Join(lines, "\n")
	}

	start := 0
	if m.devPos >= visible {
		start = m.devPos - visible + 1
	}
	end := min(len(m.devices), start+visible)
	for i := start; i < end; i++ {
		dev := m.devices[i]
		ports := make([]string, 0, 6)
		for _, p := range dev.Ports {
			ports = append(ports, fmt.Sprint(p.Number))
			if len(ports) >= 6 {
				break
			}
		}
		portText := strings.Join(ports, ",")
		if portText == "" {
			portText = "-"
		}
		status := dev.Status
		vendor := dev.Vendor
		if vendor == "" {
			vendor = "unknown"
		}
		row := fmt.Sprintf("%-15s %-17s %-18s %-18s %-10s %5d",
			dev.IP, emptyDash(dev.MAC), truncate(vendor, 18), truncate(portText, 18), status, len(dev.Findings))
		cursor := "  "
		if i == m.devPos {
			cursor = "› "
		}
		// Truncate the plain row before styling. Cutting an ANSI escape
		// sequence leaves broken colour codes and garbage glyphs on screen.
		available := width - len([]rune(cursor))
		if available < 1 {
			available = 1
		}
		row = truncate(row, available)

		style := lipgloss.NewStyle()
		switch {
		case len(dev.Findings) > 0:
			style = foundStyle
		case status == "probing":
			style = warnStyle
		}
		if i == m.devPos {
			style = selectStyle
		}
		lines = append(lines, cursor+style.Render(row))
	}
	return strings.Join(lines, "\n")
}

func (m Model) detailView(width, height int) string {
	if len(m.devices) == 0 || m.devPos >= len(m.devices) {
		return "No device selected"
	}
	dev := m.devices[m.devPos]
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s  %s  %s\n", dev.IP, emptyDash(dev.MAC), emptyDash(dev.Vendor)))
	if dev.Hostname != "" {
		b.WriteString("hostname: " + dev.Hostname + "\n")
	}
	for _, note := range dev.Notes {
		b.WriteString(dimStyle.Render(note) + "\n")
	}
	if len(dev.Ports) > 0 {
		var ports []string
		for _, p := range dev.Ports {
			desc := fmt.Sprintf("%d/%s", p.Number, p.Service)
			if p.Product != "" {
				desc += " (" + p.Product
				if p.Version != "" {
					desc += " " + p.Version
				}
				desc += ")"
			}
			ports = append(ports, desc)
		}
		b.WriteString("ports: " + truncate(strings.Join(ports, ", "), width) + "\n")
	}
	if len(dev.Findings) == 0 {
		b.WriteString(dimStyle.Render("no default credentials found yet") + "\n")
	} else {
		b.WriteString(foundStyle.Render("findings:") + "\n")
		for _, f := range dev.Findings {
			b.WriteString(fmt.Sprintf("  %-6s :%-5d %s : %s\n",
				f.Protocol, f.Port, printable(f.Login), printable(f.Password)))
		}
	}
	lines := strings.Split(b.String(), "\n")
	if len(lines) > height {
		lines = lines[:height]
	}
	return strings.Join(lines, "\n")
}

func (m Model) footer() string {
	if m.closing {
		return "finished  |  closing in 2s (q to close now)"
	}
	state := "idle"
	if m.quitting {
		state = "stopping"
	} else if m.scanning {
		state = "scanning"
		if m.paused.Load() {
			state = "paused"
		}
	} else if m.done {
		state = "finished"
	}
	keys := "↑/↓ select · enter details · p pause · s rescan · e results · q quit"
	return fmt.Sprintf("%s  |  %s", state, keys)
}

func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func printable(s string) string {
	if s == "" {
		return "<empty>"
	}
	return s
}

func truncate(s string, width int) string {
	if width <= 0 {
		return s
	}
	runes := []rune(s)
	if len(runes) <= width {
		return s
	}
	if width <= 1 {
		return string(runes[:width])
	}
	return string(runes[:width-1]) + "…"
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
