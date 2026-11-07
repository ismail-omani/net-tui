// Package engine orchestrates discovery, port scanning and credential
// probing.
package engine

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nettui/internal/creds"
	"nettui/internal/execx"
	"nettui/internal/model"
	"nettui/internal/netutil"
	"nettui/internal/priv"
	"nettui/internal/probe"
	"nettui/internal/report"
	"nettui/internal/scan"
)

// DefaultPorts is the nmap port list used for service discovery.
const DefaultPorts = "21,22,23,80,443,554,631,1883,2222,2323,5000,5900-5902,7547,8000,8080,8081,8088,8443,8554,8883,9000,37777,34567,49152"

// Options configures the engine.
type Options struct {
	Iface        string
	Target       string
	Ports        string
	Concurrency  int
	MaxCreds     int
	Timeout      time.Duration
	AttemptDelay time.Duration
	DryRun       bool
	Verbose      bool
	ResultsDir   string
	CredsDir     string
	Store        *creds.Store
	Exec         *priv.Exec
	Emit         func(model.Event)
	Paused       *atomic.Bool
	OnStderr     func(string)
}

// Engine runs one scan session.
type Engine struct {
	opts   Options
	exec   *priv.Exec
	writer *report.Writer

	mu      sync.Mutex
	devices map[string]*model.Device
	order   []string
	found   int
	runErr  error

	start  time.Time
	paused *atomic.Bool
}

// New creates an engine.
func New(opts Options) (*Engine, error) {
	if opts.Ports == "" {
		opts.Ports = DefaultPorts
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 8
	}
	if opts.MaxCreds <= 0 {
		opts.MaxCreds = 20
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 6 * time.Second
	}
	if opts.AttemptDelay <= 0 {
		opts.AttemptDelay = 300 * time.Millisecond
	}
	if opts.ResultsDir == "" {
		opts.ResultsDir = "results"
	}
	if opts.Exec == nil {
		opts.Exec = priv.New()
	}
	if opts.Paused == nil {
		opts.Paused = &atomic.Bool{}
	}
	writer, err := report.New(opts.ResultsDir)
	if err != nil {
		return nil, err
	}
	return &Engine{
		opts:    opts,
		exec:    opts.Exec,
		writer:  writer,
		devices: map[string]*model.Device{},
		paused:  opts.Paused,
	}, nil
}

// Writer exposes the report writer (used for flushes on quit).
func (e *Engine) Writer() *report.Writer { return e.writer }

// Run executes the full scan. It blocks until done or the context is
// cancelled.
func (e *Engine) Run(ctx context.Context) {
	e.start = time.Now()
	defer e.writer.Close()

	store := e.opts.Store
	if store == nil {
		e.fail(fmt.Errorf("credential store is not loaded"))
		return
	}
	e.logf("info", "credentials: %s", store.Summary())

	ifaces, err := netutil.List()
	if err != nil {
		if e.opts.Target == "" {
			e.fail(err)
			return
		}
	}
	iface := netutil.Find(ifaces, e.opts.Iface, e.opts.Target)
	if iface == nil && e.opts.Target == "" {
		e.fail(fmt.Errorf("no active network interface found"))
		return
	}
	target := e.opts.Target
	if target == "" && iface != nil {
		target = iface.Network.String()
	}
	if iface != nil {
		e.logf("info", "interface %s (%s), target %s", iface.Name, iface.Addr, target)
	} else {
		e.logf("info", "target %s (no matching interface)", target)
	}

	e.setPhase(model.PhaseDiscover, 0.02)
	entries, err := e.discover(ctx, iface, target)
	if err != nil {
		e.fail(err)
		return
	}
	if ctx.Err() != nil {
		return
	}
	if len(entries) == 0 {
		e.logf("warn", "no hosts found on %s", target)
		e.finish(ctx)
		return
	}
	e.buildDevices(entries)
	e.emitDevices()
	e.setProgress(0.18)
	e.logf("success", "discovered %d hosts", len(entries))

	if e.opts.DryRun {
		e.logf("info", "dry run: skipping credential probing")
	}

	e.setPhase(model.PhasePortScan, 0.2)
	hosts, err := e.portScan(ctx, target)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		e.logf("warn", "port scan failed: %v", err)
	} else {
		e.mergePorts(hosts)
		e.emitDevices()
	}
	e.setProgress(0.4)
	if ctx.Err() != nil {
		return
	}
	if e.opts.DryRun {
		e.finish(ctx)
		return
	}

	e.setPhase(model.PhaseProbe, 0.4)
	e.markProbing()
	e.probeAll(ctx)
	e.finish(ctx)
}

func (e *Engine) discover(ctx context.Context, iface *netutil.Iface, target string) ([]scan.ArpEntry, error) {
	if e.exec.Privileged() && iface != nil {
		arpTarget := target
		if target == iface.Network.String() {
			arpTarget = "" // use arp-scan --localnet
		}
		entries, err := scan.ARPScan(ctx, e.exec, iface.Name, arpTarget)
		if err == nil {
			if len(entries) > 0 {
				e.logf("info", "arp-scan found %d hosts", len(entries))
				return entries, nil
			}
			e.logf("warn", "arp-scan returned no hosts, falling back to nmap -sn")
		} else if ctx.Err() == nil {
			e.logf("warn", "arp-scan failed: %v", err)
		}
	}
	hosts, err := scan.Discover(ctx, e.exec, target, func(line string) {
		e.stderr(line)
	})
	if err != nil {
		return nil, err
	}
	entries := make([]scan.ArpEntry, 0, len(hosts))
	for _, h := range hosts {
		entries = append(entries, scan.ArpEntry{IP: h.IP, MAC: h.MAC, Vendor: h.MACVendor})
	}
	e.logf("info", "nmap -sn found %d hosts", len(entries))
	return entries, nil
}

func (e *Engine) portScan(ctx context.Context, target string) ([]scan.Host, error) {
	e.mu.Lock()
	targets := make([]string, 0, len(e.order))
	targets = append(targets, e.order...)
	e.mu.Unlock()
	if len(targets) == 0 {
		return nil, nil
	}
	return scan.Nmap(ctx, e.exec, scan.NmapOptions{
		Targets:  targets,
		Ports:    e.opts.Ports,
		Root:     e.exec.Privileged(),
		OnStderr: func(line string) { e.stderr(line) },
	})
}

func (e *Engine) buildDevices(entries []scan.ArpEntry) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, entry := range entries {
		if _, ok := e.devices[entry.IP]; ok {
			continue
		}
		dev := &model.Device{
			IP:     entry.IP,
			MAC:    entry.MAC,
			Vendor: entry.Vendor,
			Status: "discovered",
		}
		e.devices[entry.IP] = dev
		e.order = append(e.order, entry.IP)
	}
	sort.Slice(e.order, func(i, j int) bool { return ipLess(e.order[i], e.order[j]) })
}

func (e *Engine) mergePorts(hosts []scan.Host) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, h := range hosts {
		dev, ok := e.devices[h.IP]
		if !ok {
			dev = &model.Device{IP: h.IP, Status: "discovered"}
			e.devices[h.IP] = dev
			e.order = append(e.order, h.IP)
		}
		if dev.MAC == "" {
			dev.MAC = h.MAC
		}
		if dev.Vendor == "" {
			dev.Vendor = h.MACVendor
		}
		if dev.Hostname == "" {
			dev.Hostname = h.Hostname
		}
		if h.OS != "" {
			dev.Notes = appendUnique(dev.Notes, "OS: "+h.OS)
		}
		dev.Ports = append([]model.Port{}, h.Ports...)
		if len(dev.Ports) > 0 {
			dev.Status = "ready"
		}
		texts := vendorTexts(dev)
		dev.Vendor = creds.VendorLabel(dev.Vendor, texts...)
	}
	sort.Slice(e.order, func(i, j int) bool { return ipLess(e.order[i], e.order[j]) })
}

func (e *Engine) markProbing() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, dev := range e.devices {
		if len(dev.Ports) > 0 || dev.Status != "discovered" {
			dev.Status = "probing"
		}
	}
}

type task struct {
	dev      *model.Device
	port     model.Port
	protocol string
}

func (e *Engine) buildTasks() []task {
	e.mu.Lock()
	defer e.mu.Unlock()

	var tasks []task
	for _, ip := range e.order {
		dev := e.devices[ip]
		seen := map[string]bool{}
		count := 0
		for _, port := range dev.Ports {
			protocol := protocolForPort(port)
			if protocol == "" {
				continue
			}
			key := protocol + ":" + fmt.Sprint(port.Number)
			if seen[key] {
				continue
			}
			seen[key] = true
			tasks = append(tasks, task{dev: dev, port: port, protocol: protocol})
			count++
			if count >= 8 {
				break
			}
		}
		// SNMP is UDP and is not covered by the TCP port scan.
		tasks = append(tasks, task{dev: dev, port: model.Port{Number: 161, Protocol: "udp", Service: "snmp"}, protocol: "snmp"})
	}
	return tasks
}

func (e *Engine) probeAll(ctx context.Context) {
	tasks := e.buildTasks()
	if len(tasks) == 0 {
		e.logf("info", "nothing to probe")
		return
	}
	e.logf("info", "probing %d service tasks across %d devices", len(tasks), len(e.order))

	var completed int64
	total := int64(len(tasks))
	sem := make(chan struct{}, e.opts.Concurrency)
	hostSems := sync.Map{}
	hostSem := func(ip string) chan struct{} {
		v, _ := hostSems.LoadOrStore(ip, make(chan struct{}, 2))
		return v.(chan struct{})
	}

	var wg sync.WaitGroup
	for _, t := range tasks {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(t task) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			hs := hostSem(t.dev.IP)
			select {
			case hs <- struct{}{}:
				defer func() { <-hs }()
			case <-ctx.Done():
				return
			}
			for e.paused.Load() {
				select {
				case <-ctx.Done():
					return
				case <-time.After(200 * time.Millisecond):
				}
			}
			e.runTask(ctx, t)
			done := atomic.AddInt64(&completed, 1)
			e.setProgress(0.4 + 0.6*float64(done)/float64(total))
		}(t)
	}
	wg.Wait()
}

func (e *Engine) runTask(ctx context.Context, t task) {
	runner := probe.Registry[t.protocol]
	if runner == nil {
		return
	}
	dev := t.dev
	env := probe.Env{
		IP:          dev.IP,
		Port:        t.port.Number,
		Protocol:    t.protocol,
		Vendor:      dev.Vendor,
		VendorTexts: vendorTexts(dev),
		Store:       e.opts.Store,
		Timeout:     e.opts.Timeout,
		MaxCreds:    e.opts.MaxCreds,
		Delay:       e.opts.AttemptDelay,
		Log: func(format string, args ...any) {
			e.logf("debug", format, args...)
		},
		Note: func(format string, args ...any) {
			e.logf("info", format, args...)
		},
		Attempt: func(login, password string, ok bool) {
			e.writer.Attempt(dev.IP, t.protocol, t.port.Number, login, password, ok, "")
		},
	}
	finding, err := runner(ctx, env)
	if err != nil {
		if ctx.Err() == nil {
			e.logf("debug", "%s %s:%d: %v", t.protocol, dev.IP, t.port.Number, err)
		}
		return
	}
	if finding != nil {
		e.addFinding(dev.IP, *finding)
	}
}

func (e *Engine) addFinding(ip string, f model.Finding) {
	e.mu.Lock()
	dev, ok := e.devices[ip]
	if !ok {
		e.mu.Unlock()
		return
	}
	duplicate := false
	for _, existing := range dev.Findings {
		if existing.Protocol == f.Protocol && existing.Port == f.Port &&
			existing.Login == f.Login && existing.Password == f.Password {
			duplicate = true
			break
		}
	}
	if !duplicate {
		dev.Findings = append(dev.Findings, f)
		dev.Status = "found"
		e.found++
	}
	e.mu.Unlock()
	if duplicate {
		return
	}

	written, err := e.writer.AddFinding(ip, f)
	if err != nil {
		e.logf("error", "write result for %s: %v", ip, err)
	} else if written {
		e.logf("success", "FOUND %s %s:%d  %s:%s", ip, f.Protocol, f.Port, printable(f.Login), printable(f.Password))
		e.emit(model.Event{Type: model.EvFinding, IP: ip, Finding: &f})
		e.emitDevices()
	}
}

func (e *Engine) finish(ctx context.Context) {
	e.mu.Lock()
	// Replace transient states ("discovered", "ready", "probing") with a
	// clear final result so the UI and _devices.json never look unfinished.
	for _, dev := range e.devices {
		switch {
		case len(dev.Findings) > 0:
			dev.Status = "found"
		case e.opts.DryRun:
			dev.Status = "scanned"
		case len(dev.Ports) > 0:
			dev.Status = "clean"
		default:
			dev.Status = "no ports"
		}
	}
	snapshot := e.snapshotLocked()
	found := e.found
	e.mu.Unlock()

	if err := e.writer.WriteDevices(snapshot); err != nil {
		e.logf("warn", "write device inventory: %v", err)
	}
	e.setPhase(model.PhaseDone, 1)
	msg := fmt.Sprintf("scan complete: %d devices, %d findings, %s", len(snapshot), found, time.Since(e.start).Round(time.Second))
	e.logf("info", "%s", msg)
	e.emit(model.Event{Type: model.EvDone, Phase: model.PhaseDone, Progress: 1, Message: msg, Devices: snapshot})
	_ = ctx
}

func (e *Engine) fail(err error) {
	e.mu.Lock()
	e.runErr = err
	e.mu.Unlock()
	e.logf("error", "%v", err)
	e.emit(model.Event{Type: model.EvError, Err: err})
	e.emit(model.Event{Type: model.EvDone, Phase: model.PhaseDone})
}

// Flush writes the current device inventory, used on graceful quit.
func (e *Engine) Flush() {
	e.mu.Lock()
	snapshot := e.snapshotLocked()
	e.mu.Unlock()
	e.writer.WriteDevices(snapshot)
}

func (e *Engine) snapshotLocked() []model.Device {
	out := make([]model.Device, 0, len(e.order))
	for _, ip := range e.order {
		dev := e.devices[ip]
		copied := *dev
		copied.Ports = append([]model.Port{}, dev.Ports...)
		copied.Findings = append([]model.Finding{}, dev.Findings...)
		copied.Notes = append([]string{}, dev.Notes...)
		out = append(out, copied)
	}
	return out
}

// Snapshot returns a consistent copy of all devices.
func (e *Engine) Snapshot() []model.Device {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.snapshotLocked()
}

// FindingsCount returns the number of recorded findings.
func (e *Engine) FindingsCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.found
}

// Err returns the fatal error that stopped the scan, if any.
func (e *Engine) Err() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.runErr
}

func (e *Engine) emitDevices() {
	e.mu.Lock()
	snapshot := e.snapshotLocked()
	e.mu.Unlock()
	e.emit(model.Event{Type: model.EvDevices, Devices: snapshot})
}

func (e *Engine) emit(ev model.Event) {
	if e.opts.Emit == nil {
		return
	}
	ev.Time = time.Now()
	e.opts.Emit(ev)
}

func (e *Engine) logf(level, format string, args ...any) {
	if level == "debug" && !e.opts.Verbose {
		return
	}
	e.emit(model.Event{Type: model.EvLog, Level: level, Message: fmt.Sprintf(format, args...)})
}

func (e *Engine) stderr(line string) {
	if e.opts.OnStderr != nil {
		e.opts.OnStderr(line)
		return
	}
	e.logf("info", "%s", line)
}

func (e *Engine) setPhase(phase model.Phase, progress float64) {
	e.emit(model.Event{Type: model.EvPhase, Phase: phase, Progress: progress})
}

func (e *Engine) setProgress(progress float64) {
	if progress > 1 {
		progress = 1
	}
	e.emit(model.Event{Type: model.EvProgress, Progress: progress})
}

func vendorTexts(dev *model.Device) []string {
	texts := []string{dev.Vendor, dev.Hostname}
	for _, p := range dev.Ports {
		texts = append(texts, p.Product, p.Title, p.Service)
	}
	for _, note := range dev.Notes {
		texts = append(texts, note)
	}
	return texts
}

func protocolForPort(p model.Port) string {
	service := strings.ToLower(p.Service)
	tls := strings.EqualFold(p.Tunnel, "ssl")

	switch {
	case strings.Contains(service, "http"):
		if tls || p.Number == 443 || p.Number == 8443 {
			return "https"
		}
		return "http"
	case strings.Contains(service, "ssh"):
		return "ssh"
	case strings.Contains(service, "telnet"):
		return "telnet"
	case strings.Contains(service, "ftp"):
		return "ftp"
	case strings.Contains(service, "rtsp"):
		return "rtsp"
	case strings.Contains(service, "vnc"):
		return "vnc"
	case strings.Contains(service, "mqtt"):
		if p.Number == 8883 {
			return "mqtts"
		}
		return "mqtt"
	case strings.Contains(service, "ipp"):
		return "ipp"
	}

	switch p.Number {
	case 22, 2222:
		return "ssh"
	case 23, 2323:
		return "telnet"
	case 21:
		return "ftp"
	case 554, 8554:
		return "rtsp"
	case 1883:
		return "mqtt"
	case 8883:
		return "mqtts"
	case 631:
		return "ipp"
	case 443, 8443:
		return "https"
	case 80, 8000, 8080, 8081, 8088, 9000, 5000, 7547, 49152:
		return "http"
	case 5900, 5901, 5902:
		return "vnc"
	}
	return ""
}

func printable(s string) string {
	if s == "" {
		return "<empty>"
	}
	return s
}

func ipLess(a, b string) bool {
	ia := netParse(a)
	ib := netParse(b)
	if ia == nil || ib == nil {
		return a < b
	}
	for i := 0; i < 4; i++ {
		if ia[i] != ib[i] {
			return ia[i] < ib[i]
		}
	}
	return false
}

func netParse(s string) []byte {
	return parseIP(s)
}

func parseIP(s string) []byte {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	return ip.To4()
}

func appendUnique(list []string, value string) []string {
	for _, v := range list {
		if v == value {
			return list
		}
	}
	return append(list, value)
}

// Ensure execx.Direct implements execx.Runner (used by tests and headless).
var _ execx.Runner = execx.Direct{}
