// Command net-tui performs a local-network default-credential audit.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"

	"nettui/internal/creds"
	"nettui/internal/engine"
	"nettui/internal/model"
	"nettui/internal/netutil"
	"nettui/internal/priv"
	"nettui/internal/tui"
)

const version = "0.1.0"

type cliConfig struct {
	iface        string
	target       string
	ports        string
	concurrency  int
	maxCreds     int
	timeout      time.Duration
	attemptDelay time.Duration
	dryRun       bool
	noTUI        bool
	fetchCreds   bool
	resultsDir   string
	credsDir     string
	yes          bool
	verbose      bool
	showVer      bool
}

func main() {
	cfg := parseFlags()

	if cfg.showVer {
		fmt.Println("net-tui", version)
		return
	}
	if cfg.fetchCreds {
		fmt.Printf("fetching credential lists into %s ...\n", cfg.credsDir)
		if err := creds.Fetch(cfg.credsDir, true); err != nil {
			fatal(err)
		}
		fmt.Println("done")
		return
	}
	if cfg.target != "" {
		if err := validateTarget(cfg.target); err != nil {
			fatal(err)
		}
	}

	store, warnings, err := creds.Load(cfg.credsDir)
	if err != nil {
		fatal(fmt.Errorf("%w\nhint: run `net-tui --fetch-creds` to download the credential lists", err))
	}
	for _, w := range warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}

	exec := priv.New()

	if cfg.noTUI || !isInteractive() {
		runHeadless(cfg, store, exec)
		return
	}

	res, err := tui.Run(tui.Config{
		Store:        store,
		Exec:         exec,
		PresetIface:  cfg.iface,
		PresetTarget: cfg.target,
		Ports:        cfg.ports,
		Concurrency:  cfg.concurrency,
		MaxCreds:     cfg.maxCreds,
		Timeout:      cfg.timeout,
		AttemptDelay: cfg.attemptDelay,
		DryRun:       cfg.dryRun,
		Verbose:      cfg.verbose,
		ResultsDir:   cfg.resultsDir,
		CredsDir:     cfg.credsDir,
	})
	if err != nil {
		fatal(err)
	}
	if res.Duration == 0 && !res.Completed && res.Devices == 0 {
		fmt.Println("no scan was run")
		return
	}
	printSummary(res.Completed, res.Devices, res.Findings, res.ResultsDir, res.Duration, res.Err)
}

// printSummary prints the final status after the TUI has released the
// terminal, so completion is unambiguous even in a shell scrollback.
func printSummary(completed bool, devices, findings int, resultsDir string, duration time.Duration, runErr error) {
	status := "interrupted"
	marker := "!"
	switch {
	case runErr != nil:
		status = "failed"
		marker = "x"
	case completed:
		status = "done"
		marker = "+"
	}
	if duration > 0 {
		fmt.Printf("\n%s scan %s: %d devices, %d findings, %s\n", marker, status, devices, findings, duration.Round(time.Second))
	} else {
		fmt.Printf("\n%s scan %s: %d devices, %d findings\n", marker, status, devices, findings)
	}
	if resultsDir != "" {
		fmt.Printf("results: %s\n", resultsDir)
	}
	if runErr != nil {
		fmt.Fprintln(os.Stderr, "error:", runErr)
	}
}

func parseFlags() cliConfig {
	var cfg cliConfig
	flag.StringVar(&cfg.iface, "iface", "", "interface to scan (default: auto-detect)")
	flag.StringVar(&cfg.target, "target", "", "target CIDR override, e.g. 192.168.1.0/24")
	flag.StringVar(&cfg.ports, "ports", engine.DefaultPorts, "nmap port list")
	flag.IntVar(&cfg.concurrency, "concurrency", 8, "global probe concurrency")
	flag.IntVar(&cfg.maxCreds, "max-creds", 20, "max credentials per host/protocol")
	flag.DurationVar(&cfg.timeout, "timeout", 6*time.Second, "per-probe timeout")
	flag.DurationVar(&cfg.attemptDelay, "attempt-delay", 300*time.Millisecond, "delay between credential attempts")
	flag.BoolVar(&cfg.dryRun, "dry-run", false, "discover and scan only, do not try credentials")
	flag.BoolVar(&cfg.noTUI, "no-tui", false, "headless mode")
	flag.BoolVar(&cfg.fetchCreds, "fetch-creds", false, "download/refresh credential lists and exit")
	flag.StringVar(&cfg.resultsDir, "results", "results", "results directory")
	flag.StringVar(&cfg.credsDir, "creds", "data/creds", "credential list directory")
	flag.BoolVar(&cfg.yes, "yes", false, "skip authorization prompt in headless mode")
	flag.BoolVar(&cfg.verbose, "verbose", false, "verbose probe logging")
	flag.BoolVar(&cfg.showVer, "version", false, "print version")
	flag.Usage = usage
	flag.Parse()
	return cfg
}

func usage() {
	fmt.Fprintf(os.Stderr, `net-tui %s - local network default-credential audit

Usage:
  net-tui [flags]

Common flags:
  --fetch-creds          download default credential lists into --creds
  --no-tui               run without the interactive interface
  --target CIDR          scan a specific private subnet
  --iface NAME           force an interface
  --dry-run              only discover hosts and scan ports
  --concurrency N        parallel probes (default 8)
  --max-creds N          credentials per host/protocol (default 20)
  --timeout DURATION     per-probe timeout (default 6s)
  --attempt-delay DUR    pause between login attempts (default 300ms)
  --results DIR          output directory (default "results")
  --creds DIR            credential directory (default "data/creds")
  --yes                  skip the authorization prompt (headless)
  --verbose              log every probe error
  --version              print version

Examples:
  sudo ./net-tui
  ./net-tui --fetch-creds
  ./net-tui --no-tui --target 192.168.1.0/24 --dry-run
`, version)
}

func validateTarget(target string) error {
	ip, _, err := net.ParseCIDR(target)
	if err != nil {
		return fmt.Errorf("invalid target %q: %w", target, err)
	}
	if !netutil.Private(ip) {
		return fmt.Errorf("refusing to scan non-private target %q", target)
	}
	return nil
}

func isInteractive() bool {
	return term.IsTerminal(int(os.Stdout.Fd())) && term.IsTerminal(int(os.Stdin.Fd()))
}

type printer struct {
	mu sync.Mutex
}

func (p *printer) emit(ev model.Event) {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch ev.Type {
	case model.EvLog:
		prefix := "  "
		switch ev.Level {
		case "warn":
			prefix = "! "
		case "error":
			prefix = "x "
		case "success":
			prefix = "+ "
		case "debug":
			prefix = ". "
		}
		fmt.Printf("%s %s%s\n", time.Now().Format("15:04:05"), prefix, ev.Message)
	case model.EvPhase:
		if ev.Phase != model.PhaseIdle {
			fmt.Printf("== %s ==\n", ev.Phase)
		}
	case model.EvFinding:
		if ev.Finding != nil {
			fmt.Printf("[+] %s %s:%d %s:%s\n", ev.IP, ev.Finding.Protocol, ev.Finding.Port,
				printable(ev.Finding.Login), printable(ev.Finding.Password))
		}
	case model.EvError:
		if ev.Err != nil {
			fmt.Fprintln(os.Stderr, "error:", ev.Err)
		}
	}
}

func runHeadless(cfg cliConfig, store *creds.Store, exec *priv.Exec) {
	fmt.Printf("net-tui %s - local network default-credential audit\n", version)
	if !cfg.yes {
		fmt.Println("Only scan networks you own or have explicit permission to test.")
		fmt.Print(`Type "yes" to continue: `)
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.TrimSpace(strings.ToLower(line)) != "yes" {
			fmt.Println("aborted")
			return
		}
	}

	setupHeadlessPrivileges(exec)

	ifaces, err := netutil.List()
	if err != nil && cfg.target == "" {
		fatal(err)
	}
	target := cfg.target
	iface := cfg.iface
	if target == "" {
		chosen := netutil.Find(ifaces, iface, "")
		if chosen == nil {
			if len(ifaces) > 1 {
				chosen = chooseInterface(ifaces)
			}
		}
		if chosen == nil {
			fatal(fmt.Errorf("no interface selected; use --iface or --target"))
		}
		iface = chosen.Name
		target = chosen.Network.String()
	} else if iface == "" {
		if chosen := netutil.Find(ifaces, "", target); chosen != nil {
			iface = chosen.Name
		}
	}
	fmt.Printf("target %s (interface %s)\n", target, iface)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\nstopping...")
		cancel()
	}()

	p := &printer{}
	eng, err := engine.New(engine.Options{
		Iface:        iface,
		Target:       target,
		Ports:        cfg.ports,
		Concurrency:  cfg.concurrency,
		MaxCreds:     cfg.maxCreds,
		Timeout:      cfg.timeout,
		AttemptDelay: cfg.attemptDelay,
		DryRun:       cfg.dryRun,
		Verbose:      cfg.verbose,
		ResultsDir:   cfg.resultsDir,
		CredsDir:     cfg.credsDir,
		Store:        store,
		Exec:         exec,
		Emit:         p.emit,
	})
	if err != nil {
		fatal(err)
	}
	start := time.Now()
	eng.Run(ctx)

	snapshot := eng.Snapshot()
	findings := eng.FindingsCount()
	printSummary(ctx.Err() == nil, len(snapshot), findings, cfg.resultsDir, time.Since(start), eng.Err())
}

func setupHeadlessPrivileges(exec *priv.Exec) {
	switch exec.Mode() {
	case priv.ModeRoot:
		return
	case priv.ModeSudo:
		if exec.CheckCached() {
			exec.SetPassword("")
			return
		}
		if term.IsTerminal(int(os.Stdin.Fd())) {
			fmt.Print("sudo password: ")
			pw, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err == nil && exec.ValidateSudo(string(pw)) == nil {
				return
			}
			fmt.Fprintln(os.Stderr, "warning: sudo authentication failed, continuing unprivileged")
		} else {
			fmt.Fprintln(os.Stderr, "warning: sudo needs a password but stdin is not a terminal; continuing unprivileged")
		}
		exec.SetUnprivileged()
	default:
		fmt.Fprintln(os.Stderr, "warning: no sudo available, continuing unprivileged (no arp-scan)")
	}
}

func chooseInterface(ifaces []netutil.Iface) *netutil.Iface {
	fmt.Println("Available networks:")
	for i, iface := range ifaces {
		fmt.Printf("  %d) %s\n", i+1, iface.String())
	}
	fmt.Printf("Select [1-%d]: ", len(ifaces))
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	line = strings.TrimSpace(line)
	var idx int
	if _, err := fmt.Sscanf(line, "%d", &idx); err != nil || idx < 1 || idx > len(ifaces) {
		return nil
	}
	return &ifaces[idx-1]
}

func printable(s string) string {
	if s == "" {
		return "<empty>"
	}
	return s
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
