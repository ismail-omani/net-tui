// Package scan runs arp-scan and nmap and parses their output.
package scan

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"

	"nettui/internal/execx"
)

// ArpEntry is one host reported by arp-scan.
type ArpEntry struct {
	IP     string
	MAC    string
	Vendor string
}

var dupSuffix = regexp.MustCompile(`\s*\(DUP: \d+\)\s*$`)

// ARPScan runs arp-scan on the given interface. When target is non-empty it
// is passed explicitly, otherwise --localnet is used.
func ARPScan(ctx context.Context, runner execx.Runner, iface, target string) ([]ArpEntry, error) {
	if _, err := exec.LookPath("arp-scan"); err != nil {
		return nil, fmt.Errorf("arp-scan not found in PATH")
	}
	args := []string{"--interface=" + iface, "--plain", "--retry=2", "--timeout=300"}
	if strings.TrimSpace(target) != "" {
		args = append(args, target)
	} else {
		args = append(args, "--localnet")
	}
	cmd := runner.Command(ctx, "arp-scan", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("arp-scan: %s", msg)
	}
	return parseARPScan(stdout.String()), nil
}

func parseARPScan(out string) []ArpEntry {
	var entries []ArpEntry
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 2 {
			fields = strings.Fields(line)
		}
		if len(fields) < 2 {
			continue
		}
		ip := strings.TrimSpace(fields[0])
		mac := strings.TrimSpace(fields[1])
		if net.ParseIP(ip) == nil || !looksLikeMAC(mac) {
			continue
		}
		vendor := ""
		if len(fields) > 2 {
			vendor = strings.Join(fields[2:], " ")
		}
		vendor = strings.TrimSpace(dupSuffix.ReplaceAllString(vendor, ""))
		entries = append(entries, ArpEntry{IP: ip, MAC: strings.ToLower(mac), Vendor: vendor})
	}
	return entries
}

func looksLikeMAC(s string) bool {
	if len(s) < 11 {
		return false
	}
	hex := 0
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
			hex++
		case r == ':' || r == '-':
		default:
			return false
		}
	}
	return hex == 12
}
