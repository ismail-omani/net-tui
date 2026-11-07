package scan

import (
	"bufio"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"

	"nettui/internal/execx"
	"nettui/internal/model"
)

// Host is one host parsed from nmap XML output.
type Host struct {
	IP        string
	MAC       string
	MACVendor string
	Hostname  string
	OS        string
	Ports     []model.Port
	Up        bool
}

// NmapOptions configures a port/service scan.
type NmapOptions struct {
	Targets    []string
	Ports      string
	Root       bool
	StatsEvery time.Duration
	OnStderr   func(line string)
}

// Nmap runs a port and service scan and returns parsed hosts.
func Nmap(ctx context.Context, runner execx.Runner, opts NmapOptions) ([]Host, error) {
	args := []string{"-Pn", "-T4", "--max-retries", "1", "--host-timeout", "90s"}
	if opts.Root {
		args = append(args, "-sS", "-sV", "-O", "--osscan-limit", "--osscan-guess")
	} else {
		args = append(args, "-sT", "-sV")
	}
	stats := opts.StatsEvery
	if stats <= 0 {
		stats = 5 * time.Second
	}
	args = append(args,
		"--stats-every", stats.String(),
		"--script", "banner,http-title,http-headers",
		"-p", opts.Ports,
		"-oX", "-",
	)
	args = append(args, opts.Targets...)
	return runXML(ctx, runner, "nmap", args, opts.OnStderr, true)
}

// Discover performs host discovery only (nmap -sn) and is used as a fallback
// when arp-scan is unavailable.
func Discover(ctx context.Context, runner execx.Runner, target string, onStderr func(string)) ([]Host, error) {
	if strings.TrimSpace(target) == "" {
		return nil, fmt.Errorf("empty discovery target")
	}
	args := []string{"-sn", "--stats-every", "5s", "-oX", "-", target}
	return runXML(ctx, runner, "nmap", args, onStderr, false)
}

func runXML(ctx context.Context, runner execx.Runner, name string, args []string, onStderr func(string), wantPorts bool) ([]Host, error) {
	cmd := runner.Command(ctx, name, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	stderrDone := make(chan string, 1)
	go func() {
		var tail strings.Builder
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			if onStderr != nil {
				onStderr(line)
			}
			tail.WriteString(line)
			tail.WriteByte('\n')
			if tail.Len() > 8192 {
				s := tail.String()
				tail.Reset()
				tail.WriteString(s[len(s)-4096:])
			}
		}
		stderrDone <- tail.String()
	}()

	data, readErr := io.ReadAll(stdout)
	waitErr := cmd.Wait()
	tail := <-stderrDone

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if waitErr != nil {
		msg := strings.TrimSpace(tail)
		if msg == "" {
			msg = waitErr.Error()
		}
		return nil, fmt.Errorf("nmap: %s", msg)
	}
	if readErr != nil {
		return nil, readErr
	}

	hosts, err := parseNmapXML(data)
	if err != nil {
		return nil, fmt.Errorf("parse nmap xml: %w", err)
	}
	if wantPorts {
		for i := range hosts {
			if len(hosts[i].Ports) > 0 {
				hosts[i].Up = true
			}
		}
	}
	return hosts, nil
}

type xmlRun struct {
	Hosts []xmlHost `xml:"host"`
}

type xmlHost struct {
	Status    xmlStatus     `xml:"status"`
	Addresses []xmlAddress  `xml:"address"`
	Hostnames []xmlHostname `xml:"hostnames>hostname"`
	Ports     []xmlPort     `xml:"ports>port"`
	OS        xmlOS         `xml:"os"`
}

type xmlStatus struct {
	State string `xml:"state,attr"`
}

type xmlAddress struct {
	Addr   string `xml:"addr,attr"`
	Type   string `xml:"addrtype,attr"`
	Vendor string `xml:"vendor,attr"`
}

type xmlHostname struct {
	Name string `xml:"name,attr"`
}

type xmlPort struct {
	Protocol string       `xml:"protocol,attr"`
	PortID   int          `xml:"portid,attr"`
	State    xmlPortState `xml:"state"`
	Service  xmlService   `xml:"service"`
	Scripts  []xmlScript  `xml:"script"`
}

type xmlPortState struct {
	State string `xml:"state,attr"`
}

type xmlService struct {
	Name     string `xml:"name,attr"`
	Product  string `xml:"product,attr"`
	Version  string `xml:"version,attr"`
	Extra    string `xml:"extrainfo,attr"`
	Tunnel   string `xml:"tunnel,attr"`
	Hostname string `xml:"hostname,attr"`
}

type xmlScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

type xmlOS struct {
	Matches []xmlOSMatch `xml:"osmatch"`
}

type xmlOSMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy int    `xml:"accuracy,attr"`
}

func parseNmapXML(data []byte) ([]Host, error) {
	var run xmlRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, err
	}
	var hosts []Host
	for _, h := range run.Hosts {
		if h.Status.State != "up" {
			continue
		}
		host := Host{Up: true}
		for _, a := range h.Addresses {
			switch a.Type {
			case "ipv4", "ipv6":
				if host.IP == "" {
					host.IP = a.Addr
				}
			case "mac":
				host.MAC = strings.ToLower(a.Addr)
				host.MACVendor = a.Vendor
			}
		}
		if host.IP == "" {
			continue
		}
		for _, hn := range h.Hostnames {
			if hn.Name != "" {
				host.Hostname = hn.Name
				break
			}
		}
		if len(h.OS.Matches) > 0 {
			host.OS = h.OS.Matches[0].Name
		}
		for _, p := range h.Ports {
			if p.State.State != "open" {
				continue
			}
			port := model.Port{
				Number:   p.PortID,
				Protocol: p.Protocol,
				Service:  p.Service.Name,
				Product:  p.Service.Product,
				Version:  p.Service.Version,
				Tunnel:   p.Service.Tunnel,
			}
			for _, s := range p.Scripts {
				if s.ID == "http-title" {
					port.Title = strings.TrimSpace(s.Output)
				}
			}
			host.Ports = append(host.Ports, port)
		}
		hosts = append(hosts, host)
	}
	return hosts, nil
}
