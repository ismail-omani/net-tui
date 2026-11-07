package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"nettui/internal/model"
	"nettui/internal/scan"
)

func TestProtocolForPort(t *testing.T) {
	cases := []struct {
		port model.Port
		want string
	}{
		{model.Port{Number: 80, Service: "http"}, "http"},
		{model.Port{Number: 443, Service: "http", Tunnel: "ssl"}, "https"},
		{model.Port{Number: 8443, Service: "http"}, "https"},
		{model.Port{Number: 8080, Service: "http-proxy"}, "http"},
		{model.Port{Number: 22, Service: "ssh"}, "ssh"},
		{model.Port{Number: 2222, Service: ""}, "ssh"},
		{model.Port{Number: 23, Service: "telnet"}, "telnet"},
		{model.Port{Number: 21, Service: "ftp"}, "ftp"},
		{model.Port{Number: 554, Service: "rtsp"}, "rtsp"},
		{model.Port{Number: 5900, Service: "vnc"}, "vnc"},
		{model.Port{Number: 1883, Service: "mqtt"}, "mqtt"},
		{model.Port{Number: 8883, Service: "mqtt"}, "mqtts"},
		{model.Port{Number: 631, Service: "ipp"}, "ipp"},
		{model.Port{Number: 37777, Service: ""}, ""},
	}
	for _, tc := range cases {
		if got := protocolForPort(tc.port); got != tc.want {
			t.Errorf("protocolForPort(%+v) = %q, want %q", tc.port, got, tc.want)
		}
	}
}

func TestAddFindingPersists(t *testing.T) {
	dir := t.TempDir()
	e, err := New(Options{ResultsDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	e.buildDevices([]scan.ArpEntry{{IP: "192.168.1.5", MAC: "aa:bb:cc:dd:ee:ff", Vendor: "TP-Link"}})
	f := model.Finding{Protocol: "telnet", Port: 23, Vendor: "TP-Link", Login: "admin", Password: "admin"}
	e.addFinding("192.168.1.5", f)
	e.addFinding("192.168.1.5", f) // duplicate must be ignored

	data, err := os.ReadFile(filepath.Join(dir, "192.168.1.5.json"))
	if err != nil {
		t.Fatal(err)
	}
	var findings []model.Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %+v", findings)
	}
	if findings[0].Login != "admin" || findings[0].Port != 23 {
		t.Fatalf("finding = %+v", findings[0])
	}
	if e.found != 1 {
		t.Fatalf("found counter = %d", e.found)
	}
}

func TestFinishNormalizesStatuses(t *testing.T) {
	dir := t.TempDir()
	e, err := New(Options{ResultsDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	e.buildDevices([]scan.ArpEntry{
		{IP: "192.168.1.2"},
		{IP: "192.168.1.3"},
		{IP: "192.168.1.4"},
	})

	e.mu.Lock()
	e.devices["192.168.1.2"].Ports = []model.Port{{Number: 80, Protocol: "tcp", Service: "http"}}
	e.devices["192.168.1.2"].Status = "probing"
	e.devices["192.168.1.3"].Ports = []model.Port{{Number: 80, Protocol: "tcp", Service: "http"}}
	e.devices["192.168.1.3"].Findings = []model.Finding{{Protocol: "http", Port: 80, Login: "admin", Password: "admin"}}
	e.devices["192.168.1.3"].Status = "probing"
	e.devices["192.168.1.4"].Status = "discovered"
	e.mu.Unlock()

	e.finish(context.Background())

	statuses := map[string]string{}
	for _, dev := range e.Snapshot() {
		statuses[dev.IP] = dev.Status
	}
	want := map[string]string{
		"192.168.1.2": "clean",
		"192.168.1.3": "found",
		"192.168.1.4": "no ports",
	}
	for ip, status := range want {
		if statuses[ip] != status {
			t.Errorf("%s status = %q, want %q", ip, statuses[ip], status)
		}
	}
}

func TestFinishDryRunStatuses(t *testing.T) {
	dir := t.TempDir()
	e, err := New(Options{ResultsDir: dir, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	e.buildDevices([]scan.ArpEntry{{IP: "192.168.1.2"}})
	e.mu.Lock()
	e.devices["192.168.1.2"].Ports = []model.Port{{Number: 80, Protocol: "tcp", Service: "http"}}
	e.devices["192.168.1.2"].Status = "ready"
	e.mu.Unlock()

	e.finish(context.Background())

	snap := e.Snapshot()
	if len(snap) != 1 || snap[0].Status != "scanned" {
		t.Fatalf("dry-run status = %+v", snap)
	}
}
