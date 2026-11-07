package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"nettui/internal/model"
)

func TestWriter(t *testing.T) {
	dir := t.TempDir()
	w, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	f := model.Finding{Protocol: "http", Port: 80, Vendor: "TP-Link", Login: "admin", Password: "admin"}
	written, err := w.AddFinding("192.168.1.1", f)
	if err != nil || !written {
		t.Fatalf("first write: %v %v", written, err)
	}
	written, err = w.AddFinding("192.168.1.1", f)
	if err != nil || written {
		t.Fatalf("duplicate should not be written: %v %v", written, err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "192.168.1.1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var findings []model.Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Login != "admin" {
		t.Fatalf("findings = %+v", findings)
	}

	w.Attempt("192.168.1.1", "http", 80, "admin", "admin", true, "")
	data, err = os.ReadFile(filepath.Join(dir, "_attempts.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("attempt log is empty")
	}
	var line attemptLine
	if err := json.Unmarshal(data, &line); err != nil {
		t.Fatal(err)
	}
	if line.RunID == "" {
		t.Fatal("attempt line has no run id")
	}

	devices := []model.Device{{IP: "192.168.1.1", Vendor: "TP-Link", Status: "found"}}
	if err := w.WriteDevices(devices); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(filepath.Join(dir, "_devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	var inventory devicesFile
	if err := json.Unmarshal(data, &inventory); err != nil {
		t.Fatal(err)
	}
	if inventory.RunID == "" {
		t.Fatal("device inventory has no run id")
	}
}
