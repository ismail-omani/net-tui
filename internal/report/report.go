// Package report persists findings, device inventory and the attempt audit
// log.
package report

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"nettui/internal/model"
)

// Writer writes results into a directory.
type Writer struct {
	dir   string
	runID string

	mu           sync.Mutex
	attemptsPath string
	attemptsFile *os.File
}

type devicesFile struct {
	GeneratedAt time.Time      `json:"generated_at"`
	RunID       string         `json:"run"`
	Devices     []model.Device `json:"devices"`
}

type attemptLine struct {
	Time     time.Time `json:"time"`
	RunID    string    `json:"run"`
	IP       string    `json:"ip"`
	Protocol string    `json:"protocol"`
	Port     int       `json:"port"`
	Login    string    `json:"login"`
	Password string    `json:"password"`
	OK       bool      `json:"ok"`
	Note     string    `json:"note,omitempty"`
}

// New creates the output directory.
func New(dir string) (*Writer, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Writer{
		dir:          dir,
		runID:        time.Now().Format("20060102-150405"),
		attemptsPath: filepath.Join(dir, "_attempts.jsonl"),
	}, nil
}

// Dir returns the results directory.
func (w *Writer) Dir() string { return w.dir }

// AddFinding appends a finding to results/<ip>.json. It returns false when
// the finding is a duplicate.
func (w *Writer) AddFinding(ip string, f model.Finding) (bool, error) {
	if net.ParseIP(ip) == nil {
		return false, fmt.Errorf("invalid IP %q", ip)
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	path := filepath.Join(w.dir, ip+".json")
	var findings []model.Finding
	if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
		if err := json.Unmarshal(data, &findings); err != nil {
			findings = nil
		}
	}
	for _, existing := range findings {
		if existing.Protocol == f.Protocol && existing.Port == f.Port &&
			existing.Login == f.Login && existing.Password == f.Password {
			return false, nil
		}
	}
	findings = append(findings, f)
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return false, err
	}
	return true, writeAtomic(path, append(data, '\n'))
}

// Attempt appends one credential attempt to the audit log.
func (w *Writer) Attempt(ip, protocol string, port int, login, password string, ok bool, note string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.attemptsFile == nil {
		f, err := os.OpenFile(w.attemptsPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return
		}
		w.attemptsFile = f
	}
	line := attemptLine{
		Time:     time.Now(),
		RunID:    w.runID,
		IP:       ip,
		Protocol: protocol,
		Port:     port,
		Login:    login,
		Password: password,
		OK:       ok,
		Note:     note,
	}
	data, err := json.Marshal(line)
	if err != nil {
		return
	}
	w.attemptsFile.Write(append(data, '\n'))
}

// WriteDevices writes the device inventory.
func (w *Writer) WriteDevices(devices []model.Device) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	data, err := json.MarshalIndent(devicesFile{GeneratedAt: time.Now(), RunID: w.runID, Devices: devices}, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(w.dir, "_devices.json"), append(data, '\n'))
}

// Close flushes and closes the audit log.
func (w *Writer) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.attemptsFile != nil {
		w.attemptsFile.Sync()
		w.attemptsFile.Close()
		w.attemptsFile = nil
	}
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
