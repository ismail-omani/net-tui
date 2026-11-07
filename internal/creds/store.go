// Package creds downloads, parses and indexes public default-credential
// lists, and maps them to vendors detected on the local network.
package creds

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	seclistsFile     = "seclists-default-passwords.csv"
	cheatsheetFile   = "defaultcreds-cheat-sheet.csv"
	routersploitFile = "routersploit-defaults.txt"
)

var sources = []struct {
	name string
	url  string
}{
	{seclistsFile, "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/default-passwords.csv"},
	{cheatsheetFile, "https://raw.githubusercontent.com/ihebski/DefaultCreds-cheat-sheet/main/DefaultCreds-Cheat-Sheet.csv"},
	{routersploitFile, "https://raw.githubusercontent.com/threat9/routersploit/master/routersploit/resources/wordlists/defaults.txt"},
}

// Cred is a login/password pair.
type Cred struct {
	Login    string
	Password string
}

// Store is the in-memory credential database.
type Store struct {
	vendor  map[string][]Cred
	generic []Cred
}

// curated contains high-value generic pairs tried before the long lists.
var curated = []Cred{
	{"admin", "admin"},
	{"admin", "password"},
	{"admin", "1234"},
	{"admin", "12345"},
	{"admin", "123456"},
	{"admin", ""},
	{"root", "root"},
	{"root", "admin"},
	{"root", ""},
	{"root", "password"},
	{"root", "1234"},
	{"root", "vizxv"},
	{"admin", "vizxv"},
	{"admin", "system"},
	{"admin", "manager"},
	{"admin", "changeme"},
	{"admin", "default"},
	{"admin", "888888"},
	{"admin", "admin123"},
	{"admin", "password123"},
	{"admin", "1234qwer"},
	{"admin", "adminadmin"},
	{"ubnt", "ubnt"},
	{"cisco", "cisco"},
	{"guest", "guest"},
	{"user", "user"},
	{"support", "support"},
	{"service", "service"},
	{"supervisor", "supervisor"},
	{"pi", "raspberry"},
}

// Fetch downloads the credential lists. Existing files are kept unless force
// is true.
func Fetch(dir string, force bool) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	client := &http.Client{Timeout: 90 * time.Second}
	for _, src := range sources {
		path := filepath.Join(dir, src.name)
		if !force {
			if st, err := os.Stat(path); err == nil && st.Size() > 0 {
				continue
			}
		}
		req, err := http.NewRequest(http.MethodGet, src.url, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("download %s: %w", src.name, err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return fmt.Errorf("download %s: HTTP %s", src.name, resp.Status)
		}
		tmp := path + ".tmp"
		f, err := os.Create(tmp)
		if err != nil {
			resp.Body.Close()
			return err
		}
		_, copyErr := io.Copy(f, resp.Body)
		resp.Body.Close()
		closeErr := f.Close()
		if copyErr != nil {
			os.Remove(tmp)
			return fmt.Errorf("download %s: %w", src.name, copyErr)
		}
		if closeErr != nil {
			os.Remove(tmp)
			return closeErr
		}
		if err := os.Rename(tmp, path); err != nil {
			os.Remove(tmp)
			return err
		}
	}
	return nil
}

// Load parses all available credential files from dir. Missing files produce
// warnings instead of hard failures so the tool still works offline with
// whatever is cached.
func Load(dir string) (*Store, []string, error) {
	s := &Store{vendor: map[string][]Cred{}}
	var warnings []string

	found := 0
	if _, err := os.Stat(filepath.Join(dir, seclistsFile)); err == nil {
		found++
		if err := s.loadCSV(filepath.Join(dir, seclistsFile)); err != nil {
			warnings = append(warnings, "seclists: "+err.Error())
		}
	}
	if _, err := os.Stat(filepath.Join(dir, cheatsheetFile)); err == nil {
		found++
		if err := s.loadCSV(filepath.Join(dir, cheatsheetFile)); err != nil {
			warnings = append(warnings, "cheatsheet: "+err.Error())
		}
	}
	if _, err := os.Stat(filepath.Join(dir, routersploitFile)); err == nil {
		found++
		if err := s.loadRoutersploit(filepath.Join(dir, routersploitFile)); err != nil {
			warnings = append(warnings, "routersploit: "+err.Error())
		}
	}
	if found == 0 {
		return nil, warnings, fmt.Errorf("no credential files in %s (run with --fetch-creds)", dir)
	}

	s.generic = dedupe(append(append([]Cred{}, curated...), s.generic...))
	for key, list := range s.vendor {
		s.vendor[key] = dedupe(list)
	}
	return s, warnings, nil
}

func (s *Store) loadCSV(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if len(rec) < 3 {
			continue
		}
		vendor := cleanVal(rec[0])
		login := cleanVal(rec[1])
		pass := cleanVal(rec[2])
		if strings.EqualFold(vendor, "vendor") || strings.EqualFold(vendor, "productvendor") ||
			strings.EqualFold(login, "username") {
			continue
		}
		s.add(vendor, login, pass)
	}
	return nil
}

func (s *Store) loadRoutersploit(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		s.add("", parts[0], parts[1])
	}
	return nil
}

func (s *Store) add(vendor, login, pass string) {
	c := Cred{Login: login, Password: pass}
	if c.Login == "" && c.Password == "" {
		return
	}
	brands := DetectVendors(vendor)
	if len(brands) == 0 {
		s.generic = append(s.generic, c)
		return
	}
	for _, b := range brands {
		s.vendor[b] = append(s.vendor[b], c)
	}
}

func cleanVal(s string) string {
	s = strings.TrimSpace(s)
	low := strings.ToLower(s)
	if low == "<blank>" || low == "<blank> " || low == "(blank)" || low == "blank" {
		return ""
	}
	return s
}

func dedupe(in []Cred) []Cred {
	seen := make(map[string]struct{}, len(in))
	out := make([]Cred, 0, len(in))
	for _, c := range in {
		key := c.Login + "\x00" + c.Password
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, c)
	}
	return out
}

// PairsFor builds an ordered credential list: vendor-specific credentials
// first, then generic ones, capped at limit.
func (s *Store) PairsFor(texts []string, limit int) []Cred {
	if limit <= 0 {
		limit = 20
	}
	brands := DetectVendors(texts...)

	var out []Cred
	seen := map[string]struct{}{}
	add := func(c Cred) {
		if len(out) >= limit {
			return
		}
		key := c.Login + "\x00" + c.Password
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, c)
	}

	vendorLimit := limit * 2 / 3
	count := 0
	for _, b := range brands {
		for _, c := range s.vendor[b] {
			if count >= vendorLimit || len(out) >= limit {
				break
			}
			before := len(out)
			add(c)
			if len(out) > before {
				count++
			}
		}
	}
	for _, c := range s.generic {
		if len(out) >= limit {
			break
		}
		add(c)
	}
	return out
}

// Communities returns SNMP community strings to try.
func (s *Store) Communities(texts []string) []string {
	base := []string{"public", "private"}
	brands := DetectVendors(texts...)
	for _, b := range brands {
		switch b {
		case "hikvision", "dahua", "axis", "vivotek":
			base = append(base, "public@")
		case "mikrotik":
			base = append(base, "public")
		}
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(base))
	for _, c := range base {
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}

// VNCPasswords returns passwords to try against VNC servers.
func (s *Store) VNCPasswords(texts []string, limit int) []string {
	common := []string{
		"password", "admin", "1234", "12345", "123456", "12345678",
		"root", "vnc", "letmein", "qwerty", "0000", "1111", "111111",
		"654321", "P@ssw0rd", "raspberry",
	}
	for _, c := range s.PairsFor(texts, 40) {
		if c.Password != "" {
			common = append(common, c.Password)
		}
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, limit)
	for _, p := range common {
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// VendorLabel picks the best human-readable vendor name for a device. Strings
// like "(Unknown: locally administered)" are treated as missing, so detection
// can fall back to nmap product and HTTP title data.
func VendorLabel(existing string, texts ...string) string {
	existing = strings.TrimSpace(existing)
	unknown := isUnknownVendor(existing)

	all := append([]string{}, texts...)
	if existing != "" && !unknown {
		all = append(all, existing)
	}
	if brands := DetectVendors(all...); len(brands) > 0 {
		return DisplayVendor(brands[0])
	}
	if unknown {
		return ""
	}
	return existing
}

func isUnknownVendor(s string) bool {
	low := strings.ToLower(strings.TrimSpace(s))
	low = strings.Trim(low, "() ")
	if low == "" || low == "unknown" {
		return true
	}
	return strings.Contains(low, "unknown") || strings.Contains(low, "locally administered")
}

// Summary returns a human-readable description of the loaded database.
func (s *Store) Summary() string {
	total := len(s.generic)
	for _, list := range s.vendor {
		total += len(list)
	}
	return fmt.Sprintf("%d credentials across %d vendors", total, len(s.vendor))
}
