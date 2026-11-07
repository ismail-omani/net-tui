package probe

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"nettui/internal/creds"
)

func testEnv(t *testing.T, serverURL string) Env {
	t.Helper()
	u, err := url.Parse(serverURL)
	if err != nil {
		t.Fatal(err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)

	dir := t.TempDir()
	csv := "Vendor,Username,Password\nHikvision,admin,s3cret\n"
	if err := os.WriteFile(filepath.Join(dir, "seclists-default-passwords.csv"), []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}
	store, _, err := creds.Load(dir)
	if err != nil {
		t.Fatal(err)
	}

	return Env{
		IP:          host,
		Port:        port,
		Protocol:    "http",
		Vendor:      "Hikvision",
		VendorTexts: []string{"Hikvision"},
		Store:       store,
		Timeout:     3 * time.Second,
		MaxCreds:    5,
		Attempt:     func(string, string, bool) {},
	}
}

func TestHTTPBasicAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "admin" || pass != "s3cret" {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	finding, err := HTTP(context.Background(), testEnv(t, srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if finding == nil || finding.Login != "admin" || finding.Password != "s3cret" {
		t.Fatalf("finding = %+v", finding)
	}
}

func TestHTTPNoFormReportsNote(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			fmt.Fprint(w, `<html><body><h1>Appliance</h1><p>JavaScript UI</p></body></html>`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	env := testEnv(t, srv.URL)
	var notes []string
	env.Note = func(format string, args ...any) {
		notes = append(notes, fmt.Sprintf(format, args...))
	}

	finding, err := HTTP(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if finding != nil {
		t.Fatalf("unexpected finding: %+v", finding)
	}
	if joined := strings.Join(notes, "\n"); !strings.Contains(joined, "no login form") {
		t.Fatalf("missing skip note, got %q", joined)
	}
}

func TestHTTPFormLogin(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			if c, err := r.Cookie("auth"); err == nil && c.Value == "1" {
				http.Redirect(w, r, "/dashboard", http.StatusFound)
				return
			}
			fmt.Fprint(w, `<html><body><form method="post" action="/login">
				<input type="text" name="username">
				<input type="password" name="password">
				<input type="submit" value="Login">
			</form></body></html>`)
		case "/login":
			r.ParseForm()
			if r.Form.Get("username") == "admin" && r.Form.Get("password") == "s3cret" {
				http.SetCookie(w, &http.Cookie{Name: "auth", Value: "1", Path: "/"})
				http.Redirect(w, r, "/dashboard", http.StatusFound)
				return
			}
			fmt.Fprint(w, `<html><body>Invalid credentials<form method="post" action="/login">
				<input type="text" name="username">
				<input type="password" name="password">
			</form></body></html>`)
		case "/dashboard":
			fmt.Fprint(w, `<html><body>Welcome to the dashboard. <a href="/logout">logout</a></body></html>`)
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	finding, err := HTTP(context.Background(), testEnv(t, srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if finding == nil || finding.Login != "admin" || finding.Password != "s3cret" {
		t.Fatalf("finding = %+v", finding)
	}
}
