package probe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

const zteLoginPage = `<html><head><title>F680</title><script>
function passwordSHA256() {
  var tokenElement = createHiddenInput("Frm_Loginchecktoken", "TESTTOKEN");
  var randnumElement = createHiddenInput("UserRandomNum", "12345678");
}
</script></head><body>
<input type="text" name="Username" id="Frm_Username">
<input type="password" name="Password" id="Frm_Password">
<input type="submit" id="LoginId" value="Login" onclick="dosubmit()">
</body></html>`

func TestHTTPZTEFormlessLogin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.SetCookie(w, &http.Cookie{Name: "_TESTCOOKIESUPPORT", Value: "1", Path: "/"})
			fmt.Fprint(w, zteLoginPage)
			return
		}
		r.ParseForm()
		random := r.Form.Get("UserRandomNum")
		sum := sha256.Sum256([]byte("s3cret" + random))
		if r.Form.Get("action") == "login" &&
			r.Form.Get("Frm_Loginchecktoken") == "TESTTOKEN" &&
			r.Form.Get("Username") == "admin" &&
			r.Form.Get("Password") == hex.EncodeToString(sum[:]) {
			http.SetCookie(w, &http.Cookie{Name: "SID", Value: "session", Path: "/"})
			fmt.Fprint(w, `<html><body>Welcome to the dashboard. <a href="/logout">logout</a></body></html>`)
			return
		}
		fmt.Fprint(w, `<html><body><input type="password" name="Password" id="Frm_Password">
<script>getObj("errmsg").innerHTML = "Информация пользователя не верна";</script></body></html>`)
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

func TestHTTPZTEFormlessFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.SetCookie(w, &http.Cookie{Name: "_TESTCOOKIESUPPORT", Value: "1", Path: "/"})
			fmt.Fprint(w, zteLoginPage)
			return
		}
		fmt.Fprint(w, `<html><body><input type="password" name="Password" id="Frm_Password">
<script>getObj("errmsg").innerHTML = "Информация пользователя не верна";</script></body></html>`)
	}))
	defer srv.Close()

	finding, err := HTTP(context.Background(), testEnv(t, srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if finding != nil {
		t.Fatalf("unexpected finding: %+v", finding)
	}
}

const ajaxLoginPage = `<html><body>
<form name="gotomain" action="main.html" method="post">
<input type="text" name="username" id="username">
<input type="password" name="password" id="password">
<input type="button" id="login" value="Login">
</form>
<script src="/js/index.js"></script>
<script src="/js/utils/ajax.js"></script>
</body></html>`

const ajaxIndexJS = `function login(){var param={funcNo:1000,username:user,password:pwd};
request(param,function(data){ if(data.flag == "1") { window.location = "main.html"; } });}`

const ajaxRequestJS = `function request(param){$.ajax({url: "/ajax", data: JSON.stringify(param), type: "post"});}`

func ajaxLoginServer(t *testing.T, accept bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, ajaxLoginPage)
		case "/js/index.js":
			fmt.Fprint(w, ajaxIndexJS)
		case "/js/utils/ajax.js":
			fmt.Fprint(w, ajaxRequestJS)
		case "/ajax":
			var payload struct {
				FuncNo   int    `json:"funcNo"`
				Username string `json:"username"`
				Password string `json:"password"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if accept && payload.FuncNo == 1000 && payload.Username == "admin" && payload.Password == "s3cret" {
				fmt.Fprint(w, `{"results":[{"imei":"test"}],"error_info":"none","flag":"1"}`)
				return
			}
			fmt.Fprint(w, `{"error_info":"username or password error!","flag":"0"}`)
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestHTTPAjaxJSONLogin(t *testing.T) {
	srv := ajaxLoginServer(t, true)
	defer srv.Close()

	finding, err := HTTP(context.Background(), testEnv(t, srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if finding == nil || finding.Login != "admin" || finding.Password != "s3cret" {
		t.Fatalf("finding = %+v", finding)
	}
}

func TestHTTPAjaxJSONFailure(t *testing.T) {
	srv := ajaxLoginServer(t, false)
	defer srv.Close()

	finding, err := HTTP(context.Background(), testEnv(t, srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if finding != nil {
		t.Fatalf("unexpected finding: %+v", finding)
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
