package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"

	"nettui/internal/creds"
	"nettui/internal/model"
)

const httpUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"

var failureWords = []string{
	"invalid", "incorrect", "failed", "failure", "wrong password", "wrong username",
	"access denied", "authentication failed", "login error", "bad password",
}

var successWords = []string{
	"logout", "sign out", "dashboard", "successfully", "main menu", "system status",
	"device status", "administration",
}

type httpPage struct {
	status int
	body   []byte
	url    *url.URL
	header http.Header
}

func newHTTPClient(timeout time.Duration, jar http.CookieJar) *http.Client {
	// Keep-alives are disabled deliberately: after the TUI exits, idle
	// connections to embedded web servers can make net/http log
	// "Unsolicited response received on idle HTTP channel" to stderr.
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DialContext:         (&net.Dialer{Timeout: timeout}).DialContext,
		TLSHandshakeTimeout: timeout,
		DisableKeepAlives:   true,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 6 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func fetchPage(ctx context.Context, client *http.Client, rawURL string) (*httpPage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", httpUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return &httpPage{status: resp.StatusCode, body: body, url: resp.Request.URL, header: resp.Header}, nil
}

func isTLSError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "tls:") ||
		strings.Contains(msg, "x509:") ||
		strings.Contains(msg, "https client") ||
		strings.Contains(msg, "server gave http response")
}

// HTTP tries Basic/Digest authentication first (when challenged), then a
// generic HTML form login heuristic.
func HTTP(ctx context.Context, env Env) (*model.Finding, error) {
	scheme := "http"
	if env.Protocol == "https" {
		scheme = "https"
	}
	base := fmt.Sprintf("%s://%s:%d/", scheme, env.IP, env.Port)
	initial, err := fetchPage(ctx, newHTTPClient(env.timeout(), nil), base)
	if err != nil {
		if scheme == "https" && isTLSError(err) {
			scheme = "http"
			env.Protocol = "http"
			base = fmt.Sprintf("http://%s:%d/", env.IP, env.Port)
			initial, err = fetchPage(ctx, newHTTPClient(env.timeout(), nil), base)
		}
		if err != nil {
			return nil, err
		}
	}

	pairs := env.pairs()
	if len(pairs) == 0 {
		return nil, nil
	}

	if initial.status == http.StatusUnauthorized {
		challenges := initial.header.Values("WWW-Authenticate")
		if len(challenges) == 0 {
			if c := initial.header.Get("WWW-Authenticate"); c != "" {
				challenges = []string{c}
			}
		}
		if len(challenges) == 0 {
			env.notef("http: %s:%d returned 401 without WWW-Authenticate", env.IP, env.Port)
			return nil, nil
		}
		for _, c := range pairs {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			ok, err := tryHTTPAuth(ctx, base, challenges, c, env.timeout())
			env.attempted(c.Login, c.Password, ok)
			if ok {
				return env.Finding(c.Login, c.Password), nil
			}
			if err != nil {
				env.logf("http auth error: %v", err)
			}
		}
		env.notef("http: basic/digest rejected %d credentials on %s:%d", len(pairs), env.IP, env.Port)
		return nil, nil
	}

	loginURL, forms := discoverLoginPage(ctx, base, initial, env.timeout())
	if len(forms) == 0 {
		env.notef("http: no login form at %s:%d (status %d), skipped", env.IP, env.Port, initial.status)
		return nil, nil
	}
	env.notef("http: form login at %s (%d credentials)", loginURL, len(pairs))
	for _, c := range pairs {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		ok, uncertain, err := tryFormLogin(ctx, loginURL, c, env.timeout())
		env.attempted(c.Login, c.Password, ok)
		if ok {
			return env.Finding(c.Login, c.Password), nil
		}
		if uncertain {
			env.logf("http: uncertain form result for %q:%q on %s", c.Login, c.Password, loginURL)
		}
		if err != nil && ctx.Err() == nil {
			env.logf("http form error: %v", err)
		}
	}
	env.notef("http: form rejected %d credentials at %s", len(pairs), loginURL)
	return nil, nil
}

func tryHTTPAuth(ctx context.Context, base string, challenges []string, c creds.Cred, timeout time.Duration) (bool, error) {
	for _, challenge := range challenges {
		scheme, params := parseChallenge(challenge)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base, nil)
		if err != nil {
			return false, err
		}
		req.Header.Set("User-Agent", httpUserAgent)
		switch scheme {
		case "basic":
			req.SetBasicAuth(c.Login, c.Password)
		case "digest":
			u, err := url.Parse(base)
			if err != nil {
				continue
			}
			header, ok := digestAuthorization(params, http.MethodGet, u.RequestURI(), c.Login, c.Password)
			if !ok {
				continue
			}
			req.Header.Set("Authorization", header)
		default:
			continue
		}
		client := newHTTPClient(timeout, nil)
		resp, err := client.Do(req)
		if err != nil {
			return false, err
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 400 &&
			resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
			return true, nil
		}
	}
	return false, nil
}

func discoverLoginPage(ctx context.Context, base string, initial *httpPage, timeout time.Duration) (string, []formInfo) {
	if forms := findForms(initial.body, initial.url); len(forms) > 0 {
		return initial.url.String(), forms
	}
	if timeout > 3*time.Second {
		timeout = 3 * time.Second
	}
	paths := []string{"login", "login.html", "cgi-bin/luci"}
	for _, p := range paths {
		if ctx.Err() != nil {
			return "", nil
		}
		u, err := url.Parse(p)
		if err != nil {
			continue
		}
		target := initial.url.ResolveReference(u).String()
		page, err := fetchPage(ctx, newHTTPClient(timeout, nil), target)
		if err != nil || page.status >= 400 {
			continue
		}
		if forms := findForms(page.body, page.url); len(forms) > 0 {
			return page.url.String(), forms
		}
	}
	return "", nil
}

func tryFormLogin(ctx context.Context, loginURL string, c creds.Cred, timeout time.Duration) (bool, bool, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return false, false, err
	}
	client := newHTTPClient(timeout, jar)
	baseline, err := fetchPage(ctx, client, loginURL)
	if err != nil {
		return false, false, err
	}
	forms := findForms(baseline.body, baseline.url)
	if len(forms) == 0 {
		return false, false, nil
	}
	form := forms[0]

	cookiesBefore := len(jar.Cookies(baseline.url))
	baselineText := visibleText(baseline.body)
	baselineHasForm := true

	values := url.Values{}
	for k, v := range form.fields {
		values.Set(k, v)
	}
	if form.userField != "" {
		values.Set(form.userField, c.Login)
	}
	values.Set(form.passField, c.Password)

	var req *http.Request
	if form.method == http.MethodPost {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, form.action.String(), strings.NewReader(values.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	} else {
		u := *form.action
		u.RawQuery = values.Encode()
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	}
	if err != nil {
		return false, false, err
	}
	req.Header.Set("User-Agent", httpUserAgent)
	req.Header.Set("Referer", baseline.url.String())

	resp, err := client.Do(req)
	if err != nil {
		return false, false, err
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if readErr != nil {
		return false, false, readErr
	}
	result := &httpPage{status: resp.StatusCode, body: body, url: resp.Request.URL, header: resp.Header}

	text := visibleText(result.body)
	if containsAny(text, failureWords) {
		return false, false, nil
	}
	if result.status >= 500 {
		return false, false, nil
	}

	signals := 0
	if len(jar.Cookies(result.url)) > cookiesBefore {
		signals++
	}
	if result.url.String() != form.action.String() && result.url.String() != baseline.url.String() {
		signals++
	}
	if baselineHasForm && len(findForms(result.body, result.url)) == 0 {
		signals++
	}
	for _, w := range successWords {
		if strings.Contains(text, w) && !strings.Contains(baselineText, w) {
			signals++
			break
		}
	}

	switch {
	case signals >= 2:
		return true, false, nil
	case signals == 1:
		return false, true, nil
	default:
		return false, false, nil
	}
}

func containsAny(text string, words []string) bool {
	for _, w := range words {
		if strings.Contains(text, w) {
			return true
		}
	}
	return false
}

type formInfo struct {
	action    *url.URL
	method    string
	userField string
	passField string
	fields    map[string]string
}

var userFieldRe = regexp.MustCompile(`(?i)(user|login|account|email|usr|name)`)

func findForms(body []byte, base *url.URL) []formInfo {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return nil
	}
	var out []formInfo
	doc.Find("form").EachWithBreak(func(_ int, s *goquery.Selection) bool {
		if len(out) >= 3 {
			return false
		}
		form := formInfo{method: http.MethodGet, fields: map[string]string{}}
		action, _ := s.Attr("action")
		ref, err := url.Parse(strings.TrimSpace(action))
		if err != nil {
			ref = &url.URL{}
		}
		form.action = base.ResolveReference(ref)
		if m, ok := s.Attr("method"); ok && strings.EqualFold(strings.TrimSpace(m), "post") {
			form.method = http.MethodPost
		}

		var firstText string
		s.Find("input").Each(func(_ int, in *goquery.Selection) {
			name, _ := in.Attr("name")
			typ, _ := in.Attr("type")
			id, _ := in.Attr("id")
			typ = strings.ToLower(strings.TrimSpace(typ))
			if name == "" {
				return
			}
			switch typ {
			case "password":
				if form.passField == "" {
					form.passField = name
				}
			case "text", "email", "tel", "":
				if firstText == "" {
					firstText = name
				}
				if userFieldRe.MatchString(name) || userFieldRe.MatchString(id) {
					if form.userField == "" {
						form.userField = name
					}
				}
			}
		})
		if form.passField == "" {
			return true
		}
		if form.userField == "" {
			form.userField = firstText
		}

		s.Find("input").Each(func(_ int, in *goquery.Selection) {
			name, _ := in.Attr("name")
			typ, _ := in.Attr("type")
			val, _ := in.Attr("value")
			typ = strings.ToLower(strings.TrimSpace(typ))
			if name == "" {
				return
			}
			switch typ {
			case "submit", "button", "image", "reset", "file":
				return
			case "checkbox", "radio":
				if _, checked := in.Attr("checked"); checked {
					form.fields[name] = val
				}
				return
			case "password", "text", "email", "tel", "":
				// credentials are filled in later
				return
			}
			form.fields[name] = val
		})
		out = append(out, form)
		return true
	})
	return out
}

func visibleText(body []byte) string {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return strings.ToLower(string(body))
	}
	doc.Find("script,style,noscript").Remove()
	return strings.ToLower(doc.Text())
}
