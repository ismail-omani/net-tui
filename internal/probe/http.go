package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
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

// failurePhrases also occur inside inline scripts, so they are checked against
// the raw body too. Keep them specific: generic words like "invalid" are
// present in the base64 helper scripts of many routers and would cause false
// negatives on every attempt.
var failurePhrases = []string{
	"информация пользователя не верна",
	"имя пользователя или пароль",
	"неверный пароль",
	"неверное имя пользователя",
	"пользователь заблокирован",
	"превышено количество попыток",
	"密码错误",
	"用户名或密码错误",
	"登录失败",
	"尝试次数过多",
}

var successWords = []string{
	"logout", "sign out", "dashboard", "successfully", "main menu", "system status",
	"device status", "administration", "выход", "выход из системы", "завершить сеанс",
	"главное меню", "состояние системы", "администрирование", "注销", "退出",
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
	kind := "html form"
	if forms[0].jsLogin != "" {
		kind = "JS form (" + forms[0].jsLogin + ")"
	}
	env.notef("http: %s login at %s (%d credentials)", kind, loginURL, len(pairs))
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
	if form.jsLogin == "zte-sha256" {
		random := zteRandom()
		sum := sha256.Sum256([]byte(c.Password + random))
		values.Set("UserRandomNum", random)
		values.Set(form.passField, hex.EncodeToString(sum[:]))
	}

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
	if hasFailure(result.body, text) {
		return false, false, nil
	}
	if result.status >= 500 {
		return false, false, nil
	}
	if form.jsLogin == "zte-sha256" {
		return zteSuccess(result, baseline, jar, cookiesBefore, text), false, nil
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
	// jsLogin marks a login form that is created by JavaScript instead of a
	// regular <form> element. Currently only the ZTE SHA256 scheme is
	// supported, used by ZTE F680 and several related ONT models.
	jsLogin string
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
	if len(out) == 0 {
		if form, ok := findFormlessLogin(body, doc, base); ok {
			out = append(out, form)
		}
	}
	return out
}

// findFormlessLogin handles pages such as the ZTE F680 where the username and
// password inputs are not wrapped in a <form>. The page's JavaScript builds
// the POST body on submit, so a plain HTML form heuristic never sees it.
func findFormlessLogin(body []byte, doc *goquery.Document, base *url.URL) (formInfo, bool) {
	pass := doc.Find("input[type='password']").First()
	if pass.Length() == 0 {
		return formInfo{}, false
	}
	passField, _ := pass.Attr("name")
	if passField == "" {
		passField, _ = pass.Attr("id")
	}
	if passField == "" {
		return formInfo{}, false
	}

	var userField, firstText string
	doc.Find("input").Each(func(_ int, in *goquery.Selection) {
		name, _ := in.Attr("name")
		typ, _ := in.Attr("type")
		id, _ := in.Attr("id")
		typ = strings.ToLower(strings.TrimSpace(typ))
		if name == "" || name == passField {
			return
		}
		switch typ {
		case "text", "email", "tel", "":
			if firstText == "" {
				firstText = name
			}
			if userField == "" && (userFieldRe.MatchString(name) || userFieldRe.MatchString(id)) {
				userField = name
			}
		}
	})
	if userField == "" {
		userField = firstText
	}

	form := formInfo{
		action:    base,
		method:    http.MethodPost,
		userField: userField,
		passField: passField,
		fields:    map[string]string{},
	}
	doc.Find("input[type='hidden']").Each(func(_ int, in *goquery.Selection) {
		name, _ := in.Attr("name")
		value, _ := in.Attr("value")
		if name != "" {
			form.fields[name] = value
		}
	})

	raw := string(body)
	if isZTELogin(raw) {
		form.jsLogin = "zte-sha256"
		form.fields["action"] = "login"
		if _, ok := form.fields["Frm_Logintoken"]; !ok {
			form.fields["Frm_Logintoken"] = "0"
		}
		if token := zteCheckToken(raw); token != "" {
			form.fields["Frm_Loginchecktoken"] = token
		}
	}
	return form, true
}

func isZTELogin(body string) bool {
	return strings.Contains(body, "Frm_Username") &&
		strings.Contains(body, "Frm_Password") &&
		(strings.Contains(body, "UserRandomNum") || strings.Contains(body, "passwordSHA256"))
}

var zteTokenRe = regexp.MustCompile(`Frm_Loginchecktoken["']?\s*,\s*["']([^"']+)["']`)

func zteCheckToken(body string) string {
	if m := zteTokenRe.FindStringSubmatch(body); len(m) > 1 {
		return m[1]
	}
	return ""
}

// zteRandom returns the 8-digit UserRandomNum expected by the ZTE login
// script. The password is sent as SHA256(password + UserRandomNum).
func zteRandom() string {
	n, err := rand.Int(rand.Reader, big.NewInt(90000000))
	if err != nil {
		return strconv.FormatInt(time.Now().UnixNano()%90000000+10000000, 10)
	}
	return strconv.FormatInt(n.Int64()+10000000, 10)
}

func hasFailure(body []byte, text string) bool {
	if containsAny(text, failureWords) {
		return true
	}
	return containsAny(strings.ToLower(string(body)), failurePhrases)
}

// zteSuccess evaluates a ZTE login response. A failure page keeps the login
// inputs and puts the error message only inside an inline script, which is why
// hasFailure checks the raw body as well.
func zteSuccess(result, baseline *httpPage, jar http.CookieJar, cookiesBefore int, text string) bool {
	if result.status >= 300 && result.status < 400 {
		return true
	}
	if result.url.String() != baseline.url.String() &&
		!strings.Contains(strings.ToLower(result.url.Path), "login") {
		return true
	}
	for _, c := range jar.Cookies(result.url) {
		if c.Name != "_TESTCOOKIESUPPORT" {
			return true
		}
	}
	if !bytes.Contains(result.body, []byte("Frm_Password")) &&
		!bytes.Contains(result.body, []byte("Frm_Username")) {
		return true
	}
	baselineText := visibleText(baseline.body)
	return containsAny(text, successWords) && !containsAny(baselineText, successWords)
}

func visibleText(body []byte) string {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return strings.ToLower(string(body))
	}
	doc.Find("script,style,noscript").Remove()
	return strings.ToLower(doc.Text())
}
