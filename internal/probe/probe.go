// Package probe implements default-credential checks for the protocols
// supported by net-dis.
package probe

import (
	"context"
	"time"

	"nettui/internal/creds"
	"nettui/internal/model"
)

// Env contains everything a probe needs for a single device/port.
type Env struct {
	IP          string
	Port        int
	Protocol    string
	Vendor      string
	VendorTexts []string
	Store       *creds.Store
	Timeout     time.Duration
	MaxCreds    int
	Delay       time.Duration
	Log         func(format string, args ...any)
	Note        func(format string, args ...any)
	Attempt     func(login, password string, ok bool)
}

// Finding builds a result with the environment's protocol/port/vendor.
func (e Env) Finding(login, password string) *model.Finding {
	return &model.Finding{
		Protocol: e.Protocol,
		Port:     e.Port,
		Vendor:   e.Vendor,
		Login:    login,
		Password: password,
	}
}

func (e Env) timeout() time.Duration {
	if e.Timeout <= 0 {
		return 6 * time.Second
	}
	return e.Timeout
}

func (e Env) logf(format string, args ...any) {
	if e.Log != nil {
		e.Log(format, args...)
	}
}

// notef reports an important probe decision at info level (visible without
// --verbose), for example that a page has no login form.
func (e Env) notef(format string, args ...any) {
	if e.Note != nil {
		e.Note(format, args...)
	}
}

func (e Env) attempted(login, password string, ok bool) {
	if e.Attempt != nil {
		e.Attempt(login, password, ok)
	}
	if e.Delay > 0 {
		time.Sleep(e.Delay)
	}
}

func (e Env) pairs() []creds.Cred {
	return e.Store.PairsFor(e.VendorTexts, e.MaxCreds)
}

// Func is a protocol probe.
type Func func(ctx context.Context, env Env) (*model.Finding, error)

// Registry maps protocol names to probes.
var Registry = map[string]Func{
	"http":   HTTP,
	"https":  HTTP,
	"ssh":    SSH,
	"telnet": Telnet,
	"ftp":    FTP,
	"rtsp":   RTSP,
	"snmp":   SNMP,
	"vnc":    VNC,
	"mqtt":   MQTT,
	"mqtts":  MQTT,
	"ipp":    IPP,
}
