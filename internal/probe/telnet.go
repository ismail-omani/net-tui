package probe

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	"nettui/internal/creds"
	"nettui/internal/model"
)

// Telnet tries to log in through a telnet prompt, handling IAC negotiation.
func Telnet(ctx context.Context, env Env) (*model.Finding, error) {
	addr := net.JoinHostPort(env.IP, strconv.Itoa(env.Port))
	pairs := env.pairs()

	for _, c := range pairs {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		ok, uncertain, err := telnetTry(ctx, addr, c, env.timeout())
		env.attempted(c.Login, c.Password, ok)
		if ok {
			return env.Finding(c.Login, c.Password), nil
		}
		if uncertain {
			env.logf("telnet: uncertain login result for %q:%q", c.Login, c.Password)
		}
		if err != nil && ctx.Err() == nil {
			env.logf("telnet: %v", err)
		}
	}
	return nil, nil
}

func telnetTry(ctx context.Context, addr string, c creds.Cred, timeout time.Duration) (bool, bool, error) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, false, err
	}
	defer conn.Close()

	filter := &iacFilter{}
	send := func(s string) {
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		conn.Write([]byte(s))
	}
	read := func(max time.Duration) string {
		var b strings.Builder
		start := time.Now()
		for time.Since(start) < max {
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			buf := make([]byte, 4096)
			n, err := conn.Read(buf)
			if n > 0 {
				clean, replies := filter.Feed(buf[:n])
				b.Write(clean)
				if len(replies) > 0 {
					conn.SetWriteDeadline(time.Now().Add(time.Second))
					conn.Write(replies)
				}
			}
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					if b.Len() > 0 {
						return b.String()
					}
					continue
				}
				return b.String()
			}
		}
		return b.String()
	}

	banner := read(3500)
	low := strings.ToLower(banner)
	sentLogin := false
	sentPassword := false

	switch {
	case strings.Contains(low, "login") || strings.Contains(low, "username") || strings.Contains(low, "user name"):
		send(c.Login + "\r\n")
		sentLogin = true
		next := read(2500)
		lowNext := strings.ToLower(next)
		if strings.Contains(lowNext, "password") {
			send(c.Password + "\r\n")
			sentPassword = true
		}
		banner += next
	case strings.Contains(low, "password"):
		send(c.Password + "\r\n")
		sentPassword = true
	default:
		send("\r\n")
		banner += read(1500)
	}

	if sentLogin && !sentPassword {
		next := read(3000)
		lowNext := strings.ToLower(next)
		if strings.Contains(lowNext, "password") {
			send(c.Password + "\r\n")
			sentPassword = true
			banner += next
		} else {
			banner += next
		}
	}
	if !sentPassword && !strings.Contains(strings.ToLower(banner), "password") {
		return false, false, nil
	}

	after := read(3500)
	all := strings.ToLower(banner + after)

	failWords := []string{
		"incorrect", "invalid", "failed", "denied", "bad password",
		"login incorrect", "authentication failed", "wrong password",
	}
	if containsAny(all, failWords) {
		return false, false, nil
	}
	if strings.Count(all, "password:") > 1 || (strings.Contains(all, "login:") && strings.Contains(all, "password:")) {
		return false, false, nil
	}

	if containsAny(all, []string{"busybox", "routeros", "welcome", "successfully", "logged in", "shell"}) {
		return true, false, nil
	}
	lines := strings.Split(strings.TrimSpace(after), "\n")
	if len(lines) > 0 {
		last := strings.TrimSpace(lines[len(lines)-1])
		if last != "" && strings.ContainsAny(last, "#$>%") && !strings.Contains(strings.ToLower(last), "password") {
			return true, false, nil
		}
	}
	if after == "" {
		return false, true, nil
	}
	return false, true, nil
}

// iacFilter strips telnet IAC sequences and produces polite negotiation
// replies (WILL -> DONT, DO -> WONT).
type iacFilter struct {
	pending []byte
}

func (f *iacFilter) Feed(chunk []byte) ([]byte, []byte) {
	data := make([]byte, 0, len(f.pending)+len(chunk))
	data = append(data, f.pending...)
	data = append(data, chunk...)
	f.pending = nil

	var out, replies []byte
	for i := 0; i < len(data); i++ {
		if data[i] != 255 {
			out = append(out, data[i])
			continue
		}
		if i+1 >= len(data) {
			f.pending = append(f.pending, data[i:]...)
			break
		}
		cmd := data[i+1]
		switch cmd {
		case 255: // escaped 0xFF
			out = append(out, 255)
			i++
		case 251, 252, 253, 254: // WILL, WONT, DO, DONT
			if i+2 >= len(data) {
				f.pending = append(f.pending, data[i:]...)
				i = len(data)
				break
			}
			opt := data[i+2]
			i += 2
			if cmd == 251 {
				replies = append(replies, 255, 252, opt)
			} else if cmd == 253 {
				replies = append(replies, 255, 254, opt)
			}
		case 250: // subnegotiation
			j := i + 2
			done := false
			for ; j+1 < len(data); j++ {
				if data[j] == 255 && data[j+1] == 240 {
					j++
					done = true
					break
				}
			}
			if !done {
				f.pending = append(f.pending, data[i:]...)
				i = len(data)
				break
			}
			i = j
		default:
			i++
		}
	}
	return out, replies
}
