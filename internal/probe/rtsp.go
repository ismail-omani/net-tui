package probe

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"nettui/internal/model"
)

// RTSP checks Basic/Digest authentication on cameras and NVRs.
func RTSP(ctx context.Context, env Env) (*model.Finding, error) {
	addr := net.JoinHostPort(env.IP, strconv.Itoa(env.Port))
	uri := fmt.Sprintf("rtsp://%s:%d/", env.IP, env.Port)

	status, challenge, err := rtspRequest(ctx, addr, uri, "DESCRIBE", "", env.timeout())
	if err != nil {
		return nil, err
	}
	if status != 401 {
		return nil, nil
	}
	scheme, params := parseChallenge(challenge)
	if scheme == "" {
		return nil, nil
	}

	pairs := env.pairs()
	for _, c := range pairs {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		auth := ""
		switch scheme {
		case "basic":
			auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(c.Login+":"+c.Password))
		case "digest":
			header, ok := digestAuthorization(params, "DESCRIBE", uri, c.Login, c.Password)
			if !ok {
				continue
			}
			auth = header
		default:
			return nil, nil
		}
		code, _, err := rtspRequest(ctx, addr, uri, "DESCRIBE", auth, env.timeout())
		ok := code == 200
		env.attempted(c.Login, c.Password, ok)
		if ok {
			return env.Finding(c.Login, c.Password), nil
		}
		if err != nil && ctx.Err() == nil {
			env.logf("rtsp: %v", err)
		}
	}
	return nil, nil
}

func rtspRequest(ctx context.Context, addr, uri, method, auth string, timeout time.Duration) (int, string, error) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	var b strings.Builder
	fmt.Fprintf(&b, "%s %s RTSP/1.0\r\n", method, uri)
	b.WriteString("CSeq: 1\r\n")
	b.WriteString("User-Agent: net-tui\r\n")
	b.WriteString("Accept: application/sdp\r\n")
	if auth != "" {
		fmt.Fprintf(&b, "Authorization: %s\r\n", auth)
	}
	b.WriteString("\r\n")
	if _, err := conn.Write([]byte(b.String())); err != nil {
		return 0, "", err
	}

	br := bufio.NewReader(conn)
	tp := textproto.NewReader(br)
	statusLine, err := tp.ReadLine()
	if err != nil {
		return 0, "", err
	}
	fields := strings.Fields(statusLine)
	code := 0
	if len(fields) >= 2 {
		code, _ = strconv.Atoi(fields[1])
	}
	headers, err := tp.ReadMIMEHeader()
	if err != nil && len(headers) == 0 {
		return code, "", err
	}
	return code, headers.Get("WWW-Authenticate"), nil
}
