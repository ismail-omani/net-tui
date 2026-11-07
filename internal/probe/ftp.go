package probe

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"nettui/internal/model"
)

// FTP checks USER/PASS authentication against an FTP server.
func FTP(ctx context.Context, env Env) (*model.Finding, error) {
	addr := net.JoinHostPort(env.IP, strconv.Itoa(env.Port))
	pairs := env.pairs()

	for _, c := range pairs {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		ok, err := ftpTry(ctx, addr, c.Login, c.Password, env.timeout())
		env.attempted(c.Login, c.Password, ok)
		if ok {
			return env.Finding(c.Login, c.Password), nil
		}
		if err != nil && ctx.Err() == nil {
			env.logf("ftp: %v", err)
		}
	}
	return nil, nil
}

func ftpTry(ctx context.Context, addr, login, password string, timeout time.Duration) (bool, error) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	r := bufio.NewReader(conn)
	code, _, err := readFTPReply(r)
	if err != nil {
		return false, err
	}
	if code != 220 {
		return false, fmt.Errorf("unexpected banner %d", code)
	}

	if _, err := fmt.Fprintf(conn, "USER %s\r\n", login); err != nil {
		return false, err
	}
	code, _, err = readFTPReply(r)
	if err != nil {
		return false, err
	}
	switch code {
	case 230:
		fmt.Fprint(conn, "QUIT\r\n")
		return true, nil
	case 331:
	default:
		fmt.Fprint(conn, "QUIT\r\n")
		return false, nil
	}

	if _, err := fmt.Fprintf(conn, "PASS %s\r\n", password); err != nil {
		return false, err
	}
	code, _, err = readFTPReply(r)
	if err != nil {
		return false, err
	}
	fmt.Fprint(conn, "QUIT\r\n")
	return code == 230 || code == 202, nil
}

func readFTPReply(r *bufio.Reader) (int, string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return 0, "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) < 3 {
		return 0, line, fmt.Errorf("short FTP reply")
	}
	code, err := strconv.Atoi(line[:3])
	if err != nil {
		return 0, line, fmt.Errorf("bad FTP reply %q", line)
	}
	if len(line) > 3 && line[3] == '-' {
		prefix := line[:3] + " "
		for {
			next, err := r.ReadString('\n')
			if err != nil {
				return code, line, err
			}
			if strings.HasPrefix(next, prefix) {
				break
			}
		}
	}
	return code, line, nil
}
