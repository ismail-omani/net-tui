package probe

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"nettui/internal/model"
)

// SSH checks password and keyboard-interactive authentication.
func SSH(ctx context.Context, env Env) (*model.Finding, error) {
	addr := net.JoinHostPort(env.IP, strconv.Itoa(env.Port))
	pairs := env.pairs()

	for _, c := range pairs {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		cfg := &ssh.ClientConfig{
			User: c.Login,
			Auth: []ssh.AuthMethod{
				ssh.Password(c.Password),
				ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
					answers := make([]string, len(questions))
					for i := range answers {
						answers[i] = c.Password
					}
					return answers, nil
				}),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         env.timeout(),
		}
		client, err := ssh.Dial("tcp", addr, cfg)
		if err == nil {
			client.Close()
			env.attempted(c.Login, c.Password, true)
			return env.Finding(c.Login, c.Password), nil
		}
		env.attempted(c.Login, c.Password, false)

		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "unable to authenticate") ||
			strings.Contains(msg, "no supported methods") {
			continue
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("ssh: %w", err)
	}
	return nil, nil
}
