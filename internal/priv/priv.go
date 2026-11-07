// Package priv manages privilege elevation for arp-scan and nmap.
package priv

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// Mode describes how privileged commands are executed.
type Mode int

const (
	ModeRoot Mode = iota
	ModeSudo
	ModeNone
)

// Exec runs commands, optionally through sudo.
type Exec struct {
	mu       sync.RWMutex
	mode     Mode
	password string
}

// New detects the available elevation method.
func New() *Exec {
	e := &Exec{}
	switch {
	case os.Geteuid() == 0:
		e.mode = ModeRoot
	case hasSudo():
		e.mode = ModeSudo
	default:
		e.mode = ModeNone
	}
	return e
}

func hasSudo() bool {
	_, err := exec.LookPath("sudo")
	return err == nil
}

// Mode returns the current elevation mode.
func (e *Exec) Mode() Mode {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mode
}

// Privileged reports whether commands will run as root.
func (e *Exec) Privileged() bool {
	return e.Mode() != ModeNone
}

// HasSudo reports whether sudo is available at all.
func (e *Exec) HasSudo() bool {
	return e.Mode() == ModeSudo
}

// SetUnprivileged forces direct, unprivileged execution.
func (e *Exec) SetUnprivileged() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mode = ModeNone
	e.password = ""
}

// SetPassword stores the sudo password used by subsequent commands.
func (e *Exec) SetPassword(p string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.password = p
}

// CheckCached reports whether sudo credentials are already cached for this
// session, so no password prompt is required.
func (e *Exec) CheckCached() bool {
	if e.Mode() != ModeSudo {
		return e.Mode() == ModeRoot
	}
	cmd := exec.Command("sudo", "-n", "-v")
	return cmd.Run() == nil
}

// ValidateSudo verifies the password and keeps it for later commands.
func (e *Exec) ValidateSudo(password string) error {
	cmd := exec.Command("sudo", "-S", "-p", "", "-v")
	cmd.Stdin = strings.NewReader(password + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("%s", msg)
	}
	e.mu.Lock()
	e.password = password
	e.mode = ModeSudo
	e.mu.Unlock()
	return nil
}

// Command builds an exec.Cmd according to the elevation mode.
func (e *Exec) Command(ctx context.Context, name string, args ...string) *exec.Cmd {
	e.mu.RLock()
	mode := e.mode
	password := e.password
	e.mu.RUnlock()

	if mode != ModeSudo {
		return exec.CommandContext(ctx, name, args...)
	}

	sudoArgs := make([]string, 0, len(args)+3)
	if password == "" {
		sudoArgs = append(sudoArgs, "-n")
	} else {
		sudoArgs = append(sudoArgs, "-S", "-p", "")
	}
	sudoArgs = append(sudoArgs, name)
	sudoArgs = append(sudoArgs, args...)

	cmd := exec.CommandContext(ctx, "sudo", sudoArgs...)
	if password != "" {
		cmd.Stdin = strings.NewReader(password + "\n")
	}
	return cmd
}
