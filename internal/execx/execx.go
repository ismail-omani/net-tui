// Package execx defines the command runner abstraction shared by the scanner
// packages so they can run either directly or through sudo.
package execx

import (
	"context"
	"os/exec"
)

// Runner builds commands. The privileged implementation prefixes commands
// with sudo when needed.
type Runner interface {
	Command(ctx context.Context, name string, args ...string) *exec.Cmd
}

// Direct is a Runner that executes commands without elevation.
type Direct struct{}

func (Direct) Command(ctx context.Context, name string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, name, args...)
}
