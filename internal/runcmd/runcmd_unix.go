//go:build !windows

package runcmd

import (
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/term"
)

// setProcAttr mirrors esec's run: give the child its own process group and
// foreground terminal control when attached to a real terminal.
func setProcAttr(cmd *exec.Cmd) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid:    true,
		Ctty:       int(os.Stdin.Fd()),
		Foreground: true,
	}
}

// forwardSignal forwards a signal to the child and returns the conventional
// exit code (128+signal).
func forwardSignal(cmd *exec.Cmd, sig os.Signal) int {
	s, ok := sig.(syscall.Signal)
	if !ok {
		return 1
	}
	_ = syscall.Kill(cmd.Process.Pid, s)
	return 128 + int(s)
}
