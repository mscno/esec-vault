//go:build windows

package runcmd

import (
	"os"
	"os/exec"
)

// setProcAttr is a no-op on Windows.
func setProcAttr(cmd *exec.Cmd) {}

// forwardSignal terminates the child; Windows has no Unix signal forwarding.
func forwardSignal(cmd *exec.Cmd, sig os.Signal) int {
	_ = cmd.Process.Kill()
	return 1
}
