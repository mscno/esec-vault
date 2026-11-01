package cli

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// runGit runs a git command in dir and returns stdout. Git's own stderr is
// folded into the error: cmd.Output would otherwise discard it, leaving the
// user with a bare "exit status 128" and no explanation.
func runGit(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
		}
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, msg)
	}
	return string(out), nil
}
