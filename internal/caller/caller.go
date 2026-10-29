// Package caller describes which programs asked for something: a process
// and its parents, such as "claude ▸ zsh ▸ esec-vault". A dialog shows it,
// so a person can tell their own request from an agent's.
package caller

import (
	"context"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// maxDepth bounds the walk up the process tree.
const maxDepth = 12

// Chain returns the command names of pid and its ancestors, nearest first,
// stopping before init/launchd. It is best effort: names come from ps, and
// a process can rename itself, so it informs a person and decides nothing.
func Chain(pid int) []string {
	var out []string
	for i := 0; i < maxDepth && pid > 1; i++ {
		ppid, name, ok := parent(pid)
		if !ok {
			break
		}
		out = append(out, name)
		pid = ppid
	}
	return out
}

// Describe joins a chain from the outermost program in: "zsh ▸ claude ▸ esec".
func Describe(chain []string) string {
	if len(chain) == 0 {
		return "an unknown program"
	}
	parts := make([]string, 0, len(chain))
	for i := len(chain) - 1; i >= 0; i-- {
		parts = append(parts, chain[i])
	}
	return strings.Join(parts, " ▸ ")
}

// Args returns the command line of pid ("esec vault decrypt prod"), or ""
// when it cannot be read. Like Chain it informs a person and decides
// nothing: a process can rewrite its own arguments.
func Args(pid int) string {
	if pid <= 0 {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/bin/ps", "-o", "args=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func parent(pid int) (ppid int, name string, ok bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/bin/ps", "-o", "ppid=", "-o", "comm=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return 0, "", false
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) < 2 {
		return 0, "", false
	}
	ppid, err = strconv.Atoi(fields[0])
	if err != nil {
		return 0, "", false
	}
	name = filepath.Base(strings.Join(fields[1:], " "))
	if len(name) > 40 {
		name = name[:40]
	}
	return ppid, name, true
}
