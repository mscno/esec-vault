// Package notify shows desktop notifications for security-relevant account
// events. It is best effort: the daemon also logs every event.
package notify

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Send shows a notification. Title and body are passed as process
// arguments, never interpolated into a script, so a device name cannot
// inject commands.
func Send(title, body string) {
	title, body = clean(title), clean(body)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	switch runtime.GOOS {
	case "darwin":
		_ = exec.CommandContext(ctx, "/usr/bin/osascript",
			"-e", "on run argv",
			"-e", "display notification (item 2 of argv) with title (item 1 of argv)",
			"-e", "end run",
			title, body).Run()
	case "linux":
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return
		}
		if path, err := exec.LookPath("notify-send"); err == nil {
			_ = exec.CommandContext(ctx, path, "--app-name=esec-vault", "--", title, body).Run()
		}
	}
}

// clean removes control characters and bounds the length.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
