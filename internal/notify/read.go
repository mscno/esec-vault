package notify

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// ReadConsent asks through the daemon's desktop UI, never the requesting stdin.
// The safe default is cancellation. Its result is once, session, or empty.
func ReadConsent(title, text string, timeout time.Duration) (string, error) {
	title, text = clean(title), cleanLong(text)
	ctx, cancel := context.WithTimeout(context.Background(), timeout+time.Second)
	defer cancel()
	secs := itoa(int(timeout / time.Second))
	switch runtime.GOOS {
	case "darwin":
		out, err := exec.CommandContext(ctx, "/usr/bin/osascript", "-e", "on run argv", "-e", `display dialog (item 2 of argv) with title (item 1 of argv) buttons {"Cancel", "Allow once", "Allow session"} default button "Cancel" cancel button "Cancel" giving up after (item 3 of argv as integer) with icon stop`, "-e", "end run", title, text, secs).Output()
		if err != nil || strings.Contains(string(out), "gave up:true") {
			return "", nil
		}
		if strings.Contains(string(out), "button returned:Allow session") {
			return "session", nil
		}
		if strings.Contains(string(out), "button returned:Allow once") {
			return "once", nil
		}
	case "linux":
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return "", ErrNoDialogs
		}
		bin, err := exec.LookPath("zenity")
		if err != nil {
			return "", ErrNoDialogs
		}
		out, err := exec.CommandContext(ctx, bin, "--question", "--no-markup", "--default-cancel", "--title", title, "--text", text, "--ok-label", "Allow once", "--cancel-label", "Cancel", "--extra-button", "Allow session", "--timeout", secs).Output()
		if err == nil {
			return "once", nil
		}
		if strings.TrimSpace(string(out)) == "Allow session" {
			return "session", nil
		}
	default:
		return "", ErrNoDialogs
	}
	return "", nil
}
