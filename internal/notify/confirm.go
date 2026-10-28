package notify

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Confirm shows a dialog with the buttons Deny and allow, Deny being the
// default, and reports whether allow was chosen. Closing it or letting it
// time out denies. Like Ask, the text reaches the dialog program as an
// argument, never inside a script.
func Confirm(title, text, allow string, timeout time.Duration) (bool, error) {
	title, text, allow = clean(title), cleanLong(text), clean(allow)
	ctx, cancel := context.WithTimeout(context.Background(), timeout+10*time.Second)
	defer cancel()
	secs := itoa(int(timeout / time.Second))
	switch runtime.GOOS {
	case "darwin":
		out, err := exec.CommandContext(ctx, "/usr/bin/osascript",
			"-e", "on run argv",
			"-e", "display dialog (item 2 of argv) with title (item 1 of argv) buttons {\"Deny\", (item 3 of argv)} default button \"Deny\" cancel button \"Deny\" giving up after (item 4 of argv as integer) with icon stop",
			"-e", "end run",
			title, text, allow, secs).Output()
		if err != nil {
			return false, nil
		}
		return !strings.Contains(string(out), "gave up:true") && strings.Contains(string(out), "button returned:"+allow), nil
	case "linux":
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return false, ErrNoDialogs
		}
		path, err := exec.LookPath("zenity")
		if err != nil {
			return false, ErrNoDialogs
		}
		err = exec.CommandContext(ctx, path, "--question", "--no-markup", "--default-cancel", "--title", title, "--text", text,
			"--ok-label", allow, "--cancel-label", "Deny", "--timeout", secs).Run()
		return err == nil, nil
	}
	return false, ErrNoDialogs
}

// Secret asks for a secret, such as a security key's PIN, in a dialog that
// hides what is typed. ok is false when the person cancels.
func Secret(title, prompt string, timeout time.Duration) (value string, ok bool, err error) {
	title, prompt = clean(title), cleanLong(prompt)
	ctx, cancel := context.WithTimeout(context.Background(), timeout+10*time.Second)
	defer cancel()
	secs := itoa(int(timeout / time.Second))
	switch runtime.GOOS {
	case "darwin":
		out, err := exec.CommandContext(ctx, "/usr/bin/osascript",
			"-e", "on run argv",
			"-e", "set r to display dialog (item 2 of argv) with title (item 1 of argv) default answer \"\" with hidden answer buttons {\"Cancel\", \"OK\"} default button \"OK\" cancel button \"Cancel\" giving up after (item 3 of argv as integer)",
			"-e", "if gave up of r then return \"\"",
			"-e", "return \"ok:\" & text returned of r",
			"-e", "end run",
			title, prompt, secs).Output()
		if err != nil {
			return "", false, nil
		}
		v, found := strings.CutPrefix(strings.TrimRight(string(out), "\n"), "ok:")
		return v, found, nil
	case "linux":
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return "", false, ErrNoDialogs
		}
		path, err := exec.LookPath("zenity")
		if err != nil {
			return "", false, ErrNoDialogs
		}
		out, err := exec.CommandContext(ctx, path, "--password", "--title", title, "--timeout", secs).Output()
		if err != nil {
			return "", false, nil
		}
		return strings.TrimRight(string(out), "\n"), true, nil
	}
	return "", false, ErrNoDialogs
}
