package notify

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Answers to Ask.
const (
	AnswerSign    = "Sign"
	AnswerDismiss = "Dismiss"
	AnswerLater   = "Later"
)

// ErrNoDialogs is returned where this system cannot show a dialog.
var ErrNoDialogs = errors.New("no dialogs on this system")

// Ask shows a dialog with the buttons Sign, Dismiss and Later and returns
// the one chosen; Later when the person closes it or it times out. The text
// goes to the dialog program as an argument, never into a script or markup.
func Ask(title, text string, timeout time.Duration) (string, error) {
	title, text = clean(title), cleanLong(text)
	ctx, cancel := context.WithTimeout(context.Background(), timeout+10*time.Second)
	defer cancel()
	secs := int(timeout / time.Second)
	switch runtime.GOOS {
	case "darwin":
		out, err := exec.CommandContext(ctx, "/usr/bin/osascript",
			"-e", "on run argv",
			"-e", "display dialog (item 2 of argv) with title (item 1 of argv) buttons {\"Dismiss\", \"Later\", \"Sign\"} default button \"Later\" cancel button \"Later\" giving up after (item 3 of argv as integer) with icon caution",
			"-e", "end run",
			title, text, itoa(secs)).Output()
		if err != nil {
			// Later is the cancel button: osascript reports it as an error.
			return AnswerLater, nil
		}
		switch {
		case strings.Contains(string(out), "gave up:true"):
			return AnswerLater, nil
		case strings.Contains(string(out), "button returned:Sign"):
			return AnswerSign, nil
		case strings.Contains(string(out), "button returned:Dismiss"):
			return AnswerDismiss, nil
		}
		return AnswerLater, nil
	case "linux":
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return "", ErrNoDialogs
		}
		path, err := exec.LookPath("zenity")
		if err != nil {
			return "", ErrNoDialogs
		}
		out, err := exec.CommandContext(ctx, path, "--question", "--no-markup", "--default-cancel", "--title", title, "--text", text,
			"--ok-label", AnswerSign, "--cancel-label", AnswerLater, "--extra-button", AnswerDismiss, "--timeout", itoa(secs)).Output()
		if err == nil {
			return AnswerSign, nil
		}
		if strings.TrimSpace(string(out)) == AnswerDismiss {
			return AnswerDismiss, nil
		}
		return AnswerLater, nil
	}
	return "", ErrNoDialogs
}

// cleanLong is clean for a dialog's longer text, keeping line breaks.
func cleanLong(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' {
			return r
		}
		if r < 0x20 || (r >= 0x7f && r < 0xa0) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) || r == 0x200e || r == 0x200f || r == 0x061c {
			return '?'
		}
		return r
	}, s)
	if len(s) > 8000 {
		s = s[:8000]
	}
	return s
}

func itoa(n int) string {
	if n <= 0 {
		return "60"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
