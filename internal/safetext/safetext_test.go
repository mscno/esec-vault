package safetext

import (
	"strings"
	"testing"
)

func TestClean(t *testing.T) {
	for in, want := range map[string]string{
		"laptop":                   "laptop",
		"a\nFingerprint: x\x1b[8m": "a?Fingerprint: x?[8m",
		"\u202eevil":               "?evil",
		"\u009b31m":                "?31m",
		"tab\there":                "tab here",
	} {
		if got := Clean(in); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
	if len([]rune(Clean(strings.Repeat("a", 500)))) != 201 {
		t.Error("length not bounded")
	}
	if IP("203.0.113.7") != "203.0.113.7" || IP("1.2.3.4\nFake") != "unknown" {
		t.Error("IP")
	}
}
