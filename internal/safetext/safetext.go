// Package safetext makes untrusted strings safe to print on a terminal.
// Text from the server (names, addresses, error messages) could otherwise
// carry escape sequences that hide or forge lines, such as a fake
// fingerprint next to an approval prompt.
package safetext

import (
	"net"
	"strings"
	"unicode"
)

// Clean replaces control characters, C1 controls and bidirectional
// overrides with '?', and limits the length.
func Clean(s string) string { return CleanN(s, 200) }

// CleanN is Clean with a limit of limit runes.
func CleanN(s string, limit int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= limit {
			b.WriteString("…")
			break
		}
		switch {
		case r == '\t':
			b.WriteRune(' ')
		case unicode.IsControl(r), r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069, r == 0x200e, r == 0x200f, r == 0x061c:
			b.WriteRune('?')
		default:
			b.WriteRune(r)
		}
		n++
	}
	return b.String()
}

// IP returns s if it is an IP address, otherwise "unknown".
func IP(s string) string {
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return "unknown"
}
