package runcmd

import (
	"bytes"
	"io"
	"sort"
	"strings"
	"sync"
)

// minMasked is the shortest value masked: shorter ones ("1", "true") would
// blot out ordinary output and reveal little.
const minMasked = 4

// Masker writes through to w with every secret value replaced by ***. It
// works line by line, so a value is caught even when a write splits it;
// Flush writes what is left of the last line.
type Masker struct {
	mu  sync.Mutex
	w   io.Writer
	r   *strings.Replacer
	buf bytes.Buffer
}

// NewMasker masks values in what is written to w. A value spanning lines
// (a PEM key) is masked line by line.
func NewMasker(w io.Writer, values []string) *Masker {
	seen := map[string]bool{}
	var parts []string
	for _, v := range values {
		for _, line := range strings.Split(v, "\n") {
			line = strings.TrimRight(line, "\r")
			if len(line) >= minMasked && !seen[line] {
				seen[line] = true
				parts = append(parts, line)
			}
		}
	}
	// Longest first, so a value containing another is masked whole.
	sort.Slice(parts, func(i, j int) bool { return len(parts[i]) > len(parts[j]) })
	pairs := make([]string, 0, 2*len(parts))
	for _, p := range parts {
		pairs = append(pairs, p, "***")
	}
	return &Masker{w: w, r: strings.NewReplacer(pairs...)}
}

// Write implements io.Writer.
func (m *Masker) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.buf.Write(p)
	for {
		i := bytes.IndexByte(m.buf.Bytes(), '\n')
		if i < 0 {
			break
		}
		line := m.buf.Next(i + 1)
		if _, err := io.WriteString(m.w, m.r.Replace(string(line))); err != nil {
			return len(p), err
		}
	}
	return len(p), nil
}

// Flush writes the unfinished last line.
func (m *Masker) Flush() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.buf.Len() == 0 {
		return nil
	}
	_, err := io.WriteString(m.w, m.r.Replace(m.buf.String()))
	m.buf.Reset()
	return err
}
