package runcmd

import (
	"bytes"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// minMasked is the shortest value masked: shorter ones ("1", "true") would
// blot out ordinary output and reveal little.
const minMasked = 4

// maxBuffered caps the unfinished line kept back: past it, all but what
// could still be the start of a value is written out.
const maxBuffered = 64 << 10

// idleFlush is how long an unfinished line (a prompt, a progress bar) waits
// before it is written out, but for what could still be the start of a
// value.
var idleFlush = 100 * time.Millisecond

// Masker writes through to w with every secret value replaced by ***. It
// works line by line, so a value is caught even when a write splits it;
// Flush writes what is left of the last line.
//
// Masking keeps values out of logs and transcripts by accident. It is not
// a boundary: the command it wraps has the values and can print them in
// any form.
type Masker struct {
	mu    sync.Mutex
	w     io.Writer
	r     *strings.Replacer
	parts []string
	buf   bytes.Buffer
	timer *time.Timer
	err   error
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
	return &Masker{w: w, r: strings.NewReplacer(pairs...), parts: parts}
}

// Write implements io.Writer.
func (m *Masker) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.timer != nil {
		m.timer.Stop()
	}
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
	if m.buf.Len() > maxBuffered {
		if err := m.writePartial(); err != nil {
			return len(p), err
		}
	}
	if m.buf.Len() > 0 {
		m.timer = time.AfterFunc(idleFlush, m.idle)
	}
	return len(p), m.err
}

// Flush writes the unfinished last line.
func (m *Masker) Flush() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.timer != nil {
		m.timer.Stop()
	}
	if m.buf.Len() == 0 {
		return m.err
	}
	_, err := io.WriteString(m.w, m.r.Replace(m.buf.String()))
	m.buf.Reset()
	return err
}

func (m *Masker) idle() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err == nil {
		m.err = m.writePartial()
	}
}

// writePartial writes the unfinished line but for its longest tail that
// could still become a value, which waits for more output.
func (m *Masker) writePartial() error {
	b := m.buf.Bytes()
	keep := m.heldBack(b)
	out := m.r.Replace(string(b[:len(b)-keep]))
	m.buf.Next(len(b) - keep)
	_, err := io.WriteString(m.w, out)
	return err
}

// heldBack is the length of the longest tail of b that is the start of a
// value.
func (m *Masker) heldBack(b []byte) int {
	longest := 0
	for _, p := range m.parts {
		longest = max(longest, len(p))
	}
	for k := min(len(b), longest); k > 0; k-- {
		tail := string(b[len(b)-k:])
		for _, p := range m.parts {
			if strings.HasPrefix(p, tail) {
				return k
			}
		}
	}
	return 0
}
