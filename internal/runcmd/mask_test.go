package runcmd

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMasker(t *testing.T) {
	var out bytes.Buffer
	m := NewMasker(&out, []string{"s3cr3t-token", "on", "-----BEGIN KEY-----\nABCDEFGH\n-----END KEY-----"})
	for _, chunk := range []string{"token=s3cr", "3t-token ok\nflag on\n", "key ABCDEFGH", " end"} {
		if _, err := m.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Flush(); err != nil {
		t.Fatal(err)
	}
	want := "token=*** ok\nflag on\nkey *** end"
	if out.String() != want {
		t.Fatalf("got %q, want %q", out.String(), want)
	}
}

// syncBuf is a bytes.Buffer safe to read while the masker's timer writes.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestMaskerShowsPromptsButHoldsAValueStart(t *testing.T) {
	var out syncBuf
	m := NewMasker(&out, []string{"s3cr3t-token"})
	if _, err := m.Write([]byte("Password: s3cr")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for out.String() == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := out.String(); got != "Password: " {
		t.Fatalf("idle flush wrote %q, want the prompt without the start of the value", got)
	}
	if _, err := m.Write([]byte("3t-token done")); err != nil {
		t.Fatal(err)
	}
	if err := m.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "Password: *** done" {
		t.Fatalf("got %q", got)
	}
}

func TestMaskerCapsALongLine(t *testing.T) {
	var out syncBuf
	m := NewMasker(&out, []string{"s3cr3t-token"})
	long := strings.Repeat("x", maxBuffered) + "s3cr3t-token" + strings.Repeat("y", 10) + "s3cr"
	if _, err := m.Write([]byte(long)); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	buffered := m.buf.Len()
	m.mu.Unlock()
	if buffered != len("s3cr") {
		t.Fatalf("kept %d bytes back, want only the start of a value", buffered)
	}
	if strings.Contains(out.String(), "s3cr3t-token") {
		t.Fatal("a value got through")
	}
}
