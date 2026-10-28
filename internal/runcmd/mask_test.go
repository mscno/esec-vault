package runcmd

import (
	"bytes"
	"testing"
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
