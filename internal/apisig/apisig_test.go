package apisig

import (
	"bytes"
	"crypto/ed25519"
	"net/http"
	"testing"
	"time"
)

func TestSignVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Unix(1_800_000_000, 0)
	body := []byte(`{"a":1}`)
	req, _ := http.NewRequest(http.MethodPost, "https://vault.example.com/v1/commit?x=1", bytes.NewReader(body))
	if err := Sign(req, body, "d_abcdefgh", priv, now); err != nil {
		t.Fatal(err)
	}
	s, err := Parse(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(req, body, pub, now); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(req, []byte(`{"a":2}`), pub, now); err == nil {
		t.Fatal("changed body accepted")
	}
	if err := s.Verify(req, body, pub, now.Add(2*time.Minute)); err == nil {
		t.Fatal("old signature accepted")
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if err := s.Verify(req, body, other, now); err == nil {
		t.Fatal("wrong key accepted")
	}
	moved, _ := http.NewRequest(http.MethodPost, "https://vault.example.com/v1/commit?x=2", nil)
	moved.Header = req.Header
	if err := s.Verify(moved, body, pub, now); err == nil {
		t.Fatal("signature reused for another URL")
	}
	req.Header.Set(HeaderNonce, "short")
	if _, err := Parse(req); err == nil {
		t.Fatal("malformed nonce accepted")
	}
}
