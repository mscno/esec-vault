package server

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestUserCodes(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		c := newUserCode()
		if len(c) != 9 || c[4] != '-' || strings.ContainsAny(c, "ILOU") {
			t.Fatalf("bad code %q", c)
		}
		if normalizeUserCode(c) == "" {
			t.Fatalf("own code %q does not normalize", c)
		}
		seen[c] = true
	}
	if len(seen) < 190 {
		t.Fatal("codes repeat too often")
	}
	for in, want := range map[string]string{
		"k7qm-2xdp":  "K7QM2XDP",
		"K7QM 2XDP":  "K7QM2XDP",
		"OIL0-1234":  "01101234",
		"K7QM-2XD":   "",
		"K7QM-2XDU!": "",
		"<script>":   "",
	} {
		if got := normalizeUserCode(in); got != want {
			t.Errorf("normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{
		"":                       "/account",
		"/account":               "/account",
		"/projects":              "/projects",
		"/device?code=k7qm-2xdp": "/device?code=K7QM-2XDP",
		"/device?code=<x>":       "/device",
		"https://evil.example":   "/account",
		"//evil.example/account": "/account",
		"/\\evil.example":        "/account",
		"/auth/logout":           "/account",
		"javascript:alert(1)":    "/account",
	} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	t.Setenv("ESEC_SERVER_GITHUB_CLIENT_SECRET", "s")
	t.Setenv("ESEC_SERVER_BOOTSTRAP_TOKEN", "0123456789abcdef")
	t.Setenv("ESEC_SERVER_BASE_URL", "https://vault.example.com")
	t.Setenv("ESEC_SERVER_DB_PATH", "/data/db")
	t.Setenv("ESEC_SERVER_GITHUB_CLIENT_ID", "id")
	t.Setenv("ESEC_SERVER_ALLOWED_GITHUB_IDS", "53101343")
	c, err := LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if !c.Allowed(53101343) || c.Allowed(1) || !c.Secure() {
		t.Fatal("config")
	}
	t.Setenv("ESEC_SERVER_ALLOWED_GITHUB_IDS", "mscno")
	if _, err := LoadConfig(""); err == nil {
		t.Fatal("username accepted as an allowlist entry")
	}
	t.Setenv("ESEC_SERVER_ALLOWED_GITHUB_IDS", "53101343")
	t.Setenv("ESEC_SERVER_BASE_URL", "http://vault.example.com")
	if _, err := LoadConfig(""); err == nil {
		t.Fatal("plain http accepted for a public host")
	}
	t.Setenv("ESEC_SERVER_BASE_URL", "http://localhost:8080")
	if _, err := LoadConfig(""); err != nil {
		t.Fatalf("localhost http refused: %v", err)
	}
	t.Setenv("ESEC_SERVER_GITHUB_CLIENT_SECRET", "")
	if _, err := LoadConfig(""); err == nil {
		t.Fatal("missing client secret accepted")
	}
}

// TestDeployConfigLoads keeps the shipped example configuration valid.
func TestDeployConfigLoads(t *testing.T) {
	t.Setenv("ESEC_SERVER_GITHUB_CLIENT_SECRET", "s")
	t.Setenv("ESEC_SERVER_BOOTSTRAP_TOKEN", "0123456789abcdef")
	c, err := LoadConfig("../../deploy/server.toml")
	if err != nil {
		t.Fatal(err)
	}
	if !c.Allowed(53101343) || len(c.Access.AllowedGitHubIDs) != 1 {
		t.Fatalf("allowlist: %v", c.Access.AllowedGitHubIDs)
	}
	if c.ClientIPHeader != "Fly-Client-IP" || c.Sessions.Idle.Duration != 720*time.Hour {
		t.Fatalf("config: %+v", c)
	}
}

func TestLimiterNeverRefusesWhenFull(t *testing.T) {
	l := newLimiter()
	now := time.Now()
	for i := range maxLimiterKeys {
		l.allow(fmt.Sprintf("k%d", i), 5, time.Hour, now.Add(time.Duration(i)))
	}
	if !l.allow("new", 1, time.Hour, now.Add(time.Hour/2)) {
		t.Fatal("a full limiter refused a new key")
	}
	if l.allow("new", 1, time.Hour, now.Add(time.Hour/2)) {
		t.Fatal("a new key was not counted")
	}
	if !l.allow("refunded", 1, time.Hour, now.Add(time.Hour/2)) {
		t.Fatal("first attempt refused")
	}
	l.refund("refunded")
	if !l.allow("refunded", 1, time.Hour, now.Add(time.Hour/2)) {
		t.Fatal("refund did not give the attempt back")
	}
	if len(l.m) > maxLimiterKeys {
		t.Fatal("limiter grew past its bound")
	}
}

func TestPrefixKeys(t *testing.T) {
	if prefixKey("203.0.113.7") != "203.0.113.0/24" || prefixKey("2001:db8:1:2:3::1") != "2001:db8:1::/48" {
		t.Fatal(prefixKey("2001:db8:1:2:3::1"))
	}
	if rateKey("2001:db8:1:2:3::1") != "2001:db8:1:2::/64" || rateKey("203.0.113.7") != "203.0.113.7" {
		t.Fatal(rateKey("2001:db8:1:2:3::1"))
	}
}

func TestEvictionKeepsExhaustedCounters(t *testing.T) {
	l := newLimiter()
	now := time.Now()
	// An attacker exhausts one key, then floods the table with fresh keys.
	for range 3 {
		l.allow("victim-net", 2, time.Hour, now)
	}
	for i := range maxLimiterKeys + 10 {
		l.allow(fmt.Sprintf("flood%d", i), 5, time.Hour, now.Add(time.Second))
	}
	if l.allow("victim-net", 2, time.Hour, now.Add(time.Minute)) {
		t.Fatal("flooding the table reset an exhausted counter")
	}
}

func TestFreshKeysCannotFillTheLimiter(t *testing.T) {
	l := newLimiter()
	now := time.Now()
	// Exhausted keys from an attacker, then a flood of fresh keys: the table
	// must stay bounded instead of growing towards the hard limit.
	for i := range maxLimiterKeys / 2 {
		l.allow(fmt.Sprintf("x%d", i), 1, time.Hour, now)
	}
	for i := range 3 * maxLimiterKeys {
		l.allow(fmt.Sprintf("f%d", i), 5, time.Hour, now.Add(time.Second))
	}
	if len(l.m) > maxLimiterKeys {
		t.Fatalf("limiter grew to %d keys", len(l.m))
	}
	if !l.allow("newcomer", 5, time.Hour, now.Add(2*time.Second)) {
		t.Fatal("a new address was refused")
	}
}
