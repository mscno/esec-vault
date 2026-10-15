package server

import (
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
