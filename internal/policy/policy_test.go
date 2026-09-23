package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMissingFileDeniesAll(t *testing.T) {
	p, err := Load(filepath.Join(t.TempDir(), "nope.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Decide("org/repo", "dev", 501) != Deny {
		t.Fatal("missing policy must deny everything")
	}
}

func TestRuleMatching(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.toml")
	content := `
default = "deny"

[[rule]]
project = "*"
env = ["dev", "dev-agent"]
action = "allow"

[[rule]]
project = "org/*"
env = ["staging"]
action = "ask"

[[rule]]
project = "org/repo"
env = ["prod"]
uid = 501
action = "ask"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		project, env string
		uid          uint32
		want         Action
	}{
		{"org/repo", "dev", 501, Allow},
		{"any/thing", "dev", 1, Allow},
		{"org/repo", "staging", 501, Ask},    // org/* matches
		{"org/repo", "prod", 501, Ask},       // uid matches
		{"org/repo", "prod", 502, Deny},      // uid mismatch, falls to default
		{"org/repo", "prod", 0, Deny},        // unspecified uid never matches uid rules
		{"other/repo", "staging", 501, Deny}, // prefix mismatch
		{"org/repo", "prod-secret", 501, Deny},
	}
	for _, c := range cases {
		if got := p.Decide(c.project, c.env, c.uid); got != c.want {
			t.Errorf("Decide(%s, %s, %d) = %s, want %s", c.project, c.env, c.uid, got, c.want)
		}
	}
}

func TestInvalidPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(path, []byte("[[rule]]\naction=\"nope\"\nproject=\"*\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for invalid action")
	}
	if err := os.WriteFile(path, []byte("[[rule]]\naction=\"allow\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for missing project")
	}
}
