package main

import "testing"

func TestBuildVersionPrefersLinkerInjectedValue(t *testing.T) {
	restore := func(v, c, d string) { version, commit, date = v, c, d }
	t.Cleanup(func() { restore(version, commit, date) })

	restore("1.2.3", "abc1234", "2026-01-01")
	if got := buildVersion(); got != "1.2.3 (abc1234, 2026-01-01)" {
		t.Fatalf("linker version ignored: %q", got)
	}

	// A go install build has no ldflags and must not degrade to "dev"
	// placeholders in the reported commit and date.
	restore("", "", "")
	got := buildVersion()
	if got == "" || got == "dev" {
		t.Fatalf("go install build did not resolve a version: %q", got)
	}
	if got == " (none, unknown)" {
		t.Fatalf("placeholder metadata leaked into version: %q", got)
	}
}

func TestBuildVersionOmitsPlaceholderMetadata(t *testing.T) {
	restore := func(v, c, d string) { version, commit, date = v, c, d }
	t.Cleanup(func() { restore(version, commit, date) })

	restore("0.3.1", "none", "unknown")
	if got := buildVersion(); got != "0.3.1" {
		t.Fatalf("placeholder metadata not omitted: %q", got)
	}

	restore("0.3.1", "abc1234", "unknown")
	if got := buildVersion(); got != "0.3.1 (abc1234)" {
		t.Fatalf("commit-only form wrong: %q", got)
	}
}
