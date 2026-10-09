package remote

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setup(t *testing.T) *Config {
	t.Helper()
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	cfg := DefaultConfig()
	cfg.Remotes["local"] = Entry{Type: TypeFile, Dir: filepath.Join(os.Getenv("ESEC_VAULT_HOME"), "blobs"), Prefix: "v1"}
	cfg.Default = "local"
	return cfg
}

func TestPolicyDefaults(t *testing.T) {
	p := Policy{}
	if p.DebounceDuration() != 15*time.Minute {
		t.Fatalf("expected 15m default debounce, got %v", p.DebounceDuration())
	}
	if p.Retention() != 30 {
		t.Fatalf("expected 30 default retention, got %d", p.Retention())
	}
	if p.AutoPush() {
		t.Fatal("empty push policy should not auto-push")
	}
	manual := Policy{Push: PushManual}
	if manual.AutoPush() {
		t.Fatal("manual policy must not auto-push")
	}
	onChange := Policy{Push: PushOnChange}
	if !onChange.AutoPush() {
		t.Fatal("on-change policy should auto-push")
	}
	if (Policy{Interval: "90s"}).IntervalDuration() != 90*time.Second {
		t.Fatal("interval should parse")
	}
	if (Policy{Interval: "nonsense"}).IntervalDuration() != 0 {
		t.Fatal("a bad interval should yield 0, not a panic")
	}
}

func TestEntryValidate(t *testing.T) {
	cases := []struct {
		name    string
		entry   Entry
		wantErr string
	}{
		{"file ok", Entry{Type: TypeFile, Dir: "/tmp/x"}, ""},
		{"file missing dir", Entry{Type: TypeFile}, "dir"},
		{"rclone ok", Entry{Type: TypeRclone, RcloneRemote: "r", Bucket: "b"}, ""},
		{"rclone missing remote", Entry{Type: TypeRclone, Bucket: "b"}, "rclone_remote"},
		{"rclone missing bucket", Entry{Type: TypeRclone, RcloneRemote: "r"}, "bucket"},
		{"restic ok", Entry{Type: TypeRestic, Repository: "s3:bucket"}, ""},
		{"restic missing repo", Entry{Type: TypeRestic}, "repository"},
		{"exec ok", Entry{Type: TypeExec, Command: "backup-adapter"}, ""},
		{"exec missing cmd", Entry{Type: TypeExec}, "command"},
		{"no type", Entry{}, "type"},
		{"unknown type", Entry{Type: "gcs"}, "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.entry.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error mentioning %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q should mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestConfigSaveLoadRoundTrip(t *testing.T) {
	setup(t)
	cfg := DefaultConfig()
	cfg.Remotes["r2"] = Entry{Type: TypeRclone, RcloneRemote: "cf", Bucket: "esec", Prefix: "v1", Description: "Cloudflare R2"}
	cfg.Default = "r2"
	cfg.Policy.Debounce = "30m"
	if err := Save(cfg); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("remote.toml must be 0600, got %o", fi.Mode().Perm())
	}
	back, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if back.Default != "r2" {
		t.Fatalf("default not preserved: %q", back.Default)
	}
	if back.Remotes["r2"].Bucket != "esec" {
		t.Fatal("remote entry not preserved")
	}
	if back.Policy.Debounce != "30m" {
		t.Fatal("policy not preserved")
	}
}

func TestLoadMissingConfigIsEmpty(t *testing.T) {
	setup(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Remotes) != 0 {
		t.Fatal("expected no remotes")
	}
	if cfg.Policy.Debounce != "15m" {
		t.Fatal("expected defaults on a missing config")
	}
}

// The config must never hold credentials; it only names where they live.
func TestCheckNoSecrets(t *testing.T) {
	cases := []struct {
		name    string
		toml    string
		wantErr string
	}{
		{"clean", "[remotes.r2]\ntype = \"rclone\"\nbucket = \"b\"\nrclone_remote = \"r\"\n", ""},
		{"indirection allowed", "[remotes.r2]\nsecret_access_key_env = \"R2_KEY\"\n", ""},
		{"indirection file allowed", "[remotes.r2]\napi_key_file = \"/run/secrets/k\"\n", ""},
		{"inline secret rejected", "[remotes.r2]\nsecret_access_key = \"hunter2\"\n", "secret_access_key"},
		{"inline password rejected", "[remotes.r2]\npassword = \"hunter2\"\n", "password"},
		{"inline token rejected", "[remotes.x]\nauth_token = \"abc\"\n", "auth_token"},
		{"nested inline rejected", "[remotes.x.s3]\naws_secret = \"abc\"\n", "aws_secret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckNoSecrets([]byte(tc.toml))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected rejection of %s", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q should name the field %q", err, tc.wantErr)
			}
		})
	}
}

func TestLoadRejectsInvalidRemote(t *testing.T) {
	setup(t)
	if err := os.WriteFile(ConfigPath(), []byte("[remotes.bad]\ntype = \"rclone\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil {
		t.Fatal("expected Load to reject an incomplete remote")
	}
}

func TestResolve(t *testing.T) {
	cfg := setup(t)
	name, entry, err := cfg.Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	if name != "local" || entry.Type != TypeFile {
		t.Fatalf("resolved %q/%q", name, entry.Type)
	}
	if _, _, err := cfg.Resolve("nope"); err == nil {
		t.Fatal("expected an error for an unknown remote")
	}
	// A remote with no default and no flag is an actionable error.
	empty := DefaultConfig()
	if _, _, err := empty.Resolve(""); err == nil {
		t.Fatal("expected an error when nothing is configured")
	}
}

func TestResolveHonoursEnvOverride(t *testing.T) {
	cfg := setup(t)
	cfg.Remotes["other"] = Entry{Type: TypeFile, Dir: "/tmp/other"}
	t.Setenv("ESEC_VAULT_REMOTE", "other")
	name, _, err := cfg.Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	if name != "other" {
		t.Fatalf("env override ignored, got %q", name)
	}
}

func TestNamesSorted(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Remotes["z"] = Entry{Type: TypeFile, Dir: "/z"}
	cfg.Remotes["a"] = Entry{Type: TypeFile, Dir: "/a"}
	got := cfg.Names()
	if len(got) != 2 || got[0] != "a" || got[1] != "z" {
		t.Fatalf("names not sorted: %v", got)
	}
}

func TestFileBackendRoundTrip(t *testing.T) {
	cfg := setup(t)
	be, err := New(cfg.Remotes["local"])
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	payload := []byte("sealed blob bytes")

	if err := be.Put(ctx, "vaults/a.esec", payload); err != nil {
		t.Fatal(err)
	}
	got, err := be.Get(ctx, "vaults/a.esec")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatal("round trip mismatch")
	}
	keys, err := be.List(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != "vaults/a.esec" {
		t.Fatalf("listing must return logical keys usable by Get: %v", keys)
	}
	if err := be.Delete(ctx, "vaults/a.esec"); err != nil {
		t.Fatal(err)
	}
	if _, err := be.Get(ctx, "vaults/a.esec"); err == nil {
		t.Fatal("expected ErrNotFound after delete")
	}
	// Deleting twice is not an error.
	if err := be.Delete(ctx, "vaults/a.esec"); err != nil {
		t.Fatal(err)
	}
}

func TestFileBackendPermissions(t *testing.T) {
	cfg := setup(t)
	be, _ := New(cfg.Remotes["local"])
	if err := be.Put(context.Background(), "vaults/a.esec", []byte("x")); err != nil {
		t.Fatal(err)
	}
	// The prefix is part of the object key, so it appears in the path.
	p := filepath.Join(cfg.Remotes["local"].Dir, "v1", "vaults", "a.esec")
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("stored object must be 0600, got %o", fi.Mode().Perm())
	}
}

func TestNewRejectsInvalidEntry(t *testing.T) {
	if _, err := New(Entry{Type: TypeFile}); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestGenerationName(t *testing.T) {
	ts := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	name := GenerationName(ts, 42, "deadbeefcafe1234")
	if name != "vaults/20260304T050607.000000000Z-gen00000000000000000042-deadbeefcafe1234.esec" {
		t.Fatalf("unexpected name %q", name)
	}
	got, ok := ParseGeneration(name)
	if !ok || got != 42 {
		t.Fatalf("ParseGeneration(%q) = %d,%v", name, got, ok)
	}
	if _, ok := ParseGeneration("vaults/random.esec"); ok {
		t.Fatal("should not parse a non-generation name")
	}
}
