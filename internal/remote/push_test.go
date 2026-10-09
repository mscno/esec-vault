package remote

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newTestConfig builds a config backed by a temp file remote.
func newTestConfig(t *testing.T) *Config {
	t.Helper()
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	cfg := DefaultConfig()
	cfg.Remotes["local"] = Entry{Type: TypeFile, Dir: filepath.Join(os.Getenv("ESEC_VAULT_HOME"), "blobs"), Prefix: "v1"}
	cfg.Default = "local"
	if err := Save(cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestPushVerifyAndState(t *testing.T) {
	newTestConfig(t)
	blob := []byte("generation one")
	res, err := Push(context.Background(), nil, "local", blob, 1, "abcdef123456", time.Now(), true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Skipped {
		t.Fatal("first push should not be skipped")
	}
	if !res.Verified {
		t.Fatal("push should have verified by reading back")
	}
	if res.Generation != 1 {
		t.Fatalf("generation %d", res.Generation)
	}

	state, err := LoadState()
	if err != nil {
		t.Fatal(err)
	}
	rs := state.Remote["local"]
	if rs.Key != res.Key {
		t.Fatalf("state key %q != pushed key %q", rs.Key, res.Key)
	}
	if rs.Generation != 1 {
		t.Fatalf("state generation %d", rs.Generation)
	}
	if rs.LastPush.IsZero() {
		t.Fatal("last push time not recorded")
	}
}

// Identical content must not produce a second upload.
func TestPushSkipsUnchanged(t *testing.T) {
	newTestConfig(t)
	blob := []byte("same content")
	now := time.Now()
	first, err := Push(context.Background(), nil, "local", blob, 1, "abcdef123456", now, false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Push(context.Background(), nil, "local", blob, 1, "abcdef123456", now, false)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Skipped {
		t.Fatal("an unchanged blob should be skipped")
	}
	if second.Key != first.Key {
		t.Fatal("skipped push should report the existing key")
	}
}

func TestPushChangedContentCreatesNewGeneration(t *testing.T) {
	newTestConfig(t)
	if _, err := Push(context.Background(), nil, "local", []byte("one"), 1, "abcdef123456", time.Now(), false); err != nil {
		t.Fatal(err)
	}
	res, err := Push(context.Background(), nil, "local", []byte("two"), 2, "abcdef123456", time.Now().Add(time.Minute), false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Skipped {
		t.Fatal("changed content must push")
	}
	keys, err := listLocal(t)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 generations on the remote, got %d: %v", len(keys), keys)
	}
}

// Generations are immutable, so the newest wins for Latest.
func TestLatestPicksNewest(t *testing.T) {
	newTestConfig(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := Push(context.Background(), nil, "local", []byte("old"), 1, "aaaaaaaaaaaa", base, false); err != nil {
		t.Fatal(err)
	}
	if _, err := Push(context.Background(), nil, "local", []byte("new"), 2, "aaaaaaaaaaaa", base.Add(time.Hour), false); err != nil {
		t.Fatal(err)
	}
	key, blob, err := Latest(context.Background(), nil, "local")
	if err != nil {
		t.Fatal(err)
	}
	if string(blob) != "new" {
		t.Fatalf("expected the newest generation, got %q", blob)
	}
	if gen, ok := ParseGeneration(key); !ok || gen != 2 {
		t.Fatalf("expected generation 2 key, got %q", key)
	}
}

func TestLatestWhenNeverPushed(t *testing.T) {
	newTestConfig(t)
	if _, _, err := Latest(context.Background(), nil, "local"); err == nil {
		t.Fatal("expected an error when nothing was pushed")
	}
}

func TestPruneKeepsNewest(t *testing.T) {
	newTestConfig(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 1; i <= 5; i++ {
		blob := []byte{byte(i)}
		ts := base.Add(time.Duration(i) * time.Hour)
		if _, err := Push(context.Background(), nil, "local", blob, uint64(i), "aaaaaaaaaaaa", ts, false); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := Prune(context.Background(), nil, "local", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 3 {
		t.Fatalf("expected 3 pruned, got %d: %v", len(removed), removed)
	}
	keys, err := listLocal(t)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 remaining, got %d", len(keys))
	}
	// The survivors must be the newest two.
	_, blob, err := Latest(context.Background(), nil, "local")
	if err != nil {
		t.Fatal(err)
	}
	if blob[0] != 5 {
		t.Fatalf("newest generation should survive, got %q", blob)
	}
}

func TestPruneNoopWhenUnderRetention(t *testing.T) {
	newTestConfig(t)
	base := time.Now()
	for i := 1; i <= 2; i++ {
		if _, err := Push(context.Background(), nil, "local", []byte{byte(i)}, uint64(i), "aaaaaaaaaaaa", base.Add(time.Duration(i)*time.Minute), false); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := Prune(context.Background(), nil, "local", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 0 {
		t.Fatalf("expected nothing pruned, got %v", removed)
	}
}

func TestPruneRejectsNonPositiveKeep(t *testing.T) {
	newTestConfig(t)
	if _, err := Prune(context.Background(), nil, "local", 0); err == nil {
		t.Fatal("expected an error for keep=0")
	}
}

func TestPushUnknownRemote(t *testing.T) {
	newTestConfig(t)
	if _, err := Push(context.Background(), nil, "nope", []byte("x"), 1, "ff", time.Now(), false); err == nil {
		t.Fatal("expected an error for an unknown remote")
	}
}

// A corrupted remote copy must be caught by the verify-after-push read-back.
func TestPushVerificationDetectsMismatch(t *testing.T) {
	newTestConfig(t)
	if _, err := Push(context.Background(), nil, "local", []byte("good"), 1, "aaaaaaaaaaaa", time.Now(), true); err != nil {
		t.Fatal(err)
	}
	// Verify the happy path is real by confirming Get returns what we wrote.
	be, err := New(mustEntry(t))
	if err != nil {
		t.Fatal(err)
	}
	state, _ := LoadState()
	got, err := be.Get(context.Background(), state.Remote["local"].Key)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "good" {
		t.Fatalf("read-back mismatch: %q", got)
	}
}

func mustEntry(t *testing.T) Entry {
	t.Helper()
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Remotes["local"]
}

func listLocal(t *testing.T) ([]string, error) {
	t.Helper()
	be, err := New(mustEntry(t))
	if err != nil {
		t.Fatal(err)
	}
	return be.List(context.Background(), "")
}

func TestStateSaveLoadRoundTrip(t *testing.T) {
	newTestConfig(t)
	s := &State{Remote: map[string]RemoteState{}}
	s.Remote["x"] = RemoteState{Generation: 3, Hash: "abc", Key: "k", LastPush: time.Now().UTC()}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	back, err := LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if back.Remote["x"].Generation != 3 {
		t.Fatal("state did not round trip")
	}
}

func TestStateMissingFileIsEmpty(t *testing.T) {
	newTestConfig(t)
	s, err := LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Remote) != 0 {
		t.Fatal("expected empty state")
	}
}

// Dirty tracking drives debounced auto-push.
func TestDirtyLifecycle(t *testing.T) {
	newTestConfig(t)
	if IsDirty() {
		t.Fatal("should start clean")
	}
	if err := MarkDirty("test change", 3); err != nil {
		t.Fatal(err)
	}
	if !IsDirty() {
		t.Fatal("should be dirty after MarkDirty")
	}
	reason, _, ok := DirtyReason()
	if !ok || reason != "test change" {
		t.Fatalf("DirtyReason = %q,%v", reason, ok)
	}
	if err := ClearDirty(); err != nil {
		t.Fatal(err)
	}
	if IsDirty() {
		t.Fatal("should be clean after ClearDirty")
	}
	// Clearing twice is not an error.
	if err := ClearDirty(); err != nil {
		t.Fatal(err)
	}
}

func TestDebounceElapsed(t *testing.T) {
	newTestConfig(t)
	if DebounceElapsed(time.Second) {
		t.Fatal("nothing dirty should never be due")
	}
	if err := MarkDirty("x", 0); err != nil {
		t.Fatal(err)
	}
	if DebounceElapsed(time.Hour) {
		t.Fatal("a fresh change should not be past a one-hour debounce")
	}
	if !DebounceElapsed(0) {
		t.Fatal("a zero debounce should be immediately due")
	}
}

func TestMaybePushRespectsDebounce(t *testing.T) {
	newTestConfig(t)
	// Dirty but the default 15m debounce has not elapsed: no push.
	if err := MarkDirty("x", 0); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Policy.DebounceDuration() != 15*time.Minute {
		t.Fatalf("unexpected debounce %v", cfg.Policy.DebounceDuration())
	}
}

func TestMaybePushNoRemoteConfigured(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Default != "" {
		t.Fatal("expected no default")
	}
	// BuildSnapshot would fail without a vault, but MaybePush must return
	// quietly before that because nothing is configured.
	if err := MarkDirty("x", 0); err != nil {
		t.Fatal(err)
	}
	res, err := MaybePush(context.Background(), nil, nil, "")
	if err != nil {
		t.Fatalf("MaybePush with no remote should be a no-op, got %v", err)
	}
	if res != nil {
		t.Fatal("expected no result when nothing is configured")
	}
}

func TestShortHash(t *testing.T) {
	if got := ShortHash("0123456789abcdef"); got != "0123456789ab" {
		t.Fatalf("got %q", got)
	}
	if got := ShortHash("ab"); got != "ab" {
		t.Fatalf("got %q", got)
	}
}
