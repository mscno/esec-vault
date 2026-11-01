package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mscno/esec-vault/internal/daemon"
	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/securitykey"
	"github.com/mscno/esec-vault/internal/workspace"
)

// A GUI refresh must never probe the smart-card plugin or ykman, including
// when the daemon's cache is missing, stale or unreadable.
func TestGUICachedSecurityKeysNeverOpenCard(t *testing.T) {
	home := t.TempDir()
	t.Setenv("ESEC_VAULT_HOME", home)
	previous := securitykey.Run
	t.Cleanup(func() { securitykey.Run = previous })
	securitykey.Run = func(context.Context, string, ...string) ([]byte, error) {
		t.Error("cached listing opened a hardware tool")
		return nil, errors.New("unexpected hardware access")
	}
	detected := securitykey.Detected{Serial: "15584441", Slot: "1", Recipient: "test-recipient", Name: "test key"}
	for _, age := range []time.Duration{0, 3 * time.Minute} {
		cache := daemon.SeenKeys{Checked: time.Now().UTC().Add(-age), PluggedIn: []daemon.SeenKey{{Detected: detected}}, Unprovisioned: []string{"blank"}}
		data, err := json.Marshal(cache)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(daemon.SeenKeysFile(), data, 0600); err != nil {
			t.Fatal(err)
		}
		var got securityKeysView
		output := stdoutOfRun(t, func() error {
			return (&SecurityKeysListCmd{JSON: true, Cached: true}).Run(&cliCtx{Keyring: keyring.NewMemory()})
		})
		if err := json.Unmarshal([]byte(output), &got); err != nil {
			t.Fatal(err)
		}
		if !got.Cached || got.Checked.IsZero() {
			t.Fatalf("cache metadata missing: %+v", got)
		}
		if age == 0 && (len(got.Unregistered) != 1 || len(got.Unprovisioned) != 1) {
			t.Fatalf("fresh cache ignored: %+v", got)
		}
		if age != 0 && (len(got.Unregistered) != 0 || got.Detect == "") {
			t.Fatalf("stale detection presented as current: %+v", got)
		}
	}
	if err := os.Remove(daemon.SeenKeysFile()); err != nil {
		t.Fatal(err)
	}
	stdoutOfRun(t, func() error {
		return (&SecurityKeysListCmd{JSON: true, Cached: true}).Run(&cliCtx{Keyring: keyring.NewMemory()})
	})
}

func TestGUIProjectMetadataReportsConfigAndValidationErrors(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv("ESEC_KEYRING_DIR", "")
	checkout := t.TempDir()
	path := filepath.Join(checkout, "esec.toml")
	config := "project = 'acme/mono/api'\n[files]\nformat = 'etoml'\nname = 'secrets/{env}.etoml'\n[env.'api.prod']\nguard = 'session'\nfuture = 'ignored'\n"
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	registry := &workspace.Registry{}
	if _, _, err := registry.Add(checkout, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := registry.Save(); err != nil {
		t.Fatal(err)
	}
	views, err := projectViews()
	if err != nil {
		t.Fatal(err)
	}
	wantPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 || views[0].Config == nil || views[0].Config.Path != wantPath || views[0].Config.Name != "secrets/{env}.etoml" || len(views[0].Config.Unknown) != 1 || views[0].Envs[0].Guard != "session" {
		t.Fatalf("configuration contract: %+v", views)
	}
	if err := os.WriteFile(path, []byte("project = ["), 0600); err != nil {
		t.Fatal(err)
	}
	views, err = projectViews()
	if err != nil {
		t.Fatal(err)
	}
	if views[0].Checkouts[0].Status != workspace.StatusInvalid || views[0].Checkouts[0].Error == "" {
		t.Fatalf("malformed config looked like a missing checkout: %+v", views[0].Checkouts)
	}
}
