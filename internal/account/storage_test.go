package account_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mscno/esec"
	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/vaultfile"
	"github.com/mscno/esec-vault/internal/wire"
	"github.com/mscno/esec-vault/internal/workspace"
)

func TestServerInventoryCacheAndDowngradeFence(t *testing.T) { //nolint:gocyclo // keep the ordered recovery and commit invariants in one auditable sequence
	_, a := setup(t)
	ctx := context.Background()
	if err := os.WriteFile(paths.PolicyPath(), []byte("default = 'deny'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Sync(ctx, account.SyncOptions{}); err != nil {
		t.Fatal(err)
	}
	v, err := a.ReadVault(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v.Catalog == nil || len(v.Catalog.Profiles[a.State.DeviceID].Settings["policy.toml"]) == 0 {
		t.Fatal("device settings missing")
	}
	if res, err := a.Sync(ctx, account.SyncOptions{}); err != nil || res.Pushed {
		t.Fatalf("unchanged vault uploaded again: %v", err)
	}
	if err := a.CacheProject(ctx, "acme/store", "none"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.KS.Read("acme/store"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cache still materialized")
	}
	if _, err := a.Sync(ctx, account.SyncOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.KS.Read("acme/store"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("sync repopulated evicted keyring")
	}
	v, err = a.ReadVault(ctx)
	if err != nil || len(v.Projects["acme/store"]) == 0 {
		t.Fatal("eviction deleted server data")
	}
	entries, err := a.ExportProject(ctx, "acme/store")
	if err != nil || len(entries) == 0 {
		t.Fatalf("export after eviction: %v", err)
	}
	if err := a.CacheProject(ctx, "acme/store", "offline"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.KS.Read("acme/store"); err != nil {
		t.Fatal("offline keyring missing")
	}
	id, err := identity.Load(a.KR)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := vaultfile.Seal(&vaultfile.Vault{Projects: v.Projects, Generation: v.Generation + 1}, &id.Public, nil)
	if err != nil {
		t.Fatal(err)
	}
	current, err := a.Client.Vault(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Client.PutVault(ctx, wire.VaultPut{Blob: legacy, Sig: ed25519.Sign(id.Sign, wire.VaultMessage(a.State.User, legacy)), IfMatch: current.Version})
	if err == nil || !strings.Contains(err.Error(), "upgrade this client") {
		t.Fatalf("legacy overwrite accepted: %v", err)
	}
}

type offlineTransport struct{}

func (offlineTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("test network offline")
}

func TestServerFileRecoveryAndOfflineQueue(t *testing.T) { //nolint:gocyclo // keep the ordered recovery and commit invariants in one auditable sequence
	h, a := setup(t)
	ctx := context.Background()
	pub, priv, err := esec.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.KS.Write("acme/archive", map[string]string{keystore.EnvEntry("dev"): priv}, false); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	config := []byte("project = 'acme/archive'\n[env.dev]\nkey = '" + pub + "'\nguard = 'none'\n")
	if err := os.WriteFile(filepath.Join(root, "esec.toml"), config, 0600); err != nil {
		t.Fatal(err)
	}
	var encrypted bytes.Buffer
	if _, err := esec.Encrypt(strings.NewReader("ESEC_PUBLIC_KEY="+pub+"\nTOKEN=synthetic-archive-secret\n"), &encrypted, ".env"); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, ".env.dev")
	if err := os.WriteFile(secret, encrypted.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := workspace.Update(func(r *workspace.Registry) error { _, _, err := r.Add(root, time.Now()); return err }); err != nil {
		t.Fatal(err)
	}
	transport := a.Client.HTTP.Transport
	a.Client.HTTP.Transport = offlineTransport{}
	if _, err := a.Sync(ctx, account.SyncOptions{}); err == nil {
		t.Fatal("offline sync reported success")
	}
	raw, err := os.ReadFile(account.PendingPath())
	if err != nil {
		t.Fatal("offline changes were not staged")
	}
	if bytes.Contains(raw, []byte(priv)) || bytes.Contains(raw, []byte("synthetic-archive-secret")) {
		t.Fatal("plaintext in pending queue")
	}
	a.Client.HTTP.Transport = transport
	if _, err := a.Sync(ctx, account.SyncOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(account.PendingPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("acknowledged queue was not cleared")
	}
	v, err := a.ReadVault(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Catalog.Artifacts) != 2 {
		t.Fatalf("got %d archived files", len(v.Catalog.Artifacts))
	}
	var rawObject []byte
	if err := h.DB.SQL().QueryRow(`SELECT blob FROM vault_objects LIMIT 1`).Scan(&rawObject); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rawObject, []byte("acme/archive")) || bytes.Contains(rawObject, []byte("synthetic-archive-secret")) {
		t.Fatal("server object reveals metadata or values")
	}
	if _, _, err := a.RotateUserKey(ctx, "archive rotation test"); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "restored")
	if err := a.RestoreProject(ctx, "acme/archive", "", dest); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dest, ".env.dev")) //nolint:gosec // test-owned destination
	if err != nil || !bytes.Equal(got, encrypted.Bytes()) {
		t.Fatal("restored ciphertext differs")
	}
	var plain bytes.Buffer
	if _, err := esec.Decrypt(bytes.NewReader(got), &plain, "dev", ".env", dest, priv); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plain.String(), "synthetic-archive-secret") {
		t.Fatal("restored file cannot be decrypted")
	}
	if err := a.RestoreProject(ctx, "acme/archive", "", dest); err == nil {
		t.Fatal("restore overwrote an existing directory")
	}
	// A complete capture records deletion, while an earlier revision stays
	// available. Reverting bytes is another capture, not an old timestamp.
	v, err = a.ReadVault(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var original string
	for id, capture := range v.Catalog.Captures {
		if capture.Project == "acme/archive" {
			original = id
		}
	}
	if err := os.Remove(secret); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Sync(ctx, account.SyncOptions{}); err != nil {
		t.Fatal(err)
	}
	without := filepath.Join(t.TempDir(), "without-deleted-file")
	if err := a.RestoreProject(ctx, "acme/archive", "", without); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(without, ".env.dev")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("latest capture resurrected a deleted file")
	}
	old := filepath.Join(t.TempDir(), "old-revision")
	if err := a.RestoreProject(ctx, "acme/archive", "", old, original); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(old, ".env.dev")); err != nil {
		t.Fatal("historical capture lost its file")
	}
	// The phrase and one explicit export recover file history without a
	// server, account credentials, local keyrings, or an installed identity.
	portable, err := a.RecoveryExport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	masterPub, masterPriv, err := identity.DeriveMaster(lastMnemonic, "")
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := vaultfile.OpenWithMaster(portable, &masterPub, &masterPriv)
	if err != nil {
		t.Fatal(err)
	}
	a.Client.HTTP.Transport = offlineTransport{}
	offline := filepath.Join(t.TempDir(), "offline")
	if err := account.RestoreProjectArchive(recovered, "acme/archive", "", offline, original); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(filepath.Join(offline, ".env.dev")) //nolint:gosec // test-owned destination
	if err != nil || !bytes.Equal(got, encrypted.Bytes()) {
		t.Fatal("offline phrase recovery failed")
	}
	for id, blob := range recovered.Objects {
		blob[0] ^= 1
		recovered.Objects[id] = blob
	}
	corrupt := filepath.Join(t.TempDir(), "corrupt")
	if err := account.RestoreProjectArchive(recovered, "acme/archive", "", corrupt, original); err == nil {
		t.Fatal("corrupt archive accepted")
	}
	if _, err := os.Lstat(corrupt); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("corrupt archive wrote a partial destination")
	}
}

func TestKeyLifecycleDoesNotResurrectStaleCopies(t *testing.T) {
	_, a := setup(t)
	ctx := context.Background()
	if _, err := a.Sync(ctx, account.SyncOptions{}); err != nil {
		t.Fatal(err)
	}
	stale, err := a.KS.Read("acme/store")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := keystore.PublicHex(stale[keystore.EnvEntry("dev")])
	if err != nil {
		t.Fatal(err)
	}
	if err := a.ChangeKey(ctx, "acme/store", pub, false); err != nil {
		t.Fatal(err)
	}
	v, err := a.ReadVault(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v.Projects["acme/store"][keystore.EnvEntry("dev")] != "" || v.Projects["acme/store"][keystore.PubEntry(pub)] == "" {
		t.Fatal("retirement must remove aliases and retain historical keys")
	}
	if err := a.ChangeKey(ctx, "acme/store", pub, true); err != nil {
		t.Fatal(err)
	}
	if err := a.KS.Write("acme/store", stale, true); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Sync(ctx, account.SyncOptions{}); err != nil {
		t.Fatal(err)
	}
	local, err := a.KS.Read("acme/store")
	if err != nil {
		t.Fatal(err)
	}
	v, err = a.ReadVault(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, entries := range []map[string]string{local, v.Projects["acme/store"]} {
		if entries[keystore.PubEntry(pub)] != "" || entries[keystore.EnvEntry("dev")] != "" {
			t.Fatal("tombstoned key returned")
		}
	}
}

func TestPendingKeySurvivesOfflineKeyringLoss(t *testing.T) {
	_, a := setup(t)
	ctx := context.Background()
	if _, err := a.Sync(ctx, account.SyncOptions{}); err != nil {
		t.Fatal(err)
	}
	_, priv, err := esec.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.KS.Write("acme/pending", map[string]string{keystore.EnvEntry("dev"): priv}, false); err != nil {
		t.Fatal(err)
	}
	transport := a.Client.HTTP.Transport
	a.Client.HTTP.Transport = offlineTransport{}
	if _, err := a.Sync(ctx, account.SyncOptions{}); err == nil {
		t.Fatal("offline sync succeeded")
	}
	if err := a.KS.Delete("acme/pending"); err != nil {
		t.Fatal(err)
	}
	a.Client.HTTP.Transport = transport
	if _, err := a.Sync(ctx, account.SyncOptions{}); err != nil {
		t.Fatal(err)
	}
	v, err := a.ReadVault(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v.Projects["acme/pending"][keystore.EnvEntry("dev")] != priv {
		t.Fatal("pending edit lost")
	}
}
