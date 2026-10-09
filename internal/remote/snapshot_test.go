package remote

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mscno/esec"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/vaultfile"
)

// This tests the actual upload path after mutation, then recovers with no
// identity keychain, no local identity file and only phrase + remote bytes.
func TestAutoBackupIncludesNewKeysAndColdRecovers(t *testing.T) { //nolint:gocyclo // complete disaster recovery flow with explicit checks
	cfg := newTestConfig(t)
	cfg.Policy.Debounce = "0s"
	if err := Save(cfg); err != nil {
		t.Fatal(err)
	}
	kr := keyring.NewMemory()
	phrase, err := identity.Init(kr, "with spaces ", nil)
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.Load(kr)
	if err != nil {
		t.Fatal(err)
	}
	ks := keystore.New()
	pub, priv, err := esec.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.Write("org/repo/services/api", map[string]string{"ESEC_PRIVATE_KEY_DEV": priv}, false); err != nil {
		t.Fatal(err)
	}
	if err := ks.Write("default", map[string]string{"ESEC_PRIVATE_KEY": priv}, false); err != nil {
		t.Fatal(err)
	}
	first, err := BuildSnapshot(id, ks)
	if err != nil {
		t.Fatal(err)
	}
	again, err := BuildSnapshot(id, ks)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Blob, again.Blob) {
		t.Fatal("unchanged snapshot was resealed")
	}
	// Direct filesystem changes are found by scanning, without a dirty hook.
	_, priv2, err := esec.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.Write("org/new", map[string]string{"ESEC_PRIVATE_KEY_PROD": priv2}, false); err != nil {
		t.Fatal(err)
	}
	res, err := MaybePush(context.Background(), id, ks, "")
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.Generation != 2 || !res.Verified {
		t.Fatalf("not backed up: %+v", res)
	}
	_, blob, err := Latest(context.Background(), cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	if IsDirty() {
		t.Fatal("pending marker not cleared")
	}
	// Fresh device starts here. Only phrase, passphrase and ciphertext are used.
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	masterPub, masterPriv, err := identity.DeriveMaster(phrase, "with spaces ")
	if err != nil {
		t.Fatal(err)
	}
	v, err := vaultfile.OpenWithMaster(blob, &masterPub, &masterPriv)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := identity.Recover(keyring.NewMemory(), phrase, "with spaces ", v.Identity, nil)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.PublicHex() != id.PublicHex() || v.Projects["org/new"]["ESEC_PRIVATE_KEY_PROD"] != priv2 {
		t.Fatal("new key or identity lost")
	}
	if v.Projects["default"]["ESEC_PRIVATE_KEY"] != priv || v.Projects["org/repo/services/api"]["ESEC_PRIVATE_KEY_DEV"] != priv {
		t.Fatal("default/nested keyrings omitted")
	}
	_ = pub
}

func TestUnreadableStoreNeverReplacesBackup(t *testing.T) {
	newTestConfig(t)
	kr := keyring.NewMemory()
	if _, err := identity.Init(kr, "", nil); err != nil {
		t.Fatal(err)
	}
	id, err := identity.Load(kr)
	if err != nil {
		t.Fatal(err)
	}
	ks := keystore.New()
	first, err := BuildSnapshot(id, ks)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ks.Dir, "org_bad.keyring"), []byte("KEY=\"unterminated"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildSnapshot(id, ks); err == nil {
		t.Fatal("bad keyring silently skipped")
	}
	got, err := os.ReadFile(paths.VaultFile())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Blob, got) {
		t.Fatal("backup changed on failed scan")
	}
}

func TestDirtyDeadlineSurvivesMoreChanges(t *testing.T) {
	newTestConfig(t)
	if err := MarkDirty("first", 0); err != nil {
		t.Fatal(err)
	}
	_, before, ok := DirtyReason()
	if !ok {
		t.Fatal("not dirty")
	}
	time.Sleep(time.Millisecond)
	if err := MarkDirty("second", 0); err != nil {
		t.Fatal(err)
	}
	_, after, ok := DirtyReason()
	if !ok || after < before {
		t.Fatal("debounce deadline reset")
	}
}
