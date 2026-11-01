package snapshot

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/mscno/esec"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/vaultfile"
)

func TestSnapshotColdRecoveryIgnoresLegacyDestinations(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv("ESEC_KEYRING_DIR", "")
	kr := keyring.NewMemory()
	phrase, err := identity.Init(kr, "recovery passphrase", nil)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := identity.Load(kr)
	ks := keystore.New()
	_, private, err := esec.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.Write("org/app", map[string]string{"ESEC_PRIVATE_KEY_DEV": private}, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(paths.Home(), "remote.toml"), []byte("broken legacy remote config"), 0600); err != nil {
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
		t.Fatal("unchanged snapshot changed")
	}
	masterPub, masterPriv, err := identity.DeriveMaster(phrase, "recovery passphrase")
	if err != nil {
		t.Fatal(err)
	}
	v, err := vaultfile.OpenWithMaster(first.Blob, &masterPub, &masterPriv)
	if err != nil {
		t.Fatal(err)
	}
	if v.Projects["org/app"]["ESEC_PRIVATE_KEY_DEV"] != private {
		t.Fatal("key missing from export")
	}
	if _, ok := v.Files["remote.toml"]; ok {
		t.Fatal("obsolete external configuration exported")
	}
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	fresh, err := identity.Recover(keyring.NewMemory(), phrase, "recovery passphrase", v.Identity, nil)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Public != id.Public {
		t.Fatal("export cannot recover identity")
	}
}

func TestUnreadableStoreNeverReplacesSnapshot(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv("ESEC_KEYRING_DIR", "")
	kr := keyring.NewMemory()
	if _, err := identity.Init(kr, "", nil); err != nil {
		t.Fatal(err)
	}
	id, _ := identity.Load(kr)
	ks := keystore.New()
	first, err := BuildSnapshot(id, ks)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(ks.Dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ks.Dir, "org_bad.keyring"), []byte("KEY=\"unterminated"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildSnapshot(id, ks); err == nil {
		t.Fatal("unreadable keys ignored")
	}
	got, err := os.ReadFile(paths.VaultFile())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Blob, got) {
		t.Fatal("existing snapshot replaced")
	}
}
