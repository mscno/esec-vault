package remote

import (
	"testing"

	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/storage"
)

// A command that changes keys holds the keyring lock while it stores them
// elsewhere (project init, env add): the snapshot must not lock again.
func TestSnapshotUnderHeldKeyringLock(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv("ESEC_KEYRING_DIR", "")
	kr := keyring.NewMemory()
	if _, err := identity.Init(kr, "", nil); err != nil {
		t.Fatal(err)
	}
	id, err := identity.Load(kr)
	if err != nil {
		t.Fatal(err)
	}
	ks := keystore.New()
	unlock, err := storage.Lock(ks.Dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ks.Locked = true
	if _, err := BuildSnapshot(id, ks); err != nil {
		t.Fatalf("snapshot under the caller's lock: %v", err)
	}
}
