package account_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mscno/esec"
	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/seal"
	"github.com/mscno/esec-vault/internal/workspace"
	coreseal "github.com/mscno/esec/pkg/seal"
)

func archiveFixture(t *testing.T, a *account.Account, guard string) (string, string, string, []byte) {
	t.Helper()
	pub, priv, err := esec.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.KS.Write("acme/archive", map[string]string{keystore.EnvEntry("dev"): priv}, false); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	config := "project = 'acme/archive'\n[env.dev]\nkey = '" + pub + "'\nguard = '" + guard + "'\n"
	if err := os.WriteFile(filepath.Join(root, "esec.toml"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	var encrypted bytes.Buffer
	if _, err := esec.Encrypt(strings.NewReader("ESEC_PUBLIC_KEY="+pub+"\nTOKEN=synthetic\n"), &encrypted, ".env"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env.dev"), encrypted.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := workspace.Update(func(r *workspace.Registry) error { _, _, err := r.Add(root, time.Now()); return err }); err != nil {
		t.Fatal(err)
	}
	return root, pub, priv, encrypted.Bytes()
}

func TestRepositoryCannotAuthorizeKeyDeletion(t *testing.T) {
	_, a := setup(t)
	root, pub, priv, _ := archiveFixture(t, a, "touch")
	_, attacker, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	bogus := []byte("not even an age seal")
	record := &seal.Record{Key: pub, Guard: "touch", Sealed: coreseal.Hash(bogus), Recovery: []string{"not-my-recovery-key"}, At: time.Now()}
	record.Sign("acme/archive", "dev", "gh:attacker", attacker)
	if err := (seal.Records{"dev": record}).Save(root); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".esec", "dev.age"), bogus, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Sync(context.Background(), account.SyncOptions{}); err == nil {
		t.Fatal("untrusted guard migration accepted")
	}
	local, err := a.KS.Read("acme/archive")
	if err != nil || local[keystore.PubEntry(pub)] != priv {
		t.Fatal("repository input deleted the sole key")
	}
}

func TestArchiveVerificationDetectsMissingObjects(t *testing.T) {
	h, a := setup(t)
	archiveFixture(t, a, "none")
	ctx := context.Background()
	if _, err := a.Sync(ctx, account.SyncOptions{}); err != nil {
		t.Fatal(err)
	}
	v, err := a.ReadVault(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := a.VerifyArchive(ctx, v); err != nil || n != 2 {
		t.Fatalf("intact archive: count=%d error=%v", n, err)
	}
	if _, err := h.DB.SQL().Exec(`DELETE FROM vault_objects WHERE user_id = ?`, a.State.User); err != nil {
		t.Fatal(err)
	}
	if _, err := a.VerifyArchive(ctx, v); err == nil {
		t.Fatal("missing server objects passed verification")
	}
	if _, err := a.RecoveryExport(ctx); err == nil {
		t.Fatal("incomplete recovery export succeeded")
	}
}

func TestPendingAliasRemovalCanBeUndoneBeforeSync(t *testing.T) {
	_, a := setup(t)
	ctx := context.Background()
	if _, err := a.Sync(ctx, account.SyncOptions{}); err != nil {
		t.Fatal(err)
	}
	entries, err := a.KS.Read("acme/store")
	if err != nil {
		t.Fatal(err)
	}
	name := keystore.EnvEntry("dev")
	private := entries[name]
	delete(entries, name)
	if err := a.Locked(func() error { return a.KS.Reconcile("acme/store", entries) }); err != nil {
		t.Fatal(err)
	}
	transport := a.Client.HTTP.Transport
	a.Client.HTTP.Transport = offlineTransport{}
	if _, err := a.Sync(ctx, account.SyncOptions{}); err == nil {
		t.Fatal("offline sync succeeded")
	}
	entries[name] = private
	if err := a.KS.Write("acme/store", entries, true); err != nil {
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
	if v.Projects["acme/store"][name] != private {
		t.Fatal("offline undo lost its alias")
	}
}

func TestUncachedImportSurvivesWorkingKeyringLoss(t *testing.T) {
	_, a := setup(t)
	ctx := context.Background()
	if err := a.CacheProject(ctx, "acme/store", "none"); err != nil {
		t.Fatal(err)
	}
	_, priv, err := esec.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	name := keystore.EnvEntry("pending")
	if err := a.KS.Write("acme/store", map[string]string{name: priv}, false); err != nil {
		t.Fatal(err)
	}
	transport := a.Client.HTTP.Transport
	a.Client.HTTP.Transport = offlineTransport{}
	if _, err := a.Sync(ctx, account.SyncOptions{}); err == nil {
		t.Fatal("offline sync succeeded")
	}
	if err := a.KS.Delete("acme/store"); err != nil {
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
	if v.Projects["acme/store"][name] != priv {
		t.Fatal("uncached durable import lost")
	}
	if _, err := a.KS.Read("acme/store"); !os.IsNotExist(err) {
		t.Fatal("uncached project rematerialized")
	}
}

func TestArchiveRejectsUnreadableCandidatesInsteadOfOmittingThem(t *testing.T) {
	for _, mode := range []string{"oversized", "malformed", "no-public-key", "directory", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			_, a := setup(t)
			root, pub, _, original := archiveFixture(t, a, "none")
			ctx := context.Background()
			if _, err := a.Sync(ctx, account.SyncOptions{}); err != nil {
				t.Fatal(err)
			}
			before, err := a.ReadVault(ctx)
			if err != nil {
				t.Fatal(err)
			}
			data := []byte("TOKEN=plaintext\n")
			switch mode {
			case "oversized":
				data = bytes.Repeat([]byte{'x'}, 11<<20)
			case "malformed":
				data = []byte("ESEC_PUBLIC_KEY=" + pub + "\nTOKEN=\"unterminated\n")
			}
			if err := os.WriteFile(filepath.Join(root, ".env.dev"), data, 0600); err != nil {
				t.Fatal(err)
			}
			if mode == "directory" || mode == "symlink" {
				if err := os.Remove(filepath.Join(root, ".env.dev")); err != nil {
					t.Fatal(err)
				}
				if mode == "directory" {
					if err := os.Mkdir(filepath.Join(root, ".env.dev"), 0700); err != nil {
						t.Fatal(err)
					}
				} else if err := os.Symlink(filepath.Join(t.TempDir(), "outside"), filepath.Join(root, ".env.dev")); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := a.Sync(ctx, account.SyncOptions{}); err == nil {
				t.Fatal("bad candidate was silently omitted")
			}
			after, err := a.ReadVault(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if before.Generation != after.Generation || !account.StagingIssue() {
				t.Fatal("failed archive acknowledged as complete")
			}
			dest := filepath.Join(t.TempDir(), "restored")
			if err := a.RestoreProject(ctx, "acme/archive", "", dest); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(filepath.Join(dest, ".env.dev")) //nolint:gosec // test-owned destination
			if err != nil || !bytes.Equal(got, original) {
				t.Fatal("last good capture was lost")
			}
		})
	}
}
