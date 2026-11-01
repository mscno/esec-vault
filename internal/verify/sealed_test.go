package verify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/projectfile"
	coreseal "github.com/mscno/esec/pkg/seal"

	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/seal"
)

func TestRepositorySealsPreserveCurrentAndRotatedKeysWithoutCaches(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv("ESEC_CONFIG", "")
	repo := t.TempDir()
	gitRun(t, repo, "init", "-q")
	if err := projectfile.WriteProjectFile(repo, "acme/store"); err != nil {
		t.Fatal(err)
	}
	reader, _ := age.GenerateX25519Identity()
	recovery, _ := age.GenerateX25519Identity()
	_, signing, _ := ed25519.GenerateKey(rand.Reader)
	old := writeSealedTestEnv(t, repo, reader, recovery, signing)
	gitRun(t, repo, "add", "-A")
	gitRun(t, repo, "commit", "-qm", "seal original key")
	current := writeSealedTestEnv(t, repo, reader, recovery, signing)
	gitRun(t, repo, "add", "-A")
	gitRun(t, repo, "commit", "-qm", "rotate guarded key")

	ctx := context.Background()
	uses, _, err := Collect(ctx, []string{repo}, true)
	if err != nil {
		t.Fatal(err)
	}
	source, err := sealedSource(ctx, []string{repo}, true)
	if err != nil {
		t.Fatal(err)
	}
	report := Build(uses, []Source{{Name: SourceDevice, Projects: map[string]map[string]string{}}, source})
	if !report.OK() || report.Lost != 0 || report.HistoryMissing != 0 || len(report.Keys) != 2 {
		t.Fatalf("sealed keys should need no cached copies: %+v", report)
	}
	for _, key := range report.Keys {
		if key.Places != 1 || len(key.Held[SourceSealed]) != 1 {
			t.Fatalf("missing seal: %+v", key)
		}
	}

	// Without history, the old key is not claimed to be in today's seal.
	source, err = sealedSource(ctx, []string{repo}, false)
	if err != nil || source.Projects["acme/store"][keystore.GuardEntry(old)] != "" || source.Projects["acme/store"][keystore.GuardEntry(current)] == "" {
		t.Fatalf("current seals: %+v, %v", source, err)
	}
	// A valid signed record with a replaced/missing encrypted file is not
	// preservation. The intact version in Git still is.
	if err := os.WriteFile(coreseal.Path(repo, "prod"), []byte("replaced"), 0600); err != nil {
		t.Fatal(err)
	}
	source, err = sealedSource(ctx, []string{repo}, false)
	if err != nil || len(source.Projects) != 0 {
		t.Fatalf("accepted a seal whose hash differs: %+v, %v", source, err)
	}
	source, err = sealedSource(ctx, []string{repo}, true)
	if err != nil || len(source.Projects["acme/store"]) != 2 {
		t.Fatalf("intact historical seals: %+v, %v", source, err)
	}
}

func writeSealedTestEnv(t *testing.T, repo string, reader, recovery *age.X25519Identity, signing ed25519.PrivateKey) string {
	t.Helper()
	pub, priv, _ := esec.GenerateKeypair()
	data, err := coreseal.Seal(coreseal.Payload{Project: "acme/store", Env: "prod", Guard: "touch", Private: priv}, reader.Recipient(), recovery.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if err := coreseal.Write(repo, "prod", data); err != nil {
		t.Fatal(err)
	}
	rec := &seal.Record{Key: pub, Guard: "touch", Sealed: coreseal.Hash(data), Recovery: []string{recovery.Recipient().String()}, At: time.Now().UTC().Truncate(time.Second)}
	rec.Sign("acme/store", "prod", "gh:1", signing)
	if err := (seal.Records{"prod": rec}).Save(repo); err != nil {
		t.Fatal(err)
	}
	var encrypted bytes.Buffer
	if _, err := esec.Encrypt(strings.NewReader("ESEC_PUBLIC_KEY="+pub+"\nSECRET=test\n"), &encrypted, esec.FileFormatEnv); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".env.prod"), encrypted.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestHistoryIgnoresPublicKeyHeadersWithoutEncryptedValues(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv("ESEC_CONFIG", "")
	repo := t.TempDir()
	gitRun(t, repo, "init", "-q")
	if err := projectfile.WriteProjectFile(repo, "acme/store"); err != nil {
		t.Fatal(err)
	}
	pub, _, _ := esec.GenerateKeypair()
	file := filepath.Join(repo, ".env.dev")
	if err := os.WriteFile(file, []byte("ESEC_PUBLIC_KEY="+pub+"\nEXAMPLE=plaintext\n"), 0600); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "-A")
	gitRun(t, repo, "commit", "-qm", "old template")
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	uses, _, err := Collect(context.Background(), []string{repo}, true)
	if err != nil || len(uses) != 0 {
		t.Fatalf("a template needs no historical private key: %v, %v", uses, err)
	}
}

func TestMissingCurrentKeysAndHistoricalKeysAreReportedSeparately(t *testing.T) {
	current, _, _ := esec.GenerateKeypair()
	old, _, _ := esec.GenerateKeypair()
	held, private, _ := esec.GenerateKeypair()
	uses := map[string][]Use{
		current: {{Project: "acme/store", Env: "prod", Path: "/repo/.env.prod"}},
		old:     {{Project: "acme/store", Env: "prod", Path: "/repo/.env.prod", Commit: "previous"}},
	}
	report := Build(uses, []Source{{Name: SourceDevice, Projects: map[string]map[string]string{
		"acme/store": {keystore.PubEntry(held): private},
	}}})
	if report.OK() || report.Lost != 1 || report.HistoryMissing != 1 || report.Problems != 2 {
		t.Fatalf("current missing keys must remain visible separately: %+v", report)
	}
}
