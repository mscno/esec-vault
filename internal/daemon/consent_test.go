package daemon

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mscno/esec"
	"github.com/mscno/esec-vault/internal/broker"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/notify"
	"github.com/mscno/esec-vault/internal/policy"
	"github.com/mscno/esec/pkg/projectfile"
	"github.com/mscno/esec/pkg/seal"
)

func TestReadConsentIsScopedExpiringAndRevokedByLock(t *testing.T) {
	t.Setenv("ESEC_VAULT_DIALOGS", "")
	b := broker.NewServer(nil, &policy.Policy{Default: policy.Deny}, nil, nil)
	c := newReadConsent(b)
	target := &esec.ReadTarget{Project: "acme/store", Environment: "production", PublicKey: "pub", Root: t.TempDir(), Path: filepath.Join(t.TempDir(), ".env.production"), Guard: "none"}
	old := ReadAsker
	t.Cleanup(func() { ReadAsker = old })
	calls := 0
	answer := "once"
	ReadAsker = func(_, text string, _ time.Duration) (string, error) {
		calls++
		if !strings.Contains(text, "Public key: ") || !strings.Contains(text, target.Path) {
			t.Error("consent is not bound to the displayed file and key")
		}
		return answer, nil
	}
	for n := 0; n < 2; n++ {
		if _, err := c.ask(501, 0, target); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 {
		t.Fatal("allow once was remembered")
	}
	answer = "session"
	for n := 0; n < 2; n++ {
		if _, err := c.ask(501, 0, target); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 3 {
		t.Fatal("session did not reuse its exact grant")
	}
	other := *target
	other.PublicKey = "rotated"
	if _, err := c.ask(501, 0, &other); err != nil || calls != 4 {
		t.Fatal("rotation reused a grant", err)
	}
	other = *target
	other.Environment = "staging"
	if _, err := c.ask(501, 0, &other); err != nil || calls != 5 {
		t.Fatal("another environment reused a grant", err)
	}
	c.mu.Lock()
	c.grants[consentScope(501, target)] = consentGrant{time.Now().Add(-time.Second), b.Epoch()}
	c.mu.Unlock()
	if _, err := c.ask(501, 0, target); err != nil || calls != 6 {
		t.Fatal("expired consent reused", err)
	}
	b.Lock()
	if c.has(501, target) {
		t.Fatal("lock did not revoke session consent")
	}
	ReadAsker = func(string, string, time.Duration) (string, error) { b.Lock(); return "session", nil }
	if _, err := c.ask(501, 0, target); err == nil {
		t.Fatal("approval raced past lock")
	}
}

func TestReadConsentCancellationAndNoDesktop(t *testing.T) {
	t.Setenv("ESEC_VAULT_DIALOGS", "")
	b := broker.NewServer(nil, &policy.Policy{}, nil, nil)
	c := newReadConsent(b)
	target := &esec.ReadTarget{Project: "a/b", Root: t.TempDir(), Environment: "dev", PublicKey: "key"}
	old := ReadAsker
	t.Cleanup(func() { ReadAsker = old })
	for _, tc := range []struct {
		answer string
		err    error
		code   string
	}{{"", nil, "consent_denied"}, {"", notify.ErrNoDialogs, "consent_required"}} {
		ReadAsker = func(string, string, time.Duration) (string, error) { return tc.answer, tc.err }
		_, err := c.ask(501, 0, target)
		var re *esec.ReadError
		if !errors.As(err, &re) || re.Code != tc.code || c.has(501, target) {
			t.Fatalf("unexpected consent result: %v", err)
		}
	}
}

func TestManagedReadUsesConsentWithoutPolicyOrGlobalUnlock(t *testing.T) {
	t.Setenv("ESEC_VAULT_DIALOGS", "")
	t.Setenv("ESEC_SECRET_STORE", "file")
	t.Setenv("ESEC_CONFIG", "")
	t.Setenv("ESEC_AGE_IDENTITY", "")
	t.Setenv("ESEC_AGE_IDENTITY_FILE", "")
	old := ReadAsker
	t.Cleanup(func() { ReadAsker = old })
	calls := 0
	ReadAsker = func(string, string, time.Duration) (string, error) { calls++; return "once", nil }
	s, _ := server(t, time.Hour)
	root := t.TempDir()
	pub, priv, err := esec.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	pf := &projectfile.File{Project: "acme/consent", Env: map[string]projectfile.Env{"production": {Key: pub}}}
	if err := pf.Save(root); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, ".env.production")
	if err := os.WriteFile(path, []byte("ESEC_PUBLIC_KEY="+pub+"\nTOKEN=consented\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := esec.EncryptFileInPlace(path); err != nil {
		t.Fatal(err)
	}
	id, err := identity.Load(s.Keyring)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := seal.X25519Identity(hex.EncodeToString(id.Private[:]))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := seal.Seal(seal.Payload{Project: pf.Project, Env: "production", Private: priv}, reader.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if err := seal.Write(root, "production", sealed); err != nil {
		t.Fatal(err)
	}
	target, err := esec.ResolveRead(".", path, "")
	if err != nil {
		t.Fatal(err)
	}
	inspection := esec.InspectRead(target, esec.ReadOptions{})
	if calls != 0 || inspection.Environment != "production" {
		t.Fatal("inspection opened the key")
	}
	data, err := esec.ReadDocument(target, esec.ReadOptions{})
	if err != nil || !strings.Contains(string(data), "TOKEN=consented") || calls != 1 {
		t.Fatalf("scoped read: %s %v calls=%d", data, err, calls)
	}
	if unlocked, _ := s.Broker.Session(); unlocked {
		t.Fatal("consent unlocked all broker keys")
	}
	entries, _ := keystore.New().Read(pf.Project)
	if len(entries) != 0 {
		t.Fatal("allow once persisted the opened key")
	}
}
