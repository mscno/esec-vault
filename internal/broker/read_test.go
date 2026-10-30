package broker

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mscno/esec"
	"github.com/mscno/esec-vault/internal/policy"
	"github.com/mscno/esec/pkg/projectfile"
)

func TestScopedDocumentReadDoesNotUnlockOtherKeys(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv("ESEC_CONFIG", "")
	path, entries := encryptedFixture(t, t.TempDir())
	if err := projectfile.WriteProjectFile(filepath.Dir(path), "acme/store"); err != nil {
		t.Fatal(err)
	}
	target, err := esec.ResolveRead(".", path, "")
	if err != nil {
		t.Fatal(err)
	}
	audit, err := NewAuditLogger(filepath.Join(t.TempDir(), "audit"))
	if err != nil {
		t.Fatal(err)
	}
	b := NewServer(nil, &policy.Policy{Default: policy.Deny}, audit, nil)
	b.Lock()
	asked, opened := 0, 0
	b.Consent = func(uint32, uint32, *esec.ReadTarget) (string, error) { asked++; return "once", nil }
	b.OpenRead = func(*esec.ReadTarget) (string, error) { opened++; return entries["ESEC_PRIVATE_KEY_DEV"], nil }
	req := &Request{Op: OpReadDocument, Project: target.Project, Env: target.Environment, Path: path, Format: string(target.Format), Digest: target.Digest}
	got := b.dispatch(501, 0, req)
	if !got.OK || !bytes.Contains(got.Document, []byte("s3cret")) || asked != 1 || opened != 1 {
		t.Fatalf("document: %+v calls %d/%d", got, asked, opened)
	}
	if unlocked, _ := b.Session(); unlocked {
		t.Fatal("one read unlocked the broker globally")
	}
	req.Env = "production"
	if got := b.dispatch(501, 0, req); got.OK || got.Code != "environment_mismatch" || asked != 1 {
		t.Fatalf("spoofed env: %+v", got)
	}
	req.Env = target.Environment
	req.Digest = "changed"
	if got := b.dispatch(501, 0, req); got.OK || got.Code != "file_changed" || asked != 1 {
		t.Fatalf("changed file: %+v", got)
	}
	req.Digest = target.Digest
	b.ReloadPolicy(&policy.Policy{Configured: true, Default: policy.Deny})
	if got := b.dispatch(501, 0, req); got.OK || got.Code != "policy_denied" || asked != 1 || opened != 1 {
		t.Fatalf("explicit deny: %+v", got)
	}
}

func TestInspectionNeverRequestsConsentOrOpensKeys(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv("ESEC_CONFIG", "")
	path, _ := encryptedFixture(t, t.TempDir())
	if err := projectfile.WriteProjectFile(filepath.Dir(path), "acme/store"); err != nil {
		t.Fatal(err)
	}
	b := NewServer(nil, &policy.Policy{}, nil, nil)
	b.Consent = func(uint32, uint32, *esec.ReadTarget) (string, error) {
		t.Error("inspection requested approval")
		return "", nil
	}
	b.OpenRead = func(*esec.ReadTarget) (string, error) { t.Error("inspection opened a key"); return "", nil }
	b.Inspect = func(_ uint32, target *esec.ReadTarget) *esec.ReadInspection {
		return esec.InspectLocalRead(target, esec.ReadOptions{})
	}
	response := b.dispatch(501, 0, &Request{Op: OpInspectRead, Project: "acme/store", Env: "dev", Path: path, Format: ".ejson"})
	if !response.OK || response.Inspection == nil || response.Document != nil || response.Secrets != nil {
		t.Fatalf("inspection: %+v", response)
	}
	data, err := os.ReadFile(path) //nolint:gosec // test fixture path
	if err != nil || !strings.Contains(string(data), "ESEC_PUBLIC_KEY") {
		t.Fatal(err)
	}
}

type lockingGuard struct {
	fakeGuard

	lock func()
}

func (g *lockingGuard) Key(req GuardRequest) (string, string, error) {
	g.lock()
	return g.fakeGuard.Key(req)
}

func TestForwardedInspectionAndLockCannotDiscloseDocuments(t *testing.T) {
	path, keys := encryptedFixture(t, t.TempDir())
	data := mustRead(t, path)
	audit, err := NewAuditLogger(filepath.Join(t.TempDir(), "audit"))
	if err != nil {
		t.Fatal(err)
	}
	owner := NewServer(nil, &policy.Policy{}, audit, nil)
	forwarded := NewServer(nil, &policy.Policy{Default: policy.Deny}, audit, nil)
	forwarded.Forwarded = true
	forwarded.ReadGeneration = owner.Epoch
	g := &lockingGuard{fakeGuard: fakeGuard{priv: keys["ESEC_PRIVATE_KEY_DEV"], allow: true}, lock: owner.Lock}
	forwarded.Guard = g
	req := &Request{Op: OpInspectRead, Project: "acme/store", Env: "dev", Path: "/srv/app/.ejson.dev", Format: ".ejson", Content: data, Seal: []byte("stand-in seal")}
	inspected := forwarded.dispatch(501, 0, req)
	if inspected.OK || inspected.Code != "inspection_unavailable" || g.asked.Load() != 0 {
		t.Fatalf("forwarded inspection asked to decrypt: %+v", inspected)
	}
	req.Op = OpReadDocument
	response := forwarded.dispatch(501, 0, req)
	if response.OK || response.Code != "access_revoked" || response.Document != nil {
		t.Fatalf("forwarded read survived owner lock: %+v", response)
	}
}
