package broker

import (
	"bytes"
	"errors"
	"testing"

	"github.com/mscno/esec-vault/internal/policy"
	"github.com/mscno/esec-vault/internal/secretfile"
)

func TestBrokerDocumentReadUsesGuardAndNeverWrites(t *testing.T) {
	skipUnlessUnix(t)
	path, keys := encryptedFixture(t, t.TempDir())
	before := mustRead(t, path)
	client, audit, srv := startTestBroker(t, nil, &policy.Policy{Default: policy.Deny})
	g := &fakeGuard{priv: keys["ESEC_PRIVATE_KEY_DEV"], allow: true}
	srv.Guard = g
	req := &Request{Op: OpGetSecrets, Project: "acme/store", Env: "dev", Path: path, Format: ".ejson", Session: "EsecVault app", Document: true}
	resp, err := client.Call(req)
	if err != nil || !resp.OK || resp.Document == nil {
		t.Fatalf("document read failed: %v", err)
	}
	if resp.Document.Revision != secretfile.Revision(before) || len(resp.Document.Values) != 2 || g.asked.Load() != 1 {
		t.Fatal("wrong document or bypassed guard")
	}
	if !bytes.Equal(before, mustRead(t, path)) {
		t.Fatal("viewing changed ciphertext")
	}
	entries := readAudit(t, audit)
	if len(entries) == 0 || entries[len(entries)-1].Session != "EsecVault app" {
		t.Fatal("missing app audit")
	}
	g.allow = false
	resp, err = client.Call(req)
	if err != nil || resp.OK || resp.Document != nil {
		t.Fatal("denied read returned values")
	}
	g.allow = true
	srv.RequireLogin = func() error { return errors.New("signed out") }
	resp, err = client.Call(req)
	if err != nil || resp.OK || resp.Document != nil {
		t.Fatal("logged-out read returned values")
	}
}
