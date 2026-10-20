package cli_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/passkey/passkeytest"
	"github.com/mscno/esec-vault/internal/server"
	"github.com/mscno/esec-vault/internal/servertest"
)

const e2eSigner = "http://sign.localhost:9999"

// signerPost sends what the signer page sends, from its origin.
func signerPost(t *testing.T, h *servertest.Harness, b *servertest.Browser, path string, body any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, h.URL+"/signer/v1"+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Esec-Signer", "1")
	req.Header.Set("Origin", e2eSigner)
	resp, err := b.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(data, &out)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: %d %s", path, resp.StatusCode, data)
	}
	return out
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// TestWebSigningEndToEnd adds members from the web pages with a passkey: the
// owner's device adds the passkey, the passkey signs two members in, and the
// owner's sync sends keys to the one whose GitHub SSH proof checks out, not
// to the one without a proof.
func TestWebSigningEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds binaries")
	}
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets")
	}
	bin := buildBinaries(t)
	h := servertest.StartWith(t, []server.Option{server.WithRegistrationLimits(100, 1000), server.WithSignerURL(e2eSigner)}, 53101343, 2002, 2003)
	h.GitHub.AddUser(53101343, "mscno")
	h.GitHub.AddUser(2002, "alice")
	h.GitHub.AddUser(2003, "bob")
	sock, _, aliceKey := testAgentKey(t)
	h.GitHub.AddKey("alice", aliceKey)
	gh := "ESEC_VAULT_GITHUB_URL=" + h.GitHub.URL
	const p = "--project=acme/store"

	owner := newMachine(t, bin, "owner").with(gh, "ESEC_VAULT_SIGNER="+e2eSigner)
	owner.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
	repo := t.TempDir()
	owner.run("", "project", "init", "acme/store", "--dir", repo, "--env", "dev", "--format", "env")
	writeSecret(t, owner, repo, "dev", "DATABASE_URL=postgres://db-dev")
	login(t, h, owner.with("ESEC_VAULT_BOOTSTRAP_TOKEN="+servertest.BootstrapToken), "").wait(true)
	owner.run("", "team", "create", p)

	alice := newMachine(t, bin, "alice").with(gh, "SSH_AUTH_SOCK="+sock)
	alice.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
	loginAs(t, h, "alice", alice.with("ESEC_VAULT_BOOTSTRAP_TOKEN="+server.UserBootstrapToken(servertest.BootstrapSecret, 2002)), "").wait(true)
	alice.run("", "team", "prove")
	bob := newMachine(t, bin, "bob").with(gh)
	bob.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
	loginAs(t, h, "bob", bob.with("ESEC_VAULT_BOOTSTRAP_TOKEN="+server.UserBootstrapToken(servertest.BootstrapSecret, 2003)), "").wait(true)

	// The owner registers a passkey on the web; a device adds it.
	b := h.Browser("mscno")
	_, page, err := b.Get("/account/signing")
	if err != nil {
		t.Fatal(err)
	}
	csrf := servertest.CSRF(page)
	pk := passkeytest.New("sign.localhost", e2eSigner)
	opts := signerPost(t, h, b, "/passkeys/options", nil)
	cd, err := json.Marshal(map[string]any{"type": "webauthn.create", "challenge": opts["challenge"], "origin": e2eSigner})
	if err != nil {
		t.Fatal(err)
	}
	signerPost(t, h, b, "/passkeys", map[string]any{"name": "YubiKey", "scope": "manage", "credentialId": b64u(pk.CredID), "publicKey": b64u(pk.PublicKey()), "alg": -7, "clientDataJSON": b64u(cd)})
	if out := owner.run("y\n", "changes"); !strings.Contains(out, chain.DelegateWords(pk.Delegate("dl_any000001", "x", chain.ScopeManage, time.Now()))) || !strings.Contains(out, "Added the passkey YubiKey") {
		t.Fatalf("changes (passkey):\n%s", out)
	}
	out := owner.run("", "delegate")
	if !strings.Contains(out, "YubiKey") {
		t.Fatalf("delegate list:\n%s", out)
	}
	pkID := strings.Fields(out)[0]

	// The passkey adds alice and bob from the web pages.
	for _, who := range []string{"alice", "bob"} {
		if status, _, err := b.Post("/teams/acme/store/members", csrf, url.Values{"login": {who}, "env": {"dev"}}); err != nil || status != http.StatusOK {
			t.Fatalf("propose %s: %d %v", who, status, err)
		}
		_, page, _ = b.Get("/changes")
		id := regexpFind(t, page, `/#change=([0-9]+)"`)
		begin := signerPost(t, h, b, "/changes/"+id+"/begin", map[string]any{"delegate": pkID})
		links := list(begin["links"])
		assertions := make([]map[string]string, 0, len(links))
		for _, l := range links {
			m, _ := l.(map[string]any)
			body, _ := base64.RawURLEncoding.DecodeString(str(m["body"]))
			e := envelope.Envelope{Kind: str(m["kind"]), Body: body}
			as := pk.Assert(e.Challenge())
			assertions = append(assertions, map[string]string{"credentialId": b64u(as.CredentialID), "authenticatorData": b64u(as.AuthenticatorData), "clientDataJSON": b64u(as.ClientDataJSON), "signature": b64u(as.Signature)})
		}
		signerPost(t, h, b, "/changes/"+id+"/finish", map[string]any{"delegate": pkID, "assertions": assertions})
	}
	out = owner.run("", "team", "show", p)
	if !strings.Contains(out, "alice") || !strings.Contains(out, "bob") {
		t.Fatalf("team show:\n%s", out)
	}

	// The owner's device sends keys only after checking each account.
	out = owner.run("", "team", "sync")
	if !strings.Contains(out, "alice: acme/store dev") || !strings.Contains(out, "bob has not published a GitHub SSH proof") {
		t.Fatalf("owner sync:\n%s", out)
	}
	alice.run("y\n", "team", "sync")
	if ok, out := decrypts(alice, repo, "dev"); !ok || !strings.Contains(out, "postgres://db-dev") {
		t.Fatalf("alice:\n%s", out)
	}
	bob.run("y\n", "team", "sync")
	if ok, _ := decrypts(bob, repo, "dev"); ok {
		t.Fatal("bob got a key without a GitHub proof")
	}
}

func regexpFind(t *testing.T, s, pattern string) string {
	t.Helper()
	m := regexp.MustCompile(pattern).FindStringSubmatch(s)
	if m == nil {
		t.Fatalf("no %s in:\n%s", pattern, s)
	}
	return m[1]
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func list(v any) []any {
	l, _ := v.([]any)
	return l
}
