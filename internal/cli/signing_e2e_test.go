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
func TestWebSigningEndToEnd(t *testing.T) { //nolint:gocyclo,maintidx // one sequential story with explicit checks
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
	owner.run("", "project", "init", "acme/store", "--dir", repo, "--env", "dev,prod", "--format", "env")
	writeSecret(t, owner, repo, "dev", "DATABASE_URL=postgres://db-dev")
	writeSecret(t, owner, repo, "prod", "DATABASE_URL=postgres://db-prod")
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
	var waiting []struct {
		Kind        string   `json:"kind"`
		Removes     bool     `json:"removes"`
		Description []string `json:"description"`
	}
	if raw := owner.runJSON(&waiting, "changes"); len(waiting) != 1 || waiting[0].Removes || len(waiting[0].Description) == 0 {
		t.Fatalf("changes --json:\n%s", raw)
	}
	// With nothing to answer, nothing is signed, and it says so.
	if out, err := owner.cmd(owner.home, "", "esec-vault", "changes").CombinedOutput(); err == nil || !strings.Contains(string(out), "1 change(s) not signed") {
		t.Fatalf("changes without an answer (err %v):\n%s", err, out)
	}
	if raw := owner.runJSON(&waiting, "changes"); len(waiting) != 1 {
		t.Fatalf("the unanswered change is gone:\n%s", raw)
	}
	if out := owner.run("y\n", "changes"); !strings.Contains(out, chain.DelegateWords(pk.Delegate("dl_any000001", "x", chain.ScopeManage, time.Now()))) || !strings.Contains(out, "Added the passkey YubiKey") {
		t.Fatalf("changes (passkey):\n%s", out)
	}
	out := owner.run("", "delegate")
	if !strings.Contains(out, "YubiKey") {
		t.Fatalf("delegate list:\n%s", out)
	}
	pkID := strings.Fields(out)[0]

	// signWaiting signs the change waiting on the Changes page with the
	// passkey, as the signer page does.
	signWaiting := func() {
		t.Helper()
		_, page, _ := b.Get("/changes")
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

	// The passkey adds alice and bob from the web pages.
	for _, who := range []string{"alice", "bob"} {
		if status, _, err := b.Post("/teams/acme/store/members", csrf, url.Values{"login": {who}, "env": {"dev"}}); err != nil || status != http.StatusOK {
			t.Fatalf("propose %s: %d %v", who, status, err)
		}
		signWaiting()
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

	// --- The same for a group of people: the passkey adds them on the web,
	// and the owner's device seals the group key only to proven accounts. ---
	const g = "acme/backend"
	owner.run("", "group", "create", g)
	owner.run("", "access", "grant", g, "--env", "prod", p)
	for _, who := range []string{"alice", "bob"} {
		if status, page, err := b.Post("/groups/"+g+"/members", csrf, url.Values{"login": {who}}); err != nil || status != http.StatusOK {
			t.Fatalf("propose %s for the group: %d %v\n%s", who, status, err, page)
		}
		signWaiting()
	}
	if out := owner.run("", "group", "show", g); !strings.Contains(out, "Members (2): alice, bob") {
		t.Fatalf("group show after the web adds:\n%s", out)
	}
	out = owner.run("", "access", "sync")
	if !strings.Contains(out, "the group key to 1 machine(s), token(s) or admin(s)") || !strings.Contains(out, "the group key to bob (added on the web)") {
		t.Fatalf("owner sync for the group:\n%s", out)
	}
	if out := alice.run("y\n", "access", "sync"); !strings.Contains(out, "+ acme/store prod") {
		t.Fatalf("alice sync through the group:\n%s", out)
	}
	bob.run("y\n", "access", "sync")
	if ok, _ := decrypts(bob, repo, "prod"); ok {
		t.Fatal("bob got prod through the group without a GitHub proof")
	}
	_, page, _ = b.Get("/groups/" + g)
	if !strings.Contains(page, "alice") || !strings.Contains(page, "/groups/"+g+"/members/remove") {
		t.Fatalf("group page lacks its people:\n%s", page)
	}
	// Removing bob on the web stops his keys at once; the passkey signs it.
	if status, page, err := b.Post("/groups/"+g+"/members/remove", csrf, url.Values{"login": {"bob"}}); err != nil || status != http.StatusOK || !strings.Contains(page, "being removed") {
		t.Fatalf("remove bob on the web: %d %v\n%s", status, err, page)
	}
	if out, err := bob.cmd(bob.home, "", "esec-vault", "access", "sync").CombinedOutput(); err != nil || !strings.Contains(string(out), "is removing you") {
		t.Fatalf("bob while being removed: %v\n%s", err, out)
	}
	signWaiting()
	if out := owner.run("", "group", "show", g); !strings.Contains(out, "Members (1): alice") {
		t.Fatalf("group show after the web removal:\n%s", out)
	}
	if out := owner.run("", "access", "sync"); !strings.Contains(out, "a new group key, since bob left") {
		t.Fatalf("owner sync after the web removal:\n%s", out)
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
