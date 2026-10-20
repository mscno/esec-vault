package account_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/machine"
	"github.com/mscno/esec-vault/internal/passkey/passkeytest"
	"github.com/mscno/esec-vault/internal/servertest"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// jsonPost sends what passkey.js sends: JSON with the page's CSRF token.
func jsonPost(t *testing.T, h *servertest.Harness, b *servertest.Browser, csrf, path string, body any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, h.URL+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Csrf-Token", csrf)
	req.Header.Set("Origin", h.URL)
	resp, err := b.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	data, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(data, &out)
	return resp.StatusCode, out
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func TestWebSigning(t *testing.T) { //nolint:gocyclo,maintidx // one sequential story
	h, a := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := a.CreateTeam(ctx, project, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateGroup(ctx, group); err != nil {
		t.Fatal(err)
	}
	if _, err := a.GrantGroup(ctx, group, project, []string{"dev"}); err != nil {
		t.Fatal(err)
	}
	web1, err := a.NewCred(ctx, group, team.KindMachine, "web-1", time.Time{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	web2, err := a.NewCred(ctx, group, team.KindMachine, "web-2", time.Time{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b := h.Browser("mscno")

	// The server signs removals once a device let it.
	page := getPage(t, b, "/account/signing", "Let the server sign removals")
	if status, body, err := b.Post("/account/delegates/server", servertest.CSRF(page), nil); err != nil || status != http.StatusOK || !strings.Contains(body, "waiting for your device") {
		t.Fatalf("propose server: %d %v", status, err)
	}
	changes, err := a.Changes(ctx)
	if err != nil || len(changes) != 1 || changes[0].Kind != wire.ChangeDelegateServer {
		t.Fatalf("changes: %+v %v", changes, err)
	}
	if _, err := a.ApplyChange(ctx, changes[0]); err != nil {
		t.Fatal(err)
	}
	if err := a.CloseChange(ctx, changes[0].ID, true); err != nil {
		t.Fatal(err)
	}
	page = getPage(t, b, "/groups/"+group, "web-1")
	_, body := dsRequest(t, h, b, http.MethodPost, "/groups/"+group+"/remove", "", url.Values{"csrf": {servertest.CSRF(page)}, "cred": {web1.ID}})
	if !strings.Contains(body, "signed by the server for you") {
		t.Fatalf("server removal:\n%s", body)
	}
	if _, err := machine.FetchGroup(ctx, web1, ""); err == nil {
		t.Fatal("a machine removed by the server still fetched keys")
	}
	// An admin's sync gives the group a new key; the others keep working.
	if _, err := a.TeamSync(ctx, account.TeamSyncOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := fetchDev(ctx, t, web2); got == "" {
		t.Fatal("web-2 lost its key")
	}
	view, err := a.Group(ctx, group)
	if err != nil || view.State.Key.Version != 2 || len(view.State.KeyExposed) != 0 {
		t.Fatalf("after server removal: key v%d exposed %d %v", view.State.Key.Version, len(view.State.KeyExposed), err)
	}
	// Narrowing is signed by the server; widening waits.
	_, body = dsRequest(t, h, b, http.MethodPost, "/groups/"+group+"/access", "", url.Values{"csrf": {servertest.CSRF(page)}, "project": {project}})
	if !strings.Contains(body, "signed by the server") {
		t.Fatalf("server narrows:\n%s", body)
	}
	_, body = dsRequest(t, h, b, http.MethodPost, "/groups/"+group+"/access", "", url.Values{"csrf": {servertest.CSRF(page)}, "project": {project}, "env": {"dev"}})
	if !strings.Contains(body, "Proposed") {
		t.Fatalf("server widened:\n%s", body)
	}

	// The device grants the group dev again, and the project gets prod.
	if _, err := a.GrantGroup(ctx, group, project, []string{"dev"}); err != nil {
		t.Fatal(err)
	}
	for _, c := range mustChanges(ctx, t, a) {
		_ = a.CloseChange(ctx, c.ID, false)
	}
	entries, err := keystore.New().Read(project)
	if err != nil {
		t.Fatal(err)
	}
	entries["ESEC_PRIVATE_KEY_PROD"] = strings.Repeat("cd", 32)
	if err := keystore.New().Write(project, entries, true); err != nil {
		t.Fatal(err)
	}
	if _, err := a.PublishEnv(ctx, project, "prod", ""); err != nil {
		t.Fatal(err)
	}
	page = getPage(t, b, "/groups/"+group, "web-2")
	_, body = dsRequest(t, h, b, http.MethodPost, "/groups/"+group+"/access", "", url.Values{"csrf": {servertest.CSRF(page)}, "project": {project}, "env": {"dev", "prod"}})
	if !strings.Contains(body, "Proposed") {
		t.Fatalf("widening:\n%s", body)
	}

	// A passkey: registered on the web, added by a device.
	pk := passkeytest.New("127.0.0.1", h.URL)
	csrf := servertest.CSRF(getPage(t, b, "/account/signing"))
	status, opts := jsonPost(t, h, b, csrf, "/account/passkeys/options", nil)
	if status != http.StatusOK {
		t.Fatalf("options: %d %v", status, opts)
	}
	cd, err := json.Marshal(map[string]any{"type": "webauthn.create", "challenge": opts["challenge"], "origin": h.URL})
	if err != nil {
		t.Fatal(err)
	}
	reg := map[string]any{"name": "YubiKey", "scope": "manage", "credentialId": b64(pk.CredID), "publicKey": b64(pk.PublicKey()), "alg": -7, "clientDataJSON": b64(cd)}
	if status, out := jsonPost(t, h, b, "wrong", "/account/passkeys", reg); status != http.StatusForbidden {
		t.Fatalf("register without CSRF: %d %v", status, out)
	}
	status, out := jsonPost(t, h, b, csrf, "/account/passkeys", reg)
	if status != http.StatusOK || out["words"] == "" {
		t.Fatalf("register: %d %v", status, out)
	}
	changes, err = a.Changes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var addPK *account.ChangeView
	for i := range changes {
		if changes[i].Kind == wire.ChangeDelegateAdd {
			addPK = &changes[i]
		}
	}
	if addPK == nil || !strings.Contains(addPK.Describe(), str(out["words"])) {
		t.Fatalf("passkey change: %+v", changes)
	}
	if _, err := a.ApplyChange(ctx, *addPK); err != nil {
		t.Fatal(err)
	}
	_ = a.CloseChange(ctx, addPK.ID, true)
	ds, err := a.Delegates(ctx)
	if err != nil || len(ds) != 2 {
		t.Fatalf("delegates: %+v %v", ds, err)
	}
	var pkID string
	for _, d := range ds {
		if d.Kind == chain.DelegatePasskey {
			pkID = d.ID
		}
	}

	// The passkey signs the waiting change (the group reads dev and prod).
	changes, _ = a.Changes(ctx)
	if len(changes) != 1 || changes[0].Kind != wire.ChangeAccess {
		t.Fatalf("waiting: %+v", changes)
	}
	id := strconv.FormatInt(changes[0].ID, 10)
	page = getPage(t, b, "/changes", "Sign with passkey")
	csrf = servertest.CSRF(page)
	status, begin := jsonPost(t, h, b, csrf, "/changes/"+id+"/passkey/begin", map[string]any{"delegate": pkID})
	if status != http.StatusOK {
		t.Fatalf("begin: %d %v", status, begin)
	}
	sign := func(mutate func(*passkeytest.Authenticator)) []map[string]string {
		a := *pk
		if mutate != nil {
			mutate(&a)
		}
		chs := list(begin["challenges"])
		out := make([]map[string]string, 0, len(chs))
		for _, ch := range chs {
			c, _ := base64.RawURLEncoding.DecodeString(str(ch))
			as := a.Assert(c)
			out = append(out, map[string]string{"credentialId": b64(as.CredentialID), "authenticatorData": b64(as.AuthenticatorData), "clientDataJSON": b64(as.ClientDataJSON), "signature": b64(as.Signature)})
		}
		return out
	}
	if status, out := jsonPost(t, h, b, csrf, "/changes/"+id+"/passkey/finish", map[string]any{"delegate": pkID, "assertions": sign(func(a *passkeytest.Authenticator) { a.Origin = "https://evil.example" })}); status == http.StatusOK {
		t.Fatalf("finish from another origin: %v", out)
	}
	// A failed attempt ends the ceremony; start again.
	_, begin = jsonPost(t, h, b, csrf, "/changes/"+id+"/passkey/begin", map[string]any{"delegate": pkID})
	if status, out := jsonPost(t, h, b, csrf, "/changes/"+id+"/passkey/finish", map[string]any{"delegate": pkID, "assertions": sign(nil)}); status != http.StatusOK {
		t.Fatalf("finish: %d %v", status, out)
	}
	view, err = a.Group(ctx, group)
	if err != nil || len(view.Projects) != 1 || len(view.Projects[0].Envs) != 2 {
		t.Fatalf("after passkey: %+v %v", view.Projects, err)
	}
	if changes, _ := a.Changes(ctx); len(changes) != 0 {
		t.Fatalf("change left open: %+v", changes)
	}
	// The group gets the keys from an admin's sync.
	if _, err := a.TeamSync(ctx, account.TeamSyncOptions{}); err != nil {
		t.Fatal(err)
	}
	if keys, err := machine.FetchGroup(ctx, web2, ""); err != nil || keys.Projects[project]["prod"] == "" {
		t.Fatalf("web-2 did not get prod: %v", err)
	}

	// A user-chain change cannot be signed by a passkey.
	if status, _, err := b.Post("/account/delegates/"+pkID+"/remove", csrf, nil); err != nil || status != http.StatusOK {
		t.Fatal(status, err)
	}
	changes, _ = a.Changes(ctx)
	if status, _ := jsonPost(t, h, b, csrf, "/changes/"+strconv.FormatInt(changes[0].ID, 10)+"/passkey/begin", map[string]any{"delegate": pkID}); status == http.StatusOK {
		t.Fatal("a passkey was offered a user-chain change")
	}
	if _, err := a.ApplyChange(ctx, changes[0]); err != nil {
		t.Fatal(err)
	}
	if ds, _ := a.Delegates(ctx); len(ds) != 1 {
		t.Fatalf("passkey not removed: %+v", ds)
	}
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func list(v any) []any {
	l, _ := v.([]any)
	return l
}

func mustChanges(ctx context.Context, t *testing.T, a *account.Account) []account.ChangeView {
	t.Helper()
	cs, err := a.Changes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}
