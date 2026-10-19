package server_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mscno/esec-vault/internal/devicekey"
	"github.com/mscno/esec-vault/internal/servertest"
	"github.com/mscno/esec-vault/internal/wire"
)

// footer ends every page, so a page that has it rendered in full.
const footer = "The server stores only ciphertext."

// getPage fetches a page and fails unless it rendered in full.
func getPage(t *testing.T, b *servertest.Browser, path string) string {
	t.Helper()
	status, page, err := b.Get(path)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK || !strings.Contains(page, footer) {
		t.Fatalf("%s: HTTP %d, rendered in full: %t\n%s", path, status, strings.Contains(page, footer), page)
	}
	return page
}

func mustContain(t *testing.T, page string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(page, w) {
			t.Fatalf("page lacks %q:\n%s", w, page)
		}
	}
}

// pushIndex pushes a vault with a project index.
func pushIndex(t *testing.T, a *account, d *dev, ifMatch uint64, projects []wire.IndexProject) {
	t.Helper()
	put := a.vault(t, ifMatch, map[string]map[string]string{})
	idx, err := json.Marshal(wire.VaultIndex{Generation: a.gen, Projects: projects})
	if err != nil {
		t.Fatal(err)
	}
	put.Index, put.IndexSig = idx, ed25519.Sign(a.u.Sign, wire.IndexMessage(user, idx))
	if _, err := d.c.PutVault(context.Background(), *put); err != nil {
		t.Fatal(err)
	}
}

func TestWebPagesRender(t *testing.T) {
	h := harness(t)
	owner := signIn(t, h, nil, "laptop")
	a := create(t, owner)
	vm := signIn(t, h, nil, "vm")
	a.approve(t, owner, vm)
	storeKey := strings.Repeat("cd", 32)
	pushIndex(t, a, owner, 1, []wire.IndexProject{
		{ID: "acme/store", Environments: []wire.IndexEnv{{Name: "production", PublicKey: storeKey}, {Name: "staging", PublicKey: strings.Repeat("ef", 32)}}},
		{ID: "acme/billing", Environments: []wire.IndexEnv{{Name: "production", PublicKey: strings.Repeat("12", 32)}}},
	})
	b := h.Browser("mscno")

	overview := getPage(t, b, "/account")
	mustContain(t, overview, "laptop", "vm", "2 active", "Version 2", "2 projects", "3 environments", "this browser", owner.key.Words(), `href="/devices/`+vm.info.ID+`"`)

	device := getPage(t, b, "/devices/"+vm.info.ID)
	mustContain(t, device, "vm", vm.key.Words(), vm.info.ID, "approval from another device", "Device approved", "esec vault devices revoke "+vm.info.ID)

	activity := getPage(t, b, "/activity")
	mustContain(t, activity, "Account created", "Device approved", "Vault pushed", "version 2")
	devices := getPage(t, b, "/activity?category=devices")
	mustContain(t, devices, "Device approved")
	if strings.Contains(devices, "Vault pushed") {
		t.Fatal("the devices filter shows vault pushes")
	}
	byVM := getPage(t, b, "/activity?device="+vm.info.ID)
	mustContain(t, byVM, "Device approved", "Showing")
	if strings.Contains(byVM, "Account created") {
		t.Fatal("the device filter shows another device's entries")
	}

	vault := getPage(t, b, "/vault")
	mustContain(t, vault, "2 versions", "published", "laptop")

	projects := getPage(t, b, "/projects")
	mustContain(t, projects, "acme/store", "acme/billing", `data-copy="`+storeKey+`"`)
	byKey := getPage(t, b, "/projects?q="+storeKey[:20])
	mustContain(t, byKey, "acme/store", "1 project of 2")
	if strings.Contains(byKey, "acme/billing") || strings.Contains(byKey, "staging") {
		t.Fatal("search by public key shows other environments")
	}

	getPage(t, b, "/device")
	index := getPage(t, h.Browser("nobody"), "/")
	mustContain(t, index, "esec vault login "+h.URL)

	// Admin pages are not there for people who are not admins.
	if status, _, _ := b.Get("/admin"); status != http.StatusNotFound {
		t.Fatalf("admin page for a non-admin: %d", status)
	}
	if strings.Contains(overview, `href="/admin"`) {
		t.Fatal("non-admins see the admin link")
	}
}

func TestDeviceAndActivityPagesStayInTheirAccount(t *testing.T) {
	h := servertest.Start(t, ownerID, 8)
	h.GitHub.AddUser(ownerID, "mscno")
	h.GitHub.AddUser(8, "other")
	owner := signIn(t, h, nil, "laptop")
	create(t, owner)
	other := h.Browser("other")
	if status, _, _ := other.Get("/devices/" + owner.info.ID); status != http.StatusNotFound {
		t.Fatalf("another account's device page: %d", status)
	}
	page := getPage(t, other, "/activity?device="+owner.info.ID)
	if strings.Contains(page, "Account created") || strings.Contains(page, "laptop") {
		t.Fatal("the activity page shows another account's entries")
	}
}

func TestAdminPages(t *testing.T) {
	h := servertest.Start(t, ownerID, 8, 9)
	h.GitHub.AddUser(ownerID, "mscno")
	h.GitHub.AddUser(8, "other")
	h.Config.Access.AdminGitHubIDs = []int64{ownerID}
	owner := signIn(t, h, nil, "laptop")
	create(t, owner)
	getPage(t, h.Browser("other"), "/account")
	h.GitHub.AddUser(7, "stranger")
	if status, _, _ := h.Browser("stranger").Get("/account"); status != http.StatusForbidden {
		t.Fatalf("stranger: %d", status)
	}

	b := h.Browser("mscno")
	admin := getPage(t, b, "/admin")
	mustContain(t, admin, "mscno", "other", "GitHub 9", "never signed in", "signed in, no account yet", "admin", "dev")
	// Denied sign-ins are security events, with the account they tried.
	mustContain(t, admin, "Sign-in refused: not allowed", "stranger (GitHub 7)", "Account created")
	all := getPage(t, b, "/admin?events=all")
	mustContain(t, all, "Signed in on the web")

	userPage := getPage(t, b, "/admin/users/"+user)
	mustContain(t, userPage, "laptop", "account creation", "Account created")
	if strings.Contains(userPage, owner.key.Words()) {
		t.Fatal("the admin page shows device fingerprints")
	}
	if status, _, _ := b.Get("/admin/users/gh:12345"); status != http.StatusNotFound {
		t.Fatalf("unknown account: %d", status)
	}
	if status, _, _ := h.Browser("other").Get("/admin/users/" + user); status != http.StatusNotFound {
		t.Fatalf("admin user page for a non-admin: %d", status)
	}
	overview := getPage(t, b, "/account")
	mustContain(t, overview, `href="/admin"`)
}

func TestSignOutOtherBrowsers(t *testing.T) {
	h := harness(t)
	first, second := h.Browser("mscno"), h.Browser("mscno")
	getPage(t, second, "/account")
	page := getPage(t, first, "/account")
	if n := strings.Count(page, "/end\""); n != 2 {
		// One sign-out button for the other browser, one for all others.
		t.Fatalf("sign-out forms: %d", n)
	}
	sessions := func() int {
		var n int
		if err := h.DB.SQL().QueryRow(`SELECT COUNT(*) FROM web_sessions`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := sessions(); n != 2 {
		t.Fatalf("sessions before: %d", n)
	}
	if status, _, err := first.Post("/account/browsers/others/end", "", nil); err != nil || status != http.StatusForbidden {
		t.Fatalf("without CSRF: %d %v", status, err)
	}
	if status, page, err := first.Post("/account/browsers/others/end", servertest.CSRF(page), nil); err != nil || status != http.StatusOK || !strings.Contains(page, "this browser") {
		t.Fatalf("sign out others: %d %v", status, err)
	}
	if n := sessions(); n != 1 {
		t.Fatalf("sessions after: %d", n)
	}
	activity := getPage(t, first, "/activity")
	mustContain(t, activity, "Browsers signed out", "1 browser")
	var agent string
	if err := h.DB.SQL().QueryRow(`SELECT user_agent FROM web_sessions`).Scan(&agent); err != nil || agent == "" {
		t.Fatalf("user agent not recorded: %q %v", agent, err)
	}
}

func TestOverviewNotices(t *testing.T) {
	h := harness(t)
	b := h.Browser("mscno")
	page := getPage(t, b, "/account")
	mustContain(t, page, "Your account has not been created yet", "esec vault login "+h.URL)

	owner := signIn(t, h, nil, "laptop")
	a := create(t, owner)
	page = getPage(t, b, "/account")
	mustContain(t, page, "Only one device can open your vault")

	key, _ := devicekey.Generate()
	c, reg := register(t, h, key, "new-laptop")
	if err := b.Confirm(reg.UserCode, true); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PollToken(context.Background(), reg.DeviceCode); err != nil {
		t.Fatal(err)
	}
	page = getPage(t, b, "/account")
	mustContain(t, page, "new-laptop (linux/amd64) is waiting for approval", "esec vault devices approve d_")
	if strings.Contains(page, key.Words()) {
		t.Fatal("the overview shows a waiting device's words")
	}

	// Suspending from the device page returns to it.
	var pending string
	if err := h.DB.SQL().QueryRow(`SELECT id FROM devices WHERE name = 'new-laptop'`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	devicePage := getPage(t, b, "/devices/"+pending)
	if strings.Contains(devicePage, key.Words()) {
		t.Fatal("the device page shows a waiting device's words")
	}
	status, after, err := b.Post("/account/devices/"+pending+"/suspend", servertest.CSRF(devicePage), url.Values{"back": {"/devices/" + pending}})
	if err != nil || status != http.StatusOK {
		t.Fatalf("suspend: %d %v", status, err)
	}
	// It was never approved: nothing to revoke, and its words stay hidden.
	mustContain(t, after, "This device is blocked", "never had access")
	if strings.Contains(after, "esec vault devices revoke") || strings.Contains(after, key.Words()) {
		t.Fatal("a device suspended while waiting gets revoke advice or shows its words")
	}
	page = getPage(t, b, "/account")
	if strings.Contains(page, "new-laptop is suspended but not revoked") || strings.Contains(page, key.Words()) {
		t.Fatal("the overview asks to revoke a device that was never approved")
	}

	// An approved device that is suspended needs revoking.
	vm := signIn(t, h, nil, "vm")
	a.approve(t, owner, vm)
	page = getPage(t, b, "/account")
	status, _, err = b.Post("/account/devices/"+vm.info.ID+"/suspend", servertest.CSRF(page), nil)
	if err != nil || status != http.StatusOK {
		t.Fatalf("suspend vm: %d %v", status, err)
	}
	page = getPage(t, b, "/account")
	mustContain(t, page, "vm is suspended but not revoked", "esec vault devices revoke "+vm.info.ID, vm.key.Words())

	// A device unseen for months is called out.
	h.Advance(100 * 24 * time.Hour)
	page = getPage(t, b, "/account")
	mustContain(t, page, "laptop has not been seen for 3 months")
	if strings.Contains(page, "new-laptop has not been seen") {
		t.Fatal("a suspended device is called idle")
	}
}

func TestPagesLoadOnlyTheirOwnScript(t *testing.T) {
	h := harness(t)
	resp, err := http.Get(h.URL + "/static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), "javascript") {
		t.Fatalf("app.js: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self';") || strings.Contains(csp, "unsafe") {
		t.Fatalf("CSP: %s", csp)
	}
}
