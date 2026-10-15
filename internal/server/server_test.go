package server_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/mscno/esec-vault/internal/apisig"
	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/client"
	"github.com/mscno/esec-vault/internal/devicekey"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/servertest"
	"github.com/mscno/esec-vault/internal/ukey"
	"github.com/mscno/esec-vault/internal/vaultfile"
	"github.com/mscno/esec-vault/internal/wire"
)

const (
	ownerID = 53101343
	user    = "gh:53101343"
)

func harness(t *testing.T) *servertest.Harness {
	t.Helper()
	h := servertest.Start(t, ownerID)
	h.GitHub.AddUser(ownerID, "mscno")
	h.GitHub.AddUser(7, "stranger")
	return h
}

type dev struct {
	key  *devicekey.Key
	c    *client.Client
	info wire.DeviceInfo
}

func (d *dev) chainDevice() chain.Device {
	return chain.Device{ID: d.info.ID, Name: d.info.Name, Platform: d.info.Platform, EncPub: d.key.EncPubHex(), SignPub: d.key.SignPubHex(), Created: d.info.Created.UTC()}
}

// register starts a device grant.
func register(t *testing.T, h *servertest.Harness, key *devicekey.Key, name string) (*client.Client, *wire.DeviceRegisterResponse) {
	t.Helper()
	c, err := client.New(h.URL)
	if err != nil {
		t.Fatal(err)
	}
	c.Now = h.Now
	reg, err := c.RegisterDevice(context.Background(), wire.DeviceRegisterRequest{Name: name, Platform: "linux/amd64", EncPub: key.EncPubHex(), SignPub: key.SignPubHex()})
	if err != nil {
		t.Fatal(err)
	}
	c.DeviceID, c.Key = reg.DeviceID, key.Sign
	return c, reg
}

// signIn runs the full device grant for a new or existing device key.
func signIn(t *testing.T, h *servertest.Harness, key *devicekey.Key, name string) *dev {
	t.Helper()
	if key == nil {
		var err error
		if key, err = devicekey.Generate(); err != nil {
			t.Fatal(err)
		}
	}
	c, reg := register(t, h, key, name)
	if err := h.Browser("mscno").Confirm(reg.UserCode, true); err != nil {
		t.Fatal(err)
	}
	tok, err := c.PollToken(context.Background(), reg.DeviceCode)
	if err != nil {
		t.Fatal(err)
	}
	c.DeviceID, c.Token = tok.Device.ID, tok.SessionToken
	d := &dev{key: key, c: c, info: tok.Device}
	if tok.Device.Status == wire.DevicePending {
		proof, err := key.Proof(user, d.chainDevice())
		if err != nil {
			t.Fatal(err)
		}
		if err := c.UploadProof(context.Background(), proof); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

type account struct {
	u          *identity.Identity
	master     [32]byte
	masterSign ed25519.PrivateKey
	st         *chain.State
	gen        uint64
}

func (a *account) wrapped(t *testing.T) []byte {
	t.Helper()
	w, err := identity.Wrapped(a.u, &a.master, false)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func (a *account) vault(t *testing.T, ifMatch uint64, projects map[string]map[string]string) *wire.VaultPut {
	t.Helper()
	a.gen++
	blob, err := vaultfile.Seal(&vaultfile.Vault{Projects: projects, Identity: a.wrapped(t), IdentityFingerprint: a.u.Fingerprint(), Generation: a.gen}, &a.u.Public, &a.master)
	if err != nil {
		t.Fatal(err)
	}
	return &wire.VaultPut{Blob: blob, Sig: ed25519.Sign(a.u.Sign, wire.VaultMessage(user, blob)), IfMatch: ifMatch}
}

func (a *account) box(t *testing.T, st *chain.State, d *dev) wire.DeviceBox {
	t.Helper()
	m, err := ukey.FromIdentity(user, st.UKeyVersion, a.u)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ukey.SealToDevice(m, d.key.EncPub)
	if err != nil {
		t.Fatal(err)
	}
	return wire.DeviceBox{DeviceID: d.info.ID, UKeyVersion: st.UKeyVersion, Box: b}
}

func (a *account) link(t *testing.T, typ string, body any, signers ...ed25519.PrivateKey) (*envelope.Envelope, *chain.State) {
	t.Helper()
	if len(signers) == 0 {
		signers = []ed25519.PrivateKey{a.u.Sign}
	}
	e, err := a.st.NewLink(typ, body, time.Now(), signers...)
	if err != nil {
		t.Fatal(err)
	}
	next, err := a.st.Next(e)
	if err != nil {
		t.Fatal(err)
	}
	return e, next
}

func (a *account) addBody(t *testing.T, d *dev, method, approver string) chain.DeviceAddBody {
	t.Helper()
	proof, err := d.key.Proof(user, d.chainDevice())
	if err != nil {
		t.Fatal(err)
	}
	return chain.DeviceAddBody{Device: d.chainDevice(), Proof: *proof, Method: method, ApprovedBy: approver}
}

// create makes d the first device of a new account.
func create(t *testing.T, d *dev) *account {
	t.Helper()
	u, err := identity.NewRandom()
	if err != nil {
		t.Fatal(err)
	}
	mpub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, msign, _ := ed25519.GenerateKey(rand.Reader)
	a := &account{u: u, master: *mpub, masterSign: msign, st: chain.New(user)}
	initLink, st1 := a.link(t, chain.TypeInit, chain.NewInitBody(u.Public, u.SignPublic(), *mpub, msign))
	a.st = st1
	addLink, st2 := a.link(t, chain.TypeDeviceAdd, a.addBody(t, d, chain.MethodFirst, ""))
	if _, err := d.c.Commit(context.Background(), &wire.Commit{Links: []*envelope.Envelope{initLink, addLink}, DeviceBoxes: []wire.DeviceBox{a.box(t, st2, d)}, Identity: a.wrapped(t), Vault: a.vault(t, 0, map[string]map[string]string{"acme/store": {"ESEC_PRIVATE_KEY_DEV": strings.Repeat("ab", 32)}})}); err != nil {
		t.Fatal(err)
	}
	a.st = st2
	return a
}

// approve adds d with an approval by owner.
func (a *account) approve(t *testing.T, owner, d *dev) {
	t.Helper()
	e, next := a.link(t, chain.TypeDeviceAdd, a.addBody(t, d, chain.MethodApproval, owner.info.ID))
	if _, err := owner.c.Commit(context.Background(), &wire.Commit{Links: []*envelope.Envelope{e}, DeviceBoxes: []wire.DeviceBox{a.box(t, next, d)}}); err != nil {
		t.Fatal(err)
	}
	a.st = next
}

func code(err error) string {
	var ae *client.APIError
	if e, ok := err.(*client.APIError); ok {
		ae = e
		return ae.Code
	}
	if err == nil {
		return ""
	}
	return "other: " + err.Error()
}

func TestDeviceGrant(t *testing.T) { //nolint:gocyclo // one sequential story
	h := harness(t)
	key, _ := devicekey.Generate()
	c, reg := register(t, h, key, "laptop")
	if !strings.HasPrefix(reg.VerificationURIComplete, h.URL+"/device?code=") || len(reg.UserCode) != 9 {
		t.Fatalf("registration: %+v", reg)
	}
	ctx := context.Background()
	if _, err := c.PollToken(ctx, reg.DeviceCode); code(err) != wire.ErrAuthorizationPending {
		t.Fatalf("first poll: %v", err)
	}
	if _, err := c.PollToken(ctx, reg.DeviceCode); code(err) != wire.ErrSlowDown {
		t.Fatalf("fast poll: %v", err)
	}
	// Only the registered device key can collect the session.
	other, _ := devicekey.Generate()
	thief := *c
	thief.Key = other.Sign
	h.Advance(6 * time.Second)
	if _, err := thief.PollToken(ctx, reg.DeviceCode); code(err) != wire.ErrUnauthorized {
		t.Fatalf("poll with another key: %v", err)
	}
	// Lowercase input and O/I confusions still match the code.
	typed := strings.ToLower(strings.NewReplacer("0", "o", "1", "i").Replace(reg.UserCode))
	if err := h.Browser("mscno").Confirm(typed, true); err != nil {
		t.Fatal(err)
	}
	h.Advance(6 * time.Second)
	tok, err := c.PollToken(ctx, reg.DeviceCode)
	if err != nil {
		t.Fatal(err)
	}
	if tok.User.ID != user || tok.Device.Status != wire.DevicePending || !strings.HasPrefix(tok.SessionToken, "esv_") {
		t.Fatalf("token: %+v", tok)
	}
	h.Advance(6 * time.Second)
	if _, err := c.PollToken(ctx, reg.DeviceCode); code(err) != wire.ErrExpiredToken {
		t.Fatalf("reused code: %v", err)
	}

	// Denied and expired codes.
	c2, reg2 := register(t, h, key, "laptop")
	if err := h.Browser("mscno").Confirm(reg2.UserCode, false); err != nil {
		t.Fatal(err)
	}
	if _, err := c2.PollToken(ctx, reg2.DeviceCode); code(err) != wire.ErrAccessDenied {
		t.Fatalf("denied code: %v", err)
	}
	c3, reg3 := register(t, h, key, "laptop")
	h.Advance(11 * time.Minute)
	if _, err := c3.PollToken(ctx, reg3.DeviceCode); code(err) != wire.ErrExpiredToken {
		t.Fatalf("expired code: %v", err)
	}
	if err := h.Browser("mscno").Confirm(reg3.UserCode, true); err == nil {
		t.Fatal("an expired code was confirmed")
	}

	// A stranger's GitHub account never gets a web session.
	status, page, err := h.Browser("stranger").Get("/device")
	if err != nil || status != http.StatusForbidden || !strings.Contains(page, "not allowed") {
		t.Fatalf("stranger: %d %v", status, err)
	}

	// Registrations are rate limited per address.
	for i := 0; i < 10; i++ {
		_, err := c.RegisterDevice(ctx, wire.DeviceRegisterRequest{Name: "x", Platform: "linux/amd64", EncPub: key.EncPubHex(), SignPub: key.SignPubHex()})
		if code(err) == wire.ErrRateLimited {
			return
		}
	}
	t.Fatal("registrations not rate limited")
}

func TestRegistrationValidation(t *testing.T) {
	h := harness(t)
	c, err := client.New(h.URL)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := devicekey.Generate()
	for _, req := range []wire.DeviceRegisterRequest{
		{Name: "evil\x1b[2J", Platform: "linux/amd64", EncPub: key.EncPubHex(), SignPub: key.SignPubHex()},
		{Name: "ok", Platform: "linux/amd64", EncPub: "zz", SignPub: key.SignPubHex()},
		{Name: "ok", Platform: "linux", EncPub: key.EncPubHex(), SignPub: key.SignPubHex()},
		{Name: "ok", Platform: "linux/amd64", EncPub: strings.Repeat("00", 32), SignPub: key.SignPubHex()},
	} {
		if _, err := c.RegisterDevice(context.Background(), req); code(err) != wire.ErrInvalidRequest {
			t.Fatalf("accepted %+v: %v", req, err)
		}
	}
}

func TestRequestAuthentication(t *testing.T) {
	h := harness(t)
	d := signIn(t, h, nil, "laptop")
	ctx := context.Background()
	if _, err := d.c.Me(ctx); err != nil {
		t.Fatal(err)
	}

	// No token.
	noToken := *d.c
	noToken.Token = ""
	if _, err := noToken.Me(ctx); code(err) != wire.ErrUnauthorized {
		t.Fatalf("no token: %v", err)
	}
	// The token with another device's key.
	other, _ := devicekey.Generate()
	stolen := *d.c
	stolen.Key = other.Sign
	if _, err := stolen.Me(ctx); code(err) != wire.ErrUnauthorized {
		t.Fatalf("stolen token: %v", err)
	}
	// Clock skew beyond the limit.
	skewed := *d.c
	skewed.Now = func() time.Time { return h.Now().Add(5 * time.Minute) }
	if _, err := skewed.Me(ctx); code(err) != wire.ErrUnauthorized {
		t.Fatalf("skewed clock: %v", err)
	}

	// Replaying a signed request, or changing its body, is rejected.
	body := []byte(`{}`)
	req, _ := http.NewRequest(http.MethodPost, h.URL+"/v1/auth/logout", bytes.NewReader(body))
	if err := apisig.Sign(req, body, d.info.ID, d.key.Sign, h.Now()); err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+d.c.Token)
	replay := req.Clone(context.Background())
	tampered := req.Clone(context.Background())
	tampered.Body = http.NoBody
	if st := statusOf(t, tampered); st != http.StatusUnauthorized {
		t.Fatalf("tampered body accepted: %d", st)
	}
	if st := statusOf(t, req); st != http.StatusOK {
		t.Fatalf("signed logout: %d", st)
	}
	replay.Body = http.NoBody
	replay.Body = nopCloser{bytes.NewReader(body)}
	if st := statusOf(t, replay); st != http.StatusUnauthorized {
		t.Fatalf("replayed request accepted: %d", st)
	}
	// After logout the session is gone.
	if _, err := d.c.Me(ctx); code(err) != wire.ErrUnauthorized {
		t.Fatalf("session after logout: %v", err)
	}
}

func statusOf(t *testing.T, req *http.Request) int {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

type nopCloser struct{ *bytes.Reader }

func (nopCloser) Close() error { return nil }

func TestSessionLifetimesAndAllowlist(t *testing.T) {
	h := harness(t)
	d := signIn(t, h, nil, "laptop")
	a := create(t, d)
	_ = a
	ctx := context.Background()
	// Idle expiry.
	h.Advance(31 * 24 * time.Hour)
	d.c.Now = h.Now
	if _, err := d.c.Me(ctx); code(err) != wire.ErrUnauthorized {
		t.Fatalf("idle session still valid: %v", err)
	}
	// Signing in again with the same device key restores access without a
	// new approval.
	again := signIn(t, h, d.key, "laptop")
	if again.info.ID != d.info.ID || again.info.Status != wire.DeviceActive {
		t.Fatalf("re-login made a new device: %+v", again.info)
	}
	// Removing the account from the allowlist blocks it on the next request.
	h.Config.Access.AllowedGitHubIDs = []int64{1}
	if _, err := again.c.Me(ctx); code(err) != wire.ErrForbidden {
		t.Fatalf("removed account still allowed: %v", err)
	}
}

func TestPendingDeviceRestrictions(t *testing.T) {
	h := harness(t)
	owner := signIn(t, h, nil, "laptop")
	a := create(t, owner)
	vm := signIn(t, h, nil, "vm")
	ctx := context.Background()
	if _, err := vm.c.Vault(ctx); code(err) != wire.ErrForbidden {
		t.Fatalf("pending device read the vault: %v", err)
	}
	if _, err := vm.c.Devices(ctx); code(err) != wire.ErrForbidden {
		t.Fatalf("pending device listed devices: %v", err)
	}
	// A pending device cannot add another device, even with a valid link.
	other := signIn(t, h, nil, "other")
	e, next := a.link(t, chain.TypeDeviceAdd, a.addBody(t, other, chain.MethodApproval, owner.info.ID))
	if _, err := vm.c.Commit(ctx, &wire.Commit{Links: []*envelope.Envelope{e}, DeviceBoxes: []wire.DeviceBox{a.box(t, next, other)}}); code(err) != wire.ErrForbidden {
		t.Fatalf("pending device added another device: %v", err)
	}
	// Without the user key it cannot add itself either.
	stranger, _ := identity.NewRandom()
	forged, err := a.st.NewLink(chain.TypeDeviceAdd, a.addBody(t, vm, chain.MethodRecovery, ""), time.Now(), stranger.Sign)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vm.c.Commit(ctx, &wire.Commit{Links: []*envelope.Envelope{forged}}); code(err) != wire.ErrInvalidRequest {
		t.Fatalf("forged self-add: %v", err)
	}
	// Approval makes it active; the pending window expires otherwise.
	a.approve(t, owner, vm)
	if _, err := vm.c.Vault(ctx); err != nil {
		t.Fatalf("approved device cannot read the vault: %v", err)
	}
	late := signIn(t, h, nil, "late")
	h.Advance(16 * time.Minute)
	late.c.Now, owner.c.Now = h.Now, h.Now
	if _, err := late.c.Me(ctx); code(err) != wire.ErrPendingExpired {
		t.Fatalf("expired pending device: %v", err)
	}
	e, next = a.link(t, chain.TypeDeviceAdd, a.addBody(t, late, chain.MethodApproval, owner.info.ID))
	if _, err := owner.c.Commit(ctx, &wire.Commit{Links: []*envelope.Envelope{e}, DeviceBoxes: []wire.DeviceBox{a.box(t, next, late)}}); code(err) != wire.ErrPendingExpired {
		t.Fatalf("approved an expired pending device: %v", err)
	}
}

func TestCommitAndVaultRules(t *testing.T) { //nolint:gocyclo // one sequential story
	h := harness(t)
	owner := signIn(t, h, nil, "laptop")
	a := create(t, owner)
	ctx := context.Background()

	// A second init.
	u2, _ := identity.NewRandom()
	initAgain, err := a.st.NewLink(chain.TypeInit, chain.NewInitBody(u2.Public, u2.SignPublic(), a.master, a.masterSign), time.Now(), u2.Sign)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.c.Commit(ctx, &wire.Commit{Links: []*envelope.Envelope{initAgain}}); code(err) != wire.ErrInvalidRequest {
		t.Fatalf("second init: %v", err)
	}
	// Adding a device the server never registered.
	ghostKey, _ := devicekey.Generate()
	ghost := &dev{key: ghostKey, info: wire.DeviceInfo{ID: "d_ghost0000000000", Name: "ghost", Platform: "linux/amd64", Created: time.Now().UTC().Truncate(time.Second)}}
	e, next := a.link(t, chain.TypeDeviceAdd, a.addBody(t, ghost, chain.MethodApproval, owner.info.ID))
	if _, err := owner.c.Commit(ctx, &wire.Commit{Links: []*envelope.Envelope{e}, DeviceBoxes: []wire.DeviceBox{a.box(t, next, ghost)}}); code(err) != wire.ErrInvalidRequest {
		t.Fatalf("unregistered device added: %v", err)
	}
	// Approving without a box for the new device breaks the invariant.
	vm := signIn(t, h, nil, "vm")
	e, _ = a.link(t, chain.TypeDeviceAdd, a.addBody(t, vm, chain.MethodApproval, owner.info.ID))
	if _, err := owner.c.Commit(ctx, &wire.Commit{Links: []*envelope.Envelope{e}}); code(err) != wire.ErrInvalidRequest {
		t.Fatalf("device added without a box: %v", err)
	}
	a.approve(t, owner, vm)

	// Vault writes: unsigned, signed by another key, stale, then valid.
	put := a.vault(t, 1, map[string]map[string]string{"acme/store": {"ESEC_PRIVATE_KEY_DEV": strings.Repeat("cd", 32)}})
	unsigned := *put
	unsigned.Sig = nil
	if _, err := owner.c.PutVault(ctx, unsigned); code(err) != wire.ErrInvalidRequest {
		t.Fatalf("unsigned vault: %v", err)
	}
	stranger, _ := identity.NewRandom()
	forged := *put
	forged.Sig = ed25519.Sign(stranger.Sign, wire.VaultMessage(user, put.Blob))
	if _, err := owner.c.PutVault(ctx, forged); code(err) != wire.ErrInvalidRequest {
		t.Fatalf("vault signed by another key: %v", err)
	}
	notVault := *put
	notVault.Blob = []byte("hello")
	notVault.Sig = ed25519.Sign(a.u.Sign, wire.VaultMessage(user, notVault.Blob))
	if _, err := owner.c.PutVault(ctx, notVault); code(err) != wire.ErrInvalidRequest {
		t.Fatalf("non-vault blob: %v", err)
	}
	stale := *put
	stale.IfMatch = 0
	if _, err := owner.c.PutVault(ctx, stale); code(err) != wire.ErrConflict {
		t.Fatalf("stale write: %v", err)
	}
	v, err := owner.c.PutVault(ctx, *put)
	if err != nil || v.Version != 2 {
		t.Fatalf("valid write: %v %+v", err, v)
	}
	got, err := vm.c.Vault(ctx)
	if err != nil || !bytes.Equal(got.Blob, put.Blob) || !ed25519.Verify(a.u.SignPublic(), wire.VaultMessage(user, got.Blob), got.Sig) {
		t.Fatalf("read back: %v", err)
	}

	// Index: unsigned or with hostile strings is refused.
	idx, err := json.Marshal(wire.VaultIndex{Projects: []wire.IndexProject{{ID: "acme/store", Environments: []wire.IndexEnv{{Name: "<script>", PublicKey: strings.Repeat("ab", 32)}}}}})
	if err != nil {
		t.Fatal(err)
	}
	withIdx := a.vault(t, 2, map[string]map[string]string{})
	withIdx.Index, withIdx.IndexSig = idx, ed25519.Sign(a.u.Sign, wire.IndexMessage(user, idx))
	if _, err := owner.c.PutVault(ctx, *withIdx); code(err) != wire.ErrInvalidRequest {
		t.Fatalf("hostile index: %v", err)
	}
	withIdx.IndexSig = nil
	if _, err := owner.c.PutVault(ctx, *withIdx); code(err) != wire.ErrInvalidRequest {
		t.Fatalf("unsigned index: %v", err)
	}

	// Rotation must carry the identity and a re-sealed vault, and boxes for
	// every remaining device.
	next2, _ := identity.NewRandom()
	rot, rotated := a.link(t, chain.TypeUKeyRotate, chain.UKeyRotateBody{EncPub: hex.EncodeToString(next2.Public[:]), SignPub: hex.EncodeToString(next2.SignPublic()), Devices: []string{owner.info.ID}}, a.u.Sign, next2.Sign)
	old := a.u
	a.u = next2
	ownerBox := a.box(t, rotated, owner)
	if _, err := owner.c.Commit(ctx, &wire.Commit{Links: []*envelope.Envelope{rot}, DeviceBoxes: []wire.DeviceBox{ownerBox}, Identity: a.wrapped(t)}); code(err) != wire.ErrInvalidRequest {
		t.Fatalf("rotation without a vault: %v", err)
	}
	badIdentity, _ := identity.Wrapped(old, &a.master, false)
	if _, err := owner.c.Commit(ctx, &wire.Commit{Links: []*envelope.Envelope{rot}, DeviceBoxes: []wire.DeviceBox{ownerBox}, Identity: badIdentity, Vault: a.vault(t, 2, nil)}); code(err) != wire.ErrInvalidRequest {
		t.Fatalf("rotation with the old identity: %v", err)
	}
	if _, err := owner.c.Commit(ctx, &wire.Commit{Links: []*envelope.Envelope{rot}, DeviceBoxes: []wire.DeviceBox{ownerBox}, Identity: a.wrapped(t), Vault: a.vault(t, 2, nil)}); err != nil {
		t.Fatalf("valid rotation: %v", err)
	}
	a.st = rotated
	// The device left out of the rotation is revoked and locked out.
	if _, err := vm.c.Me(ctx); code(err) != wire.ErrUnauthorized && code(err) != wire.ErrDeviceRevoked {
		t.Fatalf("revoked device still has access: %v", err)
	}
	// Reusing a sequence number is a conflict.
	if _, err := owner.c.Commit(ctx, &wire.Commit{Links: []*envelope.Envelope{rot}}); code(err) != wire.ErrConflict {
		t.Fatalf("replayed link: %v", err)
	}
}

func TestSuspendBlocksImmediately(t *testing.T) {
	h := harness(t)
	owner := signIn(t, h, nil, "laptop")
	a := create(t, owner)
	vm := signIn(t, h, nil, "vm")
	a.approve(t, owner, vm)
	ctx := context.Background()
	if err := owner.c.Suspend(ctx, owner.info.ID); code(err) != wire.ErrInvalidRequest {
		t.Fatalf("self-suspend: %v", err)
	}
	if err := owner.c.Suspend(ctx, vm.info.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := vm.c.Vault(ctx); err == nil {
		t.Fatal("suspended device still reads the vault")
	}
	// It cannot sign in again either.
	key := vm.key
	c, reg := register(t, h, key, "vm")
	if err := h.Browser("mscno").Confirm(reg.UserCode, true); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PollToken(ctx, reg.DeviceCode); code(err) != wire.ErrAccessDenied {
		t.Fatalf("suspended device signed in again: %v", err)
	}
}

func TestWebSecurity(t *testing.T) {
	h := harness(t)
	b := h.Browser("mscno")
	// Headers.
	resp, err := http.Get(h.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for _, hdr := range []string{"Content-Security-Policy", "X-Frame-Options", "Referrer-Policy", "X-Content-Type-Options"} {
		if resp.Header.Get(hdr) == "" {
			t.Fatalf("missing %s", hdr)
		}
	}
	// Open redirect attempts land on the account page.
	for _, next := range []string{"https://evil.example", "//evil.example", "/\\evil.example", "javascript:alert(1)"} {
		_, page, err := b.Get("/auth/github?next=" + url.QueryEscape(next))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(page, "Devices") {
			t.Fatalf("next=%q did not land on the account page", next)
		}
	}
	// Forms need the CSRF token.
	status, page, err := b.Get("/account")
	if err != nil || status != http.StatusOK {
		t.Fatalf("account: %d %v", status, err)
	}
	if status, _, _ := b.Post("/auth/logout", "", nil); status != http.StatusForbidden {
		t.Fatalf("logout without CSRF: %d", status)
	}
	if status, _, _ := b.Post("/auth/logout", "wrong", nil); status != http.StatusForbidden {
		t.Fatalf("logout with a wrong CSRF token: %d", status)
	}
	if status, _, _ := b.Post("/auth/logout", servertest.CSRF(page), nil); status != http.StatusOK {
		t.Fatalf("logout: %d", status)
	}
	// The OAuth callback refuses a state that this browser did not start.
	other := h.Browser("mscno")
	status, _, _ = other.Get("/auth/github/callback?code=code-1&state=forged")
	if status != http.StatusBadRequest {
		t.Fatalf("forged OAuth state: %d", status)
	}
}

func TestCodeGuessingIsLimited(t *testing.T) {
	h := harness(t)
	b := h.Browser("mscno")
	_, page, err := b.Get("/device")
	if err != nil {
		t.Fatal(err)
	}
	csrf := servertest.CSRF(page)
	for i := range 10 {
		form := url.Values{"code": {fmt.Sprintf("AAAA-%04d", i)}}
		path := "/device"
		if i%2 == 1 {
			path = "/device/confirm"
			form.Set("decision", "approve")
		}
		if status, _, _ := b.Post(path, csrf, form); status == http.StatusTooManyRequests {
			t.Fatalf("limited after %d wrong codes", i)
		}
	}
	// Both forms now refuse, even for a valid code.
	key, _ := devicekey.Generate()
	_, reg := register(t, h, key, "vm")
	for _, path := range []string{"/device", "/device/confirm"} {
		status, _, _ := b.Post(path, csrf, url.Values{"code": {reg.UserCode}, "decision": {"approve"}})
		if status != http.StatusTooManyRequests {
			t.Fatalf("%s after 10 wrong codes: %d", path, status)
		}
	}
}

func TestStoredKeysAreWriteOnce(t *testing.T) {
	h := harness(t)
	owner := signIn(t, h, nil, "laptop")
	a := create(t, owner)
	vm := signIn(t, h, nil, "vm")
	a.approve(t, owner, vm)
	ctx := context.Background()
	// An existing box cannot be replaced, and the identity cannot be
	// replaced outside a key change.
	if _, err := owner.c.Commit(ctx, &wire.Commit{DeviceBoxes: []wire.DeviceBox{{DeviceID: vm.info.ID, UKeyVersion: 1, Box: []byte("garbage")}}}); code(err) != wire.ErrConflict {
		t.Fatalf("box overwrite: %v", err)
	}
	if _, err := owner.c.Commit(ctx, &wire.Commit{Identity: a.wrapped(t)}); code(err) != wire.ErrInvalidRequest {
		t.Fatalf("identity overwrite: %v", err)
	}
	box, err := vm.c.DeviceBox(ctx)
	if err != nil || string(box.Box) == "garbage" {
		t.Fatalf("box changed: %v", err)
	}
	// Link times far from the server clock are refused.
	e, err := a.st.NewLink(chain.TypeDeviceRename, chain.DeviceRenameBody{DeviceID: vm.info.ID, Name: "future"}, time.Now().Add(48*time.Hour), a.u.Sign)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.c.Commit(ctx, &wire.Commit{Links: []*envelope.Envelope{e}}); code(err) != wire.ErrInvalidRequest {
		t.Fatalf("future link: %v", err)
	}
}

func TestPendingDeviceCap(t *testing.T) {
	h := harness(t)
	owner := signIn(t, h, nil, "laptop")
	create(t, owner)
	for i := range 5 {
		signIn(t, h, nil, fmt.Sprintf("vm%d", i))
	}
	key, _ := devicekey.Generate()
	c, reg := register(t, h, key, "one-too-many")
	if err := h.Browser("mscno").Confirm(reg.UserCode, true); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PollToken(context.Background(), reg.DeviceCode); code(err) != wire.ErrAccessDenied {
		t.Fatalf("sixth pending device: %v", err)
	}
}

func TestDeletedDeviceIsUnauthorized(t *testing.T) {
	h := harness(t)
	d := signIn(t, h, nil, "laptop")
	if _, err := h.DB.SQL().Exec(`DELETE FROM devices WHERE id = ?`, d.info.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.c.Me(context.Background()); code(err) != wire.ErrUnauthorized {
		t.Fatalf("deleted device: %v", err)
	}
}
