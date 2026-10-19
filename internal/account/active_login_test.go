package account_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mscno/esec/pkg/secretstore"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/ukey"
	"github.com/mscno/esec-vault/internal/vaultfile"
	"github.com/mscno/esec-vault/internal/wire"
)

type lieUI struct {
	mu           sync.Mutex
	out          strings.Builder
	confirms     []string
	secretsAsked []string
}

func (u *lieUI) Printf(f string, a ...any) { u.mu.Lock(); fmt.Fprintf(&u.out, f, a...); u.mu.Unlock() }
func (u *lieUI) Confirm(q string) bool {
	u.mu.Lock()
	u.confirms = append(u.confirms, q)
	u.mu.Unlock()
	return true
}
func (u *lieUI) Secret(l string) (string, error) {
	u.mu.Lock()
	u.secretsAsked = append(u.secretsAsked, l)
	u.mu.Unlock()
	return "", fmt.Errorf("no secret")
}

// A server that answers 'login --recover' with "device active" and a chain
// it forged around the user's public master key must still face the phrase.
func TestLoginActiveDeviceRecoverChecksPhrase(t *testing.T) { runActiveLie(t, false) }

// A machine with the user's identity must still refuse an account made with
// another recovery phrase when the server claims the device is active.
func TestLoginActiveDeviceChecksOwnIdentity(t *testing.T) { runActiveLie(t, true) }

func runActiveLie(t *testing.T, ownIdentity bool) { //nolint:gocyclo // one fake server handling every endpoint
	// The user's real phrase and master key (made on some other machine).
	t.Setenv(secretstore.EnvBackend, secretstore.BackendFile)
	t.Setenv("ESEC_KEYRING_DIR", "")
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	initKR := keyring.Keyring(keyring.NewMemory())
	if ownIdentity {
		initKR = keyring.NewOS()
	}
	mnemonic, err := identity.Init(initKR, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ownIdentity {
		if err := keystore.New().Write("acme/store", map[string]string{"ESEC_PRIVATE_KEY_PROD": strings.Repeat("cd", 32)}, false); err != nil {
			t.Fatal(err)
		}
	}
	realKeys, _ := identity.DeriveMasterKeys(mnemonic, "")

	// The fresh recovering machine.
	if !ownIdentity {
		t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	}

	const user = "gh:53101343"
	const devID = "d_activelie000000"
	created := time.Now().UTC().Truncate(time.Second)
	evil, _ := identity.NewRandom()
	_, evilMasterSign, _ := ed25519.GenerateKey(nil)

	var mu sync.Mutex
	attempt := 0
	var proof *envelope.Envelope
	var reg wire.DeviceRegisterRequest
	recoveryCalls := 0
	var stolen map[string]map[string]string

	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		reply := func(v any) { w.Header().Set("Content-Type", "application/json"); _ = json.NewEncoder(w).Encode(v) }
		switch r.URL.Path {
		case "/v1/auth/device":
			attempt++
			_ = json.NewDecoder(r.Body).Decode(&reg)
			reply(wire.DeviceRegisterResponse{DeviceID: devID, DeviceCreated: created, DeviceCode: "dc", UserCode: "ABCD-EFGH", VerificationURI: base + "/device", ExpiresIn: 600})
		case "/v1/auth/token":
			status := wire.DevicePending
			if attempt > 1 {
				status = wire.DeviceActive // the lie
			}
			reply(wire.TokenResponse{SessionToken: "tok", User: wire.User{ID: user, GitHubID: 53101343, Login: "mscno"},
				Device: wire.DeviceInfo{ID: devID, Name: "vm", Platform: runtime.GOOS + "/" + runtime.GOARCH, EncPub: reg.EncPub, SignPub: reg.SignPub, Status: status, Created: created}})
		case "/v1/devices/self/proof":
			var up wire.DeviceProofUpload
			_ = json.NewDecoder(r.Body).Decode(&up)
			proof = up.Proof
			reply(struct{}{})
		case "/v1/me":
			reply(wire.Me{User: wire.User{ID: user, GitHubID: 53101343}, Device: wire.DeviceInfo{ID: devID, Status: wire.DevicePending}, ChainSeq: 2})
		case "/v1/recovery":
			recoveryCalls++
			w.WriteHeader(http.StatusInternalServerError)
			reply(wire.Error{Code: wire.ErrInternal, Description: "temporarily unavailable, try again"})
		case "/v1/chain":
			st := chain.New(user)
			l1, _ := st.NewLink(chain.TypeInit, chain.NewInitBody(evil.Public, evil.SignPublic(), realKeys.Public, evilMasterSign), created, evil.Sign)
			st1, err := st.Next(l1)
			if err != nil {
				t.Error(err)
			}
			pd, _ := chain.VerifyProof(proof)
			l2, _ := st1.NewLink(chain.TypeDeviceAdd, chain.DeviceAddBody{Device: pd.Device, Proof: *proof, Method: chain.MethodFirst}, created, evil.Sign)
			reply(wire.Chain{Links: []*envelope.Envelope{l1, l2}})
		case "/v1/devices/self/box":
			m, _ := ukey.FromIdentity(user, 1, evil)
			pub, _ := chain.ParseKey32(reg.EncPub)
			box, _ := ukey.SealToDevice(m, pub)
			reply(wire.DeviceBox{DeviceID: devID, UKeyVersion: 1, Box: box})
		case "/v1/vault":
			if r.Method == http.MethodPut {
				var put wire.VaultPut
				_ = json.NewDecoder(r.Body).Decode(&put)
				if v, err := vaultfile.Open(put.Blob, &evil.Public, &evil.Private); err == nil {
					stolen = v.Projects
				}
				reply(wire.Vault{Version: 1})
				return
			}
			w.WriteHeader(http.StatusNotFound)
			reply(wire.Error{Code: wire.ErrNotFound})
		case "/v1/identity":
			blob, _ := identity.Wrapped(evil, &realKeys.Public, false)
			reply(wire.IdentityBlob{UKeyVersion: 1, Blob: blob})
		default:
			w.WriteHeader(http.StatusNotFound)
			reply(wire.Error{Code: wire.ErrNotFound})
		}
	}))
	defer srv.Close()
	base = strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)

	kr := keyring.NewOS()
	opts := account.LoginOptions{Server: base, Name: "vm", Method: account.LoginRecover, Mnemonic: mnemonic, Poll: 20 * time.Millisecond}
	if ownIdentity {
		opts = account.LoginOptions{Server: base, Name: "vm", Method: account.LoginApproval, Poll: 20 * time.Millisecond}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Attempt 1: the server collects the device proof, then fails recovery.
	if _, err := account.Login(ctx, kr, &lieUI{}, opts); err == nil {
		t.Fatal("first attempt unexpectedly succeeded")
	}
	// Attempt 2: the user retries, and the server now claims the device is
	// already active. Login must still demand the proof the user asked for.
	ui2 := &lieUI{}
	if _, err := account.Login(ctx, kr, ui2, opts); err == nil {
		t.Fatal("login trusted a device the server claims is active without proof")
	}
	if len(ui2.confirms) != 0 {
		t.Errorf("login asked %q instead of refusing", ui2.confirms)
	}
	if id, err := identity.Load(kr); err == nil && id.Public == evil.Public {
		t.Error("login installed the server's user key")
	}
	if _, err := account.LoadState(); err == nil {
		t.Error("login kept the refused account's record")
	}
	mu.Lock()
	defer mu.Unlock()
	if stolen != nil {
		t.Errorf("the server decrypted pushed keyrings: %v", stolen)
	}
}
