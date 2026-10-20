package passkey_test

import (
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/passkey"
	"github.com/mscno/esec-vault/internal/passkey/passkeytest"
)

func TestVerify(t *testing.T) {
	pk := passkeytest.New("vault.example", "https://vault.example")
	d := pk.Delegate("dl_test00001", "key", chain.ScopeManage, time.Now())
	challenge := sha256.Sum256([]byte("a link"))
	if err := passkey.Verify(pk.Assert(challenge[:]), &d, challenge[:]); err != nil {
		t.Fatalf("valid: %v", err)
	}
	other := sha256.Sum256([]byte("another link"))
	cases := map[string]func() error{
		"other challenge": func() error { return passkey.Verify(pk.Assert(other[:]), &d, challenge[:]) },
		"other key": func() error {
			k := passkeytest.New("vault.example", "https://vault.example")
			k.CredID = pk.CredID
			return passkey.Verify(k.Assert(challenge[:]), &d, challenge[:])
		},
		"other credential": func() error {
			a := pk.Assert(challenge[:])
			a.CredentialID = []byte("x")
			return passkey.Verify(a, &d, challenge[:])
		},
		"tampered data": func() error {
			a := pk.Assert(challenge[:])
			a.AuthenticatorData[33] ^= 1
			return passkey.Verify(a, &d, challenge[:])
		},
		"create, not get": func() error {
			a := pk.Assert(challenge[:])
			a.ClientDataJSON = []byte(strings.Replace(string(a.ClientDataJSON), "webauthn.get", "webauthn.create", 1))
			return passkey.Verify(a, &d, challenge[:])
		},
		"no one present": func() error {
			k := *pk
			k.Flags = 0x04
			return passkey.Verify(k.Assert(challenge[:]), &d, challenge[:])
		},
		"other site": func() error {
			k := *pk
			k.RPID = "evil.example"
			return passkey.Verify(k.Assert(challenge[:]), &d, challenge[:])
		},
		"other origin": func() error {
			k := *pk
			k.Origin = "https://evil.example"
			return passkey.Verify(k.Assert(challenge[:]), &d, challenge[:])
		},
	}
	for name, f := range cases {
		if f() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if !passkey.UserVerified(pk.Assert(challenge[:])) {
		t.Error("user verification flag")
	}
}
