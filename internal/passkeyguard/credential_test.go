package passkeyguard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"filippo.io/age"
)

func fakeCredential(t *testing.T, id byte, prf []byte) Credential {
	t.Helper()
	previous := Native
	Native = func(context.Context, Request) (Response, error) {
		return Response{CredentialID: bytes.Repeat([]byte{id}, 32), PRF: bytes.Clone(prf)}, nil
	}
	t.Cleanup(func() { Native = previous })
	c, err := Enroll(context.Background(), "vault.example.com", "test", "platform")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPasskeyEncryptionRequiresSamePRFAndMetadata(t *testing.T) {
	prf := bytes.Repeat([]byte{7}, 32)
	c := fakeCredential(t, 1, prf)
	encoded := c.EncodeRecipient()
	parsed, err := ParseRecipient(encoded)
	if err != nil {
		t.Fatal(err)
	}
	id, err := parsed.open(prf)
	if err != nil {
		t.Fatal(err)
	}
	if x, ok := id.(*age.X25519Identity); !ok || x.Recipient().String() != c.Recipient {
		t.Fatal("public key changed")
	}
	for _, change := range []func(*Credential){
		func(c *Credential) { c.RPID = "other.example.com" },
		func(c *Credential) { c.ID = bytes.Repeat([]byte{2}, 32) },
		func(c *Credential) { c.Salt = bytes.Repeat([]byte{3}, 32) },
		func(c *Credential) { c.Wrapped = bytes.Clone(c.Wrapped); c.Wrapped[len(c.Wrapped)-1] ^= 1 },
	} {
		changed := c
		change(&changed)
		if _, err := changed.open(prf); err == nil {
			t.Fatal("modified credential decrypted")
		}
	}
	if _, err := c.open(bytes.Repeat([]byte{9}, 32)); err == nil {
		t.Fatal("another passkey decrypted")
	}
	if _, err := c.open(nil); err == nil {
		t.Fatal("missing PRF accepted")
	}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data[:len(data)-1], []byte(`,"unknown":true}`)...)
	if _, err := Decode(data); err == nil {
		t.Fatal("unknown credential format accepted")
	}
}

func TestNativeChooserOpensOnlySelectedCredentialOnce(t *testing.T) {
	firstPRF, secondPRF := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	first, second := fakeCredential(t, 1, firstPRF), fakeCredential(t, 2, secondPRF)
	var encrypted bytes.Buffer
	w, err := age.Encrypt(&encrypted, recipient{first}, recipient{second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("synthetic test data")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	calls := 0
	Native = func(_ context.Context, request Request) (Response, error) {
		calls++
		if request.Operation != "assert" || len(request.Credentials) != 2 {
			t.Fatalf("not a combined chooser: %+v", request)
		}
		return Response{CredentialID: second.ID, PRF: bytes.Clone(secondPRF)}, nil
	}
	i := &identities{credentials: []Credential{first, second}}
	r, err := age.Decrypt(bytes.NewReader(encrypted.Bytes()), i)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := out.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	if out.String() != "synthetic test data" || calls != 1 {
		t.Fatalf("output %q, prompts %d", out.String(), calls)
	}
	// A cancellation must not fall back to the other registered credential
	// and produce a second sheet.
	Native = func(context.Context, Request) (Response, error) { calls++; return Response{}, errors.New("cancelled") }
	i = &identities{credentials: []Credential{first, second}}
	if _, err := age.Decrypt(bytes.NewReader(encrypted.Bytes()), i, i); err == nil {
		t.Fatal("cancelled sheet decrypted")
	}
	if calls != 2 {
		t.Fatalf("cancelled sheet reopened: %d calls", calls)
	}
}

func TestEnrollmentRejectsProviderWithoutPRF(t *testing.T) {
	previous := Native
	t.Cleanup(func() { Native = previous })
	Native = func(context.Context, Request) (Response, error) { return Response{CredentialID: []byte("id")}, nil }
	if _, err := Enroll(context.Background(), "vault.example.com", "test", "platform"); err == nil {
		t.Fatal("a non-encrypting passkey was enrolled")
	}
}
