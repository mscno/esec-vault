package ukey

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/identity"
)

func state(t *testing.T, id *identity.Identity) *chain.State {
	t.Helper()
	s := chain.New("gh:1")
	_, ms, _ := ed25519.GenerateKey(rand.Reader)
	e, err := s.NewLink(chain.TypeInit, chain.NewInitBody(id.Public, id.SignPublic(), [32]byte{7}, ms), time.Now(), id.Sign)
	if err != nil {
		t.Fatal(err)
	}
	n, err := s.Next(e)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestDeviceBox(t *testing.T) {
	id, _ := identity.NewRandom()
	st := state(t, id)
	m, err := FromIdentity("gh:1", 1, id)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := box.GenerateKey(rand.Reader)
	sealed, err := SealToDevice(m, *pub)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenDeviceBox(sealed, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	back, err := got.Check(st)
	if err != nil || back.Public != id.Public {
		t.Fatalf("check: %v", err)
	}
	// A box with a key the chain does not name is refused, even though it
	// opens: anyone can seal to a device's public key.
	other, _ := identity.NewRandom()
	fake, _ := FromIdentity("gh:1", 1, other)
	if _, err := fake.Check(st); err == nil {
		t.Fatal("foreign user key accepted")
	}
	wrongVersion := *m
	wrongVersion.UKeyVersion = 2
	if _, err := wrongVersion.Check(st); err == nil {
		t.Fatal("wrong version accepted")
	}
	wrongUser := *m
	wrongUser.User = "gh:2"
	if _, err := wrongUser.Check(st); err == nil {
		t.Fatal("wrong user accepted")
	}
	pub2, priv2, _ := box.GenerateKey(rand.Reader)
	if _, err := OpenDeviceBox(sealed, pub2, priv2); err == nil {
		t.Fatal("box opened by another device")
	}
}

func TestSlotBox(t *testing.T) {
	id, _ := identity.NewRandom()
	m, _ := FromIdentity("gh:1", 1, id)
	salt := bytes.Repeat([]byte{1}, 32)
	kek, err := SlotKEK([]byte("signature"), salt)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := SealSlot(m, kek, "gh:1", "s_aaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSlot(sealed, kek, "gh:1", "s_aaaaaaaa"); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSlot(sealed, kek, "gh:1", "s_bbbbbbbb"); err == nil {
		t.Fatal("slot box opened under another slot id")
	}
	if _, err := OpenSlot(sealed, kek, "gh:2", "s_aaaaaaaa"); err == nil {
		t.Fatal("slot box opened for another user")
	}
	other, _ := SlotKEK([]byte("other signature"), salt)
	if _, err := OpenSlot(sealed, other, "gh:1", "s_aaaaaaaa"); err == nil {
		t.Fatal("slot box opened with another signature")
	}
	if _, err := SlotKEK([]byte("sig"), []byte("short")); err == nil {
		t.Fatal("short salt accepted")
	}
	if bytes.Equal(SlotChallenge("gh:1", "s_a", salt), SlotChallenge("gh:1", "s_b", salt)) {
		t.Fatal("challenges must differ per slot")
	}
}
