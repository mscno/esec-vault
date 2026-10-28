package guard

import (
	"crypto/rand"
	"strings"
	"testing"

	"filippo.io/age"
	"golang.org/x/crypto/curve25519"

	"github.com/mscno/esec"
	"github.com/mscno/esec-vault/internal/keystore"
)

func TestBech32MatchesAge(t *testing.T) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	s, err := X25519IdentityString(priv)
	if err != nil {
		t.Fatal(err)
	}
	id, err := age.ParseX25519Identity(s)
	if err != nil {
		t.Fatalf("age rejects %s: %v", s, err)
	}
	pubRaw, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	var pub [32]byte
	copy(pub[:], pubRaw)
	r, err := X25519Recipient(pub)
	if err != nil {
		t.Fatal(err)
	}
	if r != id.Recipient().String() {
		t.Fatalf("recipient %s, age says %s", r, id.Recipient())
	}
}

func TestGuardRoundTrip(t *testing.T) {
	yubi, _ := age.GenerateX25519Identity()  // stands in for a hardware holder
	spare, _ := age.GenerateX25519Identity() // the recovery key
	g, guardID, err := New([]string{yubi.Recipient().String(), spare.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	back, err := FromEntries(g.Entries())
	if err != nil || len(back.Holders) != 2 || back.Recipient != guardID.Recipient().String() {
		t.Fatalf("entries: %+v %v", back, err)
	}
	// Either holder opens it; a stranger does not.
	for _, holder := range []*age.X25519Identity{yubi, spare} {
		if id, err := back.Open(holder); err != nil || id.String() != guardID.String() {
			t.Fatalf("holder could not open: %v", err)
		}
	}
	stranger, _ := age.GenerateX25519Identity()
	if _, err := back.Open(stranger); err == nil {
		t.Fatal("a stranger opened the guard")
	}

	pub, priv, _ := esec.GenerateKeypair()
	value, err := Wrap(guardID.Recipient(), Key{Project: "acme/store", Env: "prod", Level: "touch", Private: priv})
	if err != nil {
		t.Fatal(err)
	}
	k, err := Unwrap(guardID, value, pub, keystore.PublicHex)
	if err != nil || k.Private != priv || k.Level != "touch" || k.Env != "prod" {
		t.Fatalf("unwrap: %+v %v", k, err)
	}
	// Filed under another public key, it is refused.
	other, _, _ := esec.GenerateKeypair()
	if _, err := Unwrap(guardID, value, other, keystore.PublicHex); err == nil {
		t.Fatal("accepted a guarded key under the wrong public key")
	}

	// Rewrapping drops a holder.
	g2, err := Rewrap(guardID, []string{spare.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g2.Open(yubi); err == nil {
		t.Fatal("a removed holder still opens the guard")
	}
}

func TestPluginName(t *testing.T) {
	for in, want := range map[string]string{
		"age1yubikey1qwerty":   "yubikey",
		"age1se1qwerty":        "se",
		"age1qyqszqgpqyqszqgp": "",
	} {
		if got := PluginName(in); got != want {
			t.Errorf("PluginName(%s) = %q, want %q", in, got, want)
		}
	}
	if _, err := ParseIdentities("# nothing\n", nil); err == nil || !strings.Contains(err.Error(), "no age identity") {
		t.Fatalf("empty identities: %v", err)
	}
}
