package guard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	coreseal "github.com/mscno/esec/pkg/seal"
)

// A seal made for a stand-in security key opens through Presence, with no
// dialog for software stand-ins; a denied dialog opens nothing.
func TestOpenSealWithStandIn(t *testing.T) {
	key, _ := age.GenerateX25519Identity()
	file := filepath.Join(t.TempDir(), "ids.txt")
	if err := os.WriteFile(file, []byte(key.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(IdentitiesEnv, file)
	recips, err := StandInRecipients()
	if err != nil || len(recips) != 1 || recips[0] != key.Recipient().String() {
		t.Fatalf("stand-ins: %v %v", recips, err)
	}
	priv := "1111111111111111111111111111111111111111111111111111111111111111"
	pub, _ := coreseal.PublicHex(priv)
	data, err := coreseal.Seal(coreseal.Payload{Project: "acme/store", Env: "prod", Guard: "session", Private: priv}, key.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	asked := 0
	p := Presence{Ask: func(string, string) (bool, error) { asked++; return false, nil }, Note: func(string) {}, Secret: func(string) (string, error) { return "", nil }}
	got, err := p.OpenSeal(data, "acme/store", "prod", pub, recips, "t", "x")
	if err != nil || got.Private != priv || got.Guard != "session" || asked != 0 {
		t.Fatalf("open: %+v %v (asked %d)", got, err, asked)
	}
	if _, err := p.OpenSeal(data, "acme/store", "dev", pub, recips, "t", "x"); err == nil {
		t.Fatal("a prod seal opened as dev")
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
