package guard

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"
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

// yubikeyRecipient is an age1yubikey1… recipient for a made-up compressed
// point: the stub only hashes it.
func yubikeyRecipient(fill byte) (string, []byte) {
	point := append([]byte{0x02}, bytes.Repeat([]byte{fill}, 32)...)
	return plugin.EncodeRecipient("yubikey", point), point
}

// A stub is what age-plugin-yubikey's Stub::to_bytes writes: the serial
// little-endian, the retired PIV slot (R1 = 0x82) and the first four bytes
// of the SHA-256 of the recipient's point. The plugin refuses an identity
// without them ("Invalid YubiKey stub").
func TestYubiKeyStub(t *testing.T) {
	recipient, point := yubikeyRecipient(7)
	tag := sha256.Sum256(point)
	notYubiKey := plugin.EncodeRecipient("se", point)
	for slot, want := range map[string]byte{"1": 0x82, "": 0x82, "20": 0x95} {
		stub, err := YubiKeyStub("15584441", slot, recipient)
		if err != nil {
			t.Fatal(err)
		}
		name, data, err := plugin.ParseIdentity(stub)
		if err != nil || name != "yubikey" {
			t.Fatalf("slot %q: %s is not a yubikey identity: %v", slot, stub, err)
		}
		wantData := append([]byte{0xb9, 0xcc, 0xed, 0x00, want}, tag[:4]...)
		if !bytes.Equal(data, wantData) {
			t.Fatalf("slot %q: stub data %x, want %x", slot, data, wantData)
		}
	}
	for _, bad := range [][3]string{
		{"15584441", "0", recipient},
		{"15584441", "21", recipient},
		{"serial", "1", recipient},
		{"15584441", "1", notYubiKey},
	} {
		if _, err := YubiKeyStub(bad[0], bad[1], bad[2]); err == nil {
			t.Errorf("YubiKeyStub%q made a stub", bad)
		}
	}
}

// fakeYubiKeyPlugin puts an age-plugin-yubikey on PATH whose --list shows
// the YubiKey slots in list.
func fakeYubiKeyPlugin(t *testing.T, list string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake plugin is a shell script")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\ncat <<'EOF'\n" + list + "EOF\n"
	if err := os.WriteFile(filepath.Join(dir, "age-plugin-yubikey"), []byte(script), 0o755); err != nil { //nolint:gosec // an executable test fixture
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv(IdentitiesEnv, "")
}

// A seal's YubiKey readers are opened with the stubs of the YubiKeys
// plugged in, never with an identity that names no key.
func TestIdentitiesUsesPluggedInYubiKeys(t *testing.T) {
	mine, _ := yubikeyRecipient(1)
	theirs, _ := yubikeyRecipient(2)
	recovery, _ := age.GenerateX25519Identity()
	fakeYubiKeyPlugin(t, "#       Serial: 15584441, Slot: 2\n#         Name: age identity 1a2b3c4d\n# Touch policy: Always (A physical touch is required for every decryption)\n"+mine+"\n")

	ids, err := Identities([]string{recovery.Recipient().String(), theirs, mine}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want, err := YubiKeyStub("15584441", "2", mine)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Fatalf("identities %v, want only %s", ids, want)
	}
	if id, ok := ids[0].(*plugin.Identity); !ok || id.String() != want {
		t.Fatalf("identity %v, want %s", ids[0], want)
	}

	if _, err := Identities([]string{theirs}, nil); err == nil || !strings.Contains(err.Error(), "no YubiKey plugged in opens this seal") {
		t.Fatalf("a seal for someone else's YubiKey: %v", err)
	}
}

// fakeSEPlugin puts an age-plugin-se on PATH beside the fake YubiKey one.
func fakeSEPlugin(t *testing.T) string {
	t.Helper()
	dir := filepath.SplitList(os.Getenv("PATH"))[0]
	if err := os.WriteFile(filepath.Join(dir, "age-plugin-se"), []byte("#!/bin/sh\n"), 0o755); err != nil { //nolint:gosec // an executable test fixture
		t.Fatal(err)
	}
	return plugin.EncodeRecipient("se", append([]byte{0x02}, bytes.Repeat([]byte{3}, 32)...))
}

// A seal read by someone's Secure Enclave and a colleague's YubiKey still
// opens with the Secure Enclave when no YubiKey of the seal is plugged in.
func TestIdentitiesKeepsOtherPluginsWithoutYubiKey(t *testing.T) {
	fakeYubiKeyPlugin(t, "")
	se := fakeSEPlugin(t)
	colleague, _ := yubikeyRecipient(9)
	ids, err := Identities([]string{se, colleague}, nil)
	if err != nil {
		t.Fatalf("the Secure Enclave reader was dropped: %v", err)
	}
	if id, ok := ids[0].(*plugin.Identity); len(ids) != 1 || !ok || id.Name() != "se" {
		t.Fatalf("identities %v, want the Secure Enclave one", ids)
	}
	// Nothing here opens it: say why for each plugin.
	if _, err := Identities([]string{colleague}, nil); err == nil || !strings.Contains(err.Error(), "no YubiKey plugged in") {
		t.Fatalf("a seal nothing here opens: %v", err)
	}
}

// A YubiKey slot that never asks for a touch does not open a guarded seal;
// one that keeps a touch for a while does, and the dialog says so.
func TestIdentitiesTouchPolicy(t *testing.T) {
	mine, _ := yubikeyRecipient(1)
	slot := func(policy string) string {
		return "#       Serial: 15584441, Slot: 1\n# Touch policy: " + policy + " (…)\n" + mine + "\n"
	}
	fakeYubiKeyPlugin(t, slot("Never"))
	if _, _, err := identities([]string{mine}, nil); err == nil || !strings.Contains(err.Error(), "touch policy Never") {
		t.Fatalf("a slot that never asks for a touch: %v", err)
	}
	fakeYubiKeyPlugin(t, slot("Cached"))
	ids, cautions, err := identities([]string{mine}, nil)
	if err != nil || len(ids) != 1 {
		t.Fatalf("cached slot: %v %v", ids, err)
	}
	if len(cautions) != 1 || !strings.Contains(cautions[0], "15584441") || !strings.Contains(cautions[0], "security-keys setup") {
		t.Fatalf("cautions %q", cautions)
	}
	fakeYubiKeyPlugin(t, slot("Always"))
	if _, cautions, err := identities([]string{mine}, nil); err != nil || len(cautions) != 0 {
		t.Fatalf("always slot: %q %v", cautions, err)
	}
}
