package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/securitykey"
)

const testYubiKeys = `#       Serial: 15584441, Slot: 1
#         Name: age identity 1a2b3c4d
#   PIN policy: Once   (A PIN is required once per session, if set)
# Touch policy: Always (A physical touch is required for every decryption)
age1yubikey1qf28gwqh38gcsqlukuyk0vpae0lw26dvt05rvm7k0y2t90367cunzs00yyk
#       Serial: 20010203, Slot: 1
#         Name: age identity 99887766
# Touch policy: Cached (A physical touch is required for decryption, and is cached for 15 seconds)
age1yubikey1q2w7u8yr34sh7rkqpl3t4h0k5jwy7lms8sv3t6mjxxa5nrzzm4nynmjcrv3
`

func fakeYubiKeys(t *testing.T, list string) {
	t.Helper()
	prev := securitykey.Run
	securitykey.Run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		switch name + " " + strings.Join(args, " ") {
		case "age-plugin-yubikey --list":
			return []byte(list), nil
		case "ykman list --serials":
			return []byte("15584441\n20010203\n31415926\n"), nil
		}
		return nil, errors.New("unexpected command")
	}
	t.Cleanup(func() { securitykey.Run = prev })
}

// stdoutOfRun captures what fn prints on stdout.
func stdoutOfRun(t *testing.T, fn func() error) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	runErr := fn()
	os.Stdout = saved
	w.Close()
	out, _ := io.ReadAll(r)
	if runErr != nil {
		t.Fatalf("%v\n%s", runErr, out)
	}
	return string(out)
}

func TestSecurityKeysWithoutAccount(t *testing.T) { //nolint:gocyclo // one story, step by step
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv("ESEC_SECRET_STORE", "file")
	fakeYubiKeys(t, testYubiKeys)
	ctx := &cliCtx{Keyring: keyring.NewMemory()}
	changed := 0
	prev := securityKeysChanged
	securityKeysChanged = func(*cliCtx) error { changed++; return nil }
	t.Cleanup(func() { securityKeysChanged = prev })

	// Nothing registered: both plugged-in keys are offered, and the
	// YubiKey without an age identity is pointed at setup.
	var v securityKeysView
	if err := json.Unmarshal([]byte(stdoutOfRun(t, func() error { return (&SecurityKeysListCmd{JSON: true}).Run(ctx) })), &v); err != nil {
		t.Fatal(err)
	}
	if v.Source != "local" || len(v.Keys) != 0 || len(v.Unregistered) != 2 || v.Unregistered[0].Command == "" || len(v.Unprovisioned) != 1 || v.Unprovisioned[0] != "31415926" {
		t.Fatalf("list: %+v", v)
	}

	// --name names one key only.
	if err := (&SecurityKeysAddCmd{Name: "blue"}).Run(ctx); err == nil {
		t.Fatal("one name was given to two keys")
	}
	first, _, _ := strings.Cut(testYubiKeys, "#       Serial: 20010203")
	fakeYubiKeys(t, first)
	stdoutOfRun(t, func() error { return (&SecurityKeysAddCmd{Name: "blue"}).Run(ctx) })
	fakeYubiKeys(t, testYubiKeys)
	stdoutOfRun(t, func() error { return (&SecurityKeysAddCmd{}).Run(ctx) })
	if changed != 2 {
		t.Fatalf("reseal hook ran %d times", changed)
	}
	if err := json.Unmarshal([]byte(stdoutOfRun(t, func() error { return (&SecurityKeysListCmd{JSON: true}).Run(ctx) })), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Keys) != 2 || len(v.Unregistered) != 0 || !v.Keys[0].PluggedIn || v.Keys[0].Name != "YubiKey 20010203" || v.Keys[1].Name != "blue" {
		t.Fatalf("after add: %+v", v.Keys)
	}
	if out := stdoutOfRun(t, func() error { return (&SecurityKeysAddCmd{}).Run(ctx) }); !strings.Contains(out, "registered already") {
		t.Fatalf("add again: %s", out)
	}

	// Test records when a key last decrypted.
	prevTest := testDecrypt
	testDecrypt = func(chain.SecurityKey) error { return nil }
	t.Cleanup(func() { testDecrypt = prevTest })
	stdoutOfRun(t, func() error { return (&SecurityKeysTestCmd{Key: "blue"}).Run(ctx) })
	reg, _ := securitykey.Load()
	if e, ok := reg.Find("blue"); !ok || e.Tested.IsZero() {
		t.Fatalf("tested not recorded: %+v", reg)
	}

	// Remove by name.
	stdoutOfRun(t, func() error { return (&SecurityKeysRemoveCmd{Key: "blue"}).Run(ctx) })
	reg, _ = securitykey.Load()
	if len(reg.Keys) != 1 || changed != 3 {
		t.Fatalf("after remove: %+v (%d)", reg.Keys, changed)
	}
	if err := (&SecurityKeysRemoveCmd{Key: "nope"}).Run(ctx); err == nil {
		t.Fatal("removed a key that is not there")
	}
}

func TestManualSecurityKey(t *testing.T) {
	k := manualKey("yubikey", "age1yubikey1qf28gwqh38gcsqlukuyk0vpae0lw26dvt05rvm7k0y2t90367cunzs00yyk", "", "15584441")
	if k.ID != "yubikey:15584441:1" || k.Name != "YubiKey" || chain.ValidateSecurityKey(k) != nil {
		t.Fatalf("%+v %v", k, chain.ValidateSecurityKey(k))
	}
	k = manualKey("se", "age1se1qgjq3xyz0tkqqsdlhlj2c9j0frwxgnusw3jzk0fpmwsvxtwq0qkhg6w3cm", "Touch ID", "")
	if !strings.HasPrefix(k.ID, "se:") || chain.ValidateSecurityKey(k) != nil {
		t.Fatalf("%+v %v", k, chain.ValidateSecurityKey(k))
	}
}
