package securitykey

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/mscno/esec-vault/internal/chain"
)

const yk1 = "age1yubikey1qf28gwqh38gcsqlukuyk0vpae0lw26dvt05rvm7k0y2t90367cunzs00yyk"
const yk2 = "age1yubikey1q2w7u8yr34sh7rkqpl3t4h0k5jwy7lms8sv3t6mjxxa5nrzzm4nynmjcrv3"

const listOutput = `#       Serial: 15584441, Slot: 1
#         Name: age identity 1a2b3c4d
#      Created: Sun, 18 Apr 2021 10:20:43 +0000
#   PIN policy: Once   (A PIN is required once per session, if set)
# Touch policy: Always (A physical touch is required for every decryption)
` + yk1 + `

#       Serial: 20010203, Slot: 2
#         Name: esec spare
#      Created: Mon, 19 Apr 2021 10:20:43 +0000
#   PIN policy: Once   (A PIN is required once per session, if set)
# Touch policy: Cached (A physical touch is required for decryption, and is cached for 15 seconds)
` + yk2 + `
`

func TestParse(t *testing.T) {
	got, err := Parse(listOutput)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("found %d", len(got))
	}
	a, b := got[0], got[1]
	if a.Serial != "15584441" || a.Slot != "1" || a.Name != "age identity 1a2b3c4d" || a.Recipient != yk1 || a.PINPolicy != "Once" || !a.TouchAlways() {
		t.Fatalf("first: %+v", a)
	}
	if b.Serial != "20010203" || b.Slot != "2" || b.TouchPolicy != "Cached" || b.TouchAlways() {
		t.Fatalf("second: %+v", b)
	}
	k := FromDetected(a, "")
	if k.ID != "yubikey:15584441:1" || k.Name != "YubiKey 15584441" || chain.ValidateSecurityKey(k) != nil {
		t.Fatalf("key: %+v %v", k, chain.ValidateSecurityKey(k))
	}
	if none, _ := Parse("no keys here\n"); len(none) != 0 {
		t.Fatal("found keys in nothing")
	}
}

func fakeRun(t *testing.T, outputs map[string]string) {
	t.Helper()
	prev := Run
	Run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		cmd := name + " " + strings.Join(args, " ")
		out, ok := outputs[cmd]
		if !ok {
			if name == "age-plugin-yubikey" {
				return nil, ErrNoPlugin
			}
			return nil, errors.New("not found: " + name)
		}
		return []byte(out), nil
	}
	t.Cleanup(func() { Run = prev })
}

func TestDetect(t *testing.T) {
	fakeRun(t, map[string]string{
		"age-plugin-yubikey --list": listOutput,
		"ykman list --serials":      "15584441\n20010203\n31415926\n",
	})
	got, err := Detect(context.Background())
	if err != nil || len(got) != 2 {
		t.Fatalf("%v %v", got, err)
	}
	none, err := DetectUnprovisioned(context.Background())
	if err != nil || len(none) != 1 || none[0] != "31415926" {
		t.Fatalf("unprovisioned: %v %v", none, err)
	}

	fakeRun(t, map[string]string{})
	if _, err := Detect(context.Background()); !errors.Is(err, ErrNoPlugin) || !strings.Contains(err.Error(), "brew install") {
		t.Fatalf("missing plugin: %v", err)
	}
	if none, err := DetectUnprovisioned(context.Background()); none != nil || err != nil {
		t.Fatalf("no ykman: %v %v", none, err)
	}
}

func TestRegistry(t *testing.T) { //nolint:gocyclo // one story, step by step
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	r, err := Load()
	if err != nil || r.Source != "local" || len(r.Keys) != 0 {
		t.Fatalf("empty: %+v %v", r, err)
	}
	ds, _ := Parse(listOutput)
	if err := r.Add(FromDetected(ds[0], "blue")); err != nil {
		t.Fatal(err)
	}
	if err := r.Add(FromDetected(ds[1], "spare")); err != nil {
		t.Fatal(err)
	}
	if err := r.Add(chain.SecurityKey{ID: "x", Kind: "yubikey", Recipient: "age1notahardwarekey", Name: "bad"}); err == nil {
		t.Fatal("an invalid key was added")
	}
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(File())
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode: %v %v", info, err)
	}
	r, _ = Load()
	if e, ok := r.Find("BLUE"); !ok || e.Recipient != yk1 {
		t.Fatalf("find by name: %+v", e)
	}
	if e, ok := r.Find("yubikey:20010203:2"); !ok || e.Name != "spare" {
		t.Fatalf("find by id: %+v", e)
	}
	if !r.Has(yk2) || !r.Remove("spare") || r.Has(yk2) {
		t.Fatal("remove")
	}

	// The account's list replaces the local one, keeping test times.
	r.Keys[0].Tested = r.Keys[0].Tested.AddDate(2026, 0, 0)
	tested := r.Keys[0].Tested
	r.Refresh([]chain.SecurityKey{FromDetected(ds[0], "blue (account)"), FromDetected(ds[1], "spare")})
	if r.Source != "account" || len(r.Keys) != 2 || r.Keys[0].Tested != tested || r.Keys[0].Name != "blue (account)" {
		t.Fatalf("refresh: %+v", r)
	}
	// Not signed in, Mine is the local file: the two keys saved above.
	keys, err := Mine(context.Background(), nil)
	if err != nil || len(keys) != 2 || keys[0].Name != "blue" {
		t.Fatalf("mine: %v %v", keys, err)
	}
}
