package seal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/mscno/esec/pkg/projectfile"
	coreseal "github.com/mscno/esec/pkg/seal"
)

type testPerson struct {
	user, login string
	key, master *age.X25519Identity
	securityKey *age.X25519Identity // stands in for a YubiKey
}

func newPerson(t *testing.T, user, login string) *testPerson {
	t.Helper()
	p := &testPerson{user: user, login: login}
	p.key, _ = age.GenerateX25519Identity()
	p.master, _ = age.GenerateX25519Identity()
	p.securityKey, _ = age.GenerateX25519Identity()
	return p
}

func (p *testPerson) person(t *testing.T) *Person {
	t.Helper()
	enc, _ := coreseal.RecipientHex(p.key.Recipient().String())
	master, _ := coreseal.RecipientHex(p.master.Recipient().String())
	return &Person{User: p.user, Login: p.login, EncPub: enc, MasterPub: master, SecurityKeys: []string{p.securityKey.Recipient().String()}}
}

func privateHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func TestReaders(t *testing.T) {
	for in, want := range map[string]Reader{
		"me":                 {Kind: KindMe, ID: "me"},
		"mads (gh:583231)":   {Kind: KindPerson, ID: "gh:583231", Label: "mads"},
		"group acme/backend": {Kind: KindGroup, ID: "acme/backend"},
		"deploy (age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq)": {Kind: KindKey, ID: "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq", Label: "deploy"},
	} {
		got, err := ParseReader(in)
		if err != nil || got != want || got.String() != in {
			t.Errorf("%q: %+v %v (%q)", in, got, err, got.String())
		}
	}
	for _, bad := range []string{"alice", "alice (gh:0)", "group Acme", "x (nope)", "a\"b (gh:1)"} {
		if _, err := ParseReader(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestMakeOpenCheck(t *testing.T) { //nolint:gocyclo // one story, step by step
	ctx := context.Background()
	mads, alice := newPerson(t, "gh:1", "mads"), newPerson(t, "gh:2", "alice")
	d := Directory{
		Self: func(context.Context) (*Person, error) { return mads.person(t), nil },
		Person: func(_ context.Context, user string) (*Person, error) {
			if user == "gh:2" {
				return alice.person(t), nil
			}
			return nil, ErrNoAccount
		},
	}
	_, signKey, _ := ed25519.GenerateKey(rand.Reader)
	signer := Signer{By: "gh:1", Key: signKey, Recovery: mads.master.Recipient().String()}
	root := t.TempDir()
	pf := &projectfile.File{Project: "acme/store"}
	priv := privateHex(t)
	pub, _ := coreseal.PublicHex(priv)

	// dev: "me" and alice, by GitHub id; bob has no account yet.
	readers, err := ParseReaders([]string{"me", "alice (gh:2)", "bob (gh:3)"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := Make(ctx, d, Env{Project: "acme/store", Name: "dev", Root: root, Private: priv, Readers: readers}, signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(root, pf, "dev", res); err != nil {
		t.Fatal(err)
	}
	if got := pf.Env["dev"].Readers; got[0] != "mads (gh:1)" || len(res.Pending) != 1 {
		t.Fatalf("readers %v, pending %+v", got, res.Pending)
	}
	for _, id := range []age.Identity{mads.key, alice.key, mads.master, alice.master} {
		if p, err := Open(root, "acme/store", "dev", pub, id); err != nil || p.Private != priv {
			t.Fatalf("open: %v", err)
		}
	}
	other, _ := age.GenerateX25519Identity()
	if _, err := Open(root, "acme/store", "dev", pub, other); err == nil {
		t.Fatal("opened by a stranger")
	}

	// prod, guarded: only security keys and recovery keys open it.
	priv2 := privateHex(t)
	res, err = Make(ctx, d, Env{Project: "acme/store", Name: "prod", Root: root, Private: priv2, Guard: "touch", Readers: readers[:2]}, signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(root, pf, "prod", res); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root, "acme/store", "prod", "", mads.key); err == nil {
		t.Fatal("a guarded seal opened with the user key, without a touch")
	}
	if _, err := Open(root, "acme/store", "prod", "", alice.securityKey); err != nil {
		t.Fatal(err)
	}

	// Check: clean (bob pending is a warning only).
	recs, _ := LoadRecords(root)
	read := func(env string) ([]byte, error) { return coreseal.Read(root, env) }
	for _, p := range Check(pf, recs, read) {
		if p.Level == Fail {
			t.Fatalf("problem: %+v", p)
		}
	}
	// A swapped public key in esec.toml fails; so does an edited seal.
	e := pf.Env["prod"]
	e.Key = strings.Repeat("a", 64)
	pf.Env["prod"] = e
	if !hasFail(Check(pf, recs, read), "names key") {
		t.Fatal("a swapped key passed")
	}
	e.Key = recs["prod"].Key
	pf.Env["prod"] = e
	if err := os.WriteFile(coreseal.Path(root, "prod"), append(res.Data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if !hasFail(Check(pf, recs, read), "not the one recorded") {
		t.Fatal("an edited seal passed")
	}
	// A reader added by hand, without sealing, fails.
	e.Readers = append(e.Readers, "eve (gh:9)")
	pf.Env["prod"] = e
	if !hasFail(Check(pf, recs, read), "readers") {
		t.Fatal("an unsealed reader passed")
	}

	// Stale: alice adds a security key; bob signs up.
	newKey, _ := age.GenerateX25519Identity()
	d.Person = func(_ context.Context, user string) (*Person, error) {
		p := alice.person(t)
		p.SecurityKeys = append(p.SecurityKeys, newKey.Recipient().String())
		if user == "gh:3" {
			p.User, p.Login = "gh:3", "bob"
		}
		return p, nil
	}
	why, err := Stale(ctx, d, pf.Env["dev"], recs["dev"], signer)
	if err != nil || len(why) == 0 {
		t.Fatalf("bob signed up, dev not stale: %v %v", why, err)
	}
	e.Readers = e.Readers[:2]
	pf.Env["prod"] = e
	why, _ = Stale(ctx, d, pf.Env["prod"], recs["prod"], signer)
	if len(why) != 1 || !strings.Contains(why[0], "alice") {
		t.Fatalf("alice's new key: %v", why)
	}
}

func hasFail(ps []Problem, text string) bool {
	for _, p := range ps {
		if p.Level == Fail && strings.Contains(p.Detail, text) {
			return true
		}
	}
	return false
}
