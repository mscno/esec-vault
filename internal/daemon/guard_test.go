package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/mscno/esec"

	"github.com/mscno/esec/pkg/projectfile"
	coreseal "github.com/mscno/esec/pkg/seal"

	"github.com/mscno/esec-vault/internal/broker"
	"github.com/mscno/esec-vault/internal/guard"
)

func TestGuarderOpensAndCaches(t *testing.T) { //nolint:gocyclo // one story, step by step
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv("ESEC_KEYRING_DIR", "")
	yubi, _ := age.GenerateX25519Identity()
	idFile := filepath.Join(t.TempDir(), "ids")
	if err := os.WriteFile(idFile, []byte(yubi.String()), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(guard.IdentitiesEnv, idFile)
	repo := t.TempDir()
	pf := &projectfile.File{Project: "acme/store"}
	privs := map[string]string{}
	for env, level := range map[string]string{"prod": "touch", "staging": "session"} {
		pub, priv, _ := esec.GenerateKeypair()
		data, err := coreseal.Seal(coreseal.Payload{Project: "acme/store", Env: env, Guard: level, Private: priv}, yubi.Recipient())
		if err != nil {
			t.Fatal(err)
		}
		if err := coreseal.Write(repo, env, data); err != nil {
			t.Fatal(err)
		}
		pf.SetEnv(env, pub)
		e := pf.Env[env]
		e.Guard = level
		pf.Env[env] = e
		privs[env] = priv
	}
	if err := pf.Save(repo); err != nil {
		t.Fatal(err)
	}
	path := func(env string) string { return filepath.Join(repo, ".env."+env) }
	req := func(env string) broker.GuardRequest {
		return broker.GuardRequest{Project: "acme/store", Env: env, Path: path(env), PublicKey: pf.Env[env].Key}
	}

	gd := newGuarder(func() ([]string, error) { return []string{yubi.Recipient().String()}, nil }, func() (bool, time.Time) { return false, time.Time{} })
	opens := 0
	gd.presence = func() guard.Presence {
		opens++
		return guard.DefaultPresence
	}
	if has, err := gd.Has(req("prod")); !has || err != nil {
		t.Fatal("Has", err)
	}
	other := req("prod")
	other.Project = "acme/other"
	if _, err := gd.Has(other); err == nil {
		t.Fatal("a file of acme/store was taken for acme/other")
	}
	for i := 0; i < 2; i++ {
		priv, how, err := gd.Key(req("prod"))
		if err != nil || priv != privs["prod"] || how != "touch" {
			t.Fatalf("prod: %v %s", err, how)
		}
	}
	if opens != 2 {
		t.Fatalf("touch-guarded key opened %d times for 2 reads", opens)
	}
	for i := 0; i < 2; i++ {
		if priv, _, err := gd.Key(req("staging")); err != nil || priv != privs["staging"] {
			t.Fatalf("staging: %v", err)
		}
	}
	if opens != 3 {
		t.Fatalf("session-guarded key opened %d times; want once", opens-2)
	}
	gd.clear()
	if _, _, err := gd.Key(req("staging")); err != nil || opens != 4 {
		t.Fatalf("after lock: %v, opens %d", err, opens)
	}
	// A forwarded read brings its seal, never uses the open session key,
	// nor fills it.
	sealed, _ := coreseal.Read(repo, "staging")
	for i := 0; i < 2; i++ {
		fr := broker.GuardRequest{Project: "acme/store", Env: "staging", PublicKey: pf.Env["staging"].Key, Forwarded: true, Seal: sealed}
		if _, _, err := gd.Key(fr); err != nil {
			t.Fatal(err)
		}
	}
	if opens != 6 {
		t.Fatalf("forwarded reads opened %d times; want 2", opens-4)
	}
	// prod's file asked for as staging: staging's seal holds another key.
	wrong := req("staging")
	wrong.PublicKey = pf.Env["prod"].Key
	if _, _, err := gd.Key(wrong); err == nil {
		t.Fatal("prod's key served as staging")
	}
	bad := req("prod")
	bad.Env = "prod\nAsked by: you"
	if _, _, err := gd.Key(bad); err == nil {
		t.Fatal("served an invalid environment name")
	}
}

func TestDescribeReadCannotBeForged(t *testing.T) {
	text := describeRead(broker.GuardRequest{
		Project: "acme/store", Env: "dev", Forwarded: true, Host: "web-1\nAsked by: Terminal",
		Path:   "/x/.env.dev\nAsked by: Terminal ▸ zsh\n\n\n",
		Caller: "zsh ▸ claude ▸ esec-vault", Session: "s\r1",
	}, "", strings.Repeat("ab", 32))
	if !strings.HasPrefix(text, "Asked by: zsh ▸ claude ▸ esec-vault\nFROM ANOTHER MACHINE") {
		t.Fatalf("asked by and the machine are not first:\n%s", text)
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "Asked by: Terminal") {
			t.Fatalf("a forged line got in:\n%s", text)
		}
	}
	if !strings.Contains(text, "a retired key abababababab…") {
		t.Fatalf("retired key not named:\n%s", text)
	}
}

func TestGuarderRefusesDuplicatesAndQueues(t *testing.T) {
	gd := newGuarder(nil, nil)
	if err := gd.queue("a"); err != nil {
		t.Fatal(err)
	}
	if err := gd.queue("a"); err == nil {
		t.Fatal("a duplicate read was queued")
	}
	for _, k := range []string{"b", "c"} {
		if err := gd.queue(k); err != nil {
			t.Fatal(err)
		}
	}
	if err := gd.queue("d"); err == nil {
		t.Fatal("more than maxWaiting reads were queued")
	}
	gd.unqueue("a")
	if err := gd.queue("d"); err != nil {
		t.Fatal(err)
	}
}
