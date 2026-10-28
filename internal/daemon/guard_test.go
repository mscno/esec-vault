package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/mscno/esec"

	"github.com/mscno/esec-vault/internal/broker"
	"github.com/mscno/esec-vault/internal/guard"
	"github.com/mscno/esec-vault/internal/keystore"
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
	ks := keystore.New()
	g, gid, err := guard.New([]string{yubi.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.Save(ks, g); err != nil {
		t.Fatal(err)
	}
	entries := map[string]string{}
	pubs := map[string]string{}
	for env, level := range map[string]string{"prod": "touch", "staging": "session"} {
		pub, priv, _ := esec.GenerateKeypair()
		v, err := guard.Wrap(gid.Recipient(), guard.Key{Project: "acme/store", Env: env, Level: level, Private: priv})
		if err != nil {
			t.Fatal(err)
		}
		entries[keystore.GuardEntry(pub)], entries[keystore.GuardEnvEntry(env)] = v, pub
		pubs[env] = priv
	}
	if err := ks.Write("acme/store", entries, false); err != nil {
		t.Fatal(err)
	}

	gd := newGuarder(ks, func() (bool, time.Time) { return false, time.Time{} })
	opens := 0
	gd.presence = func() guard.Presence {
		opens++
		return guard.DefaultPresence
	}
	if has, err := gd.Has("acme/store", "prod", ""); !has || err != nil {
		t.Fatal("Has", err)
	}
	if has, err := gd.Has("acme/other", "prod", ""); has || err != nil {
		t.Fatal("Has other", err)
	}
	for i := 0; i < 2; i++ {
		priv, how, err := gd.Key(broker.GuardRequest{Project: "acme/store", Env: "prod"})
		if err != nil || priv != pubs["prod"] || how != "touch" {
			t.Fatalf("prod: %v %s", err, how)
		}
	}
	if opens != 2 {
		t.Fatalf("touch-guarded key opened %d times for 2 reads", opens)
	}
	for i := 0; i < 2; i++ {
		if priv, _, err := gd.Key(broker.GuardRequest{Project: "acme/store", Env: "staging"}); err != nil || priv != pubs["staging"] {
			t.Fatalf("staging: %v", err)
		}
	}
	if opens != 3 {
		t.Fatalf("session-guarded key opened %d times; want once", opens-2)
	}
	// Moved to another project's keyring, it is refused.
	if _, _, err := gd.Key(broker.GuardRequest{Project: "acme/shop", Env: "staging"}); err == nil {
		t.Fatal("served a key for another project")
	}
	gd.clear()
	if _, _, err := gd.Key(broker.GuardRequest{Project: "acme/store", Env: "staging"}); err != nil || opens != 4 {
		t.Fatalf("after lock: %v, opens %d", err, opens)
	}
	// A forwarded read never uses the open session key, nor fills it.
	for i := 0; i < 2; i++ {
		if _, _, err := gd.Key(broker.GuardRequest{Project: "acme/store", Env: "staging", Forwarded: true}); err != nil {
			t.Fatal(err)
		}
	}
	if opens != 6 {
		t.Fatalf("forwarded reads opened the guard %d times; want 2", opens-4)
	}
	// The key decides the environment: prod's file asked for as staging
	// is refused before any dialog.
	if _, _, err := gd.Key(broker.GuardRequest{Project: "acme/store", Env: "staging", PublicKey: pubOf(t, pubs["prod"])}); err == nil || opens != 6 {
		t.Fatalf("prod's key served as staging: %v (opens %d)", err, opens)
	}
	// An unknown file key never falls back to the environment's key.
	if has, _ := gd.Has("acme/store", "prod", strings.Repeat("ab", 32)); has {
		t.Fatal("a foreign file key matched prod's guarded key")
	}
	if _, _, err := gd.Key(broker.GuardRequest{Project: "acme/store", Env: "prod\nAsked by: you"}); err == nil {
		t.Fatal("served an invalid environment name")
	}
}

func pubOf(t *testing.T, priv string) string {
	t.Helper()
	pub, err := keystore.PublicHex(priv)
	if err != nil {
		t.Fatal(err)
	}
	return pub
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
