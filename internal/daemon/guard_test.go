package daemon

import (
	"os"
	"path/filepath"
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
	if !gd.Has("acme/store", "prod", "") || gd.Has("acme/other", "prod", "") {
		t.Fatal("Has")
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
}
