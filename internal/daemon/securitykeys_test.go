package daemon

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/mscno/esec-vault/internal/securitykey"
)

func TestDetectNotifiesOncePerYubiKey(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	list := `#       Serial: 15584441, Slot: 1
# Touch policy: Always (A physical touch is required for every decryption)
age1yubikey1qf28gwqh38gcsqlukuyk0vpae0lw26dvt05rvm7k0y2t90367cunzs00yyk
`
	prev := securitykey.Run
	securitykey.Run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		switch name + " " + strings.Join(args, " ") {
		case "age-plugin-yubikey --list":
			return []byte(list), nil
		case "ykman list --serials":
			return []byte("15584441\n31415926\n"), nil
		}
		return nil, errors.New("unexpected")
	}
	t.Cleanup(func() { securitykey.Run = prev })
	var notes []string
	Notifier = func(_, body string) { notes = append(notes, body) }
	t.Cleanup(func() { Notifier = func(string, string) {} })

	s := &Server{Logger: slog.New(slog.DiscardHandler)}
	s.detectOnce(context.Background())
	s.detectOnce(context.Background())
	if len(notes) != 2 || !strings.Contains(notes[0], "security-keys add") || !strings.Contains(notes[1], "setup --serial 31415926") {
		t.Fatalf("notes: %q", notes)
	}
	seen, err := LoadSeenKeys()
	if err != nil || len(seen.PluggedIn) != 1 || seen.PluggedIn[0].Registered || seen.Unprovisioned[0] != "31415926" || seen.Checked.IsZero() {
		t.Fatalf("seen: %+v %v", seen, err)
	}

	// Registered: no notification, and the app sees it as registered.
	reg, _ := securitykey.Load()
	ds, _ := securitykey.Parse(list)
	if err := reg.Add(securitykey.FromDetected(ds[0], "blue")); err != nil {
		t.Fatal(err)
	}
	if err := reg.Save(); err != nil {
		t.Fatal(err)
	}
	s.detectOnce(context.Background())
	seen, _ = LoadSeenKeys()
	if !seen.PluggedIn[0].Registered || len(notes) != 2 {
		t.Fatalf("after registering: %+v %q", seen, notes)
	}

	// No plugin: quiet.
	securitykey.Run = func(context.Context, string, ...string) ([]byte, error) { return nil, securitykey.ErrNoPlugin }
	s.detectOnce(context.Background())
	if len(notes) != 2 {
		t.Fatal("notified without a plugin")
	}
}
