package cli

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/guard"
)

// Exercise the real age plugin protocol without a card or terminal. The
// stand-in refuses identities lacking the YubiKey's serial/slot/key tag,
// then requests a PIN through the client's UI before decrypting.
func TestSecurityKeyTestUsesDetectedIdentityAndDesktopPIN(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the plugin launcher is a shell script")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	script := "#!/bin/sh\nexec '" + strings.ReplaceAll(exe, "'", "'\\''") + "' -test.run=^TestSecurityKeyPluginProcess$ -- \"$@\"\n"
	if err := os.WriteFile(filepath.Join(dir, "age-plugin-yubikey"), []byte(script), 0o700); err != nil { //nolint:gosec // Executable plugin test fixture.
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ESEC_TEST_YUBIKEY_IDENTITY", id.String())
	t.Setenv(guard.IdentitiesEnv, "")
	detected, _ := securityKeyTestDetected()
	k := chain.SecurityKey{Kind: "yubikey", Recipient: detected, Name: "test key"}
	previous := guard.DefaultPresence
	t.Cleanup(func() { guard.DefaultPresence = previous })
	var prompts []string
	guard.DefaultPresence = guard.Presence{
		Secret: func(prompt string) (string, error) {
			prompts = append(prompts, prompt)
			return "123456", nil
		},
		Note: func(string) {},
	}
	if err := testDecrypt(k); err != nil {
		t.Fatalf("test without a terminal failed: %v", err)
	}
	if len(prompts) != 1 || !strings.Contains(prompts[0], "Enter PIN") {
		t.Fatalf("desktop PIN prompts: %q", prompts)
	}
	guard.DefaultPresence.Secret = func(string) (string, error) { return "", guard.ErrDenied }
	if err := testDecrypt(k); err == nil {
		t.Fatal("cancelled PIN still decrypted")
	}
}

func securityKeyTestDetected() (recipient, list string) {
	recipient = strings.Split(testYubiKeys, "\n")[4]
	list, _, _ = strings.Cut(testYubiKeys, "#       Serial: 20010203")
	return
}

func TestSecurityKeyPluginProcess(t *testing.T) {
	encoded := os.Getenv("ESEC_TEST_YUBIKEY_IDENTITY")
	if encoded == "" {
		return
	}
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		t.Fatal("missing plugin arguments")
	}
	args = args[1:]
	recipient, list := securityKeyTestDetected()
	if len(args) == 1 && args[0] == "--list" {
		fmt.Print(list)
		os.Exit(0)
	}
	id, err := age.ParseX25519Identity(encoded)
	if err != nil {
		t.Fatal(err)
	}
	p, err := plugin.New("yubikey")
	if err != nil {
		t.Fatal(err)
	}
	fs := flag.NewFlagSet("test-yubikey", flag.ContinueOnError)
	p.RegisterFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	p.HandleRecipient(func([]byte) (age.Recipient, error) { return id.Recipient(), nil })
	p.HandleIdentity(func(data []byte) (age.Identity, error) {
		stub, err := guard.YubiKeyStub("15584441", "1", recipient)
		if err != nil {
			return nil, err
		}
		_, want, err := plugin.ParseIdentity(stub)
		if err != nil || !bytes.Equal(data, want) {
			return nil, errors.New("invalid YubiKey stub: missing serial/slot/key tag")
		}
		pin, err := p.RequestValue("Enter PIN", true)
		if err != nil {
			return nil, err
		}
		if pin != "123456" {
			return nil, errors.New("incorrect test PIN")
		}
		return id, nil
	})
	os.Exit(p.Main())
}
