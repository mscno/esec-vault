package guard

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/passkeyguard"
	"github.com/mscno/esec-vault/internal/securitykey"
)

func TestPluginWaitDoesNotRequestAnEarlyTouch(t *testing.T) {
	var note, prompt string
	p := Presence{
		Note: func(s string) { note = s },
		Secret: func(s string) (string, error) {
			prompt = s
			return "123456", nil
		},
	}
	ui := p.ClientUI()
	ui.WaitTimer("yubikey")
	if strings.Contains(note, "touch your security key") || !strings.Contains(note, "only when the key blinks") {
		t.Fatalf("silence was mistaken for a touch request: %q", note)
	}
	if got, err := ui.RequestValue("yubikey", "Enter PIN", true); err != nil || got != "123456" {
		t.Fatalf("PIN response: %q %v", got, err)
	}
	if !strings.Contains(prompt, "after this prompt closes") || !strings.Contains(prompt, "OTP") {
		t.Fatalf("PIN prompt does not explain touch order: %q", prompt)
	}
}

func TestNativePasskeyReadSkipsCustomPrompt(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("native passkey selection is a macOS policy")
	}
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv(IdentitiesEnv, "")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "age-plugin-passkey"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil { //nolint:gosec // Executable plugin test fixture.
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	previous := passkeyguard.Native
	t.Cleanup(func() { passkeyguard.Native = previous })
	passkeyguard.Native = func(context.Context, passkeyguard.Request) (passkeyguard.Response, error) {
		return passkeyguard.Response{CredentialID: bytes.Repeat([]byte{1}, 32), PRF: bytes.Repeat([]byte{2}, 32)}, nil
	}
	c, err := passkeyguard.Enroll(context.Background(), "vault.example.com", "test", "platform")
	if err != nil {
		t.Fatal(err)
	}
	reg := &securitykey.Registry{Source: "local"}
	if err := reg.Add(chain.SecurityKey{ID: "passkey:test", Kind: chain.SecurityKeyPasskey, Name: "test", Recipient: c.EncodeRecipient()}); err != nil {
		t.Fatal(err)
	}
	if err := reg.Save(); err != nil {
		t.Fatal(err)
	}
	legacy, _ := yubikeyRecipient(1)
	ids, err := Identities([]string{legacy, c.EncodeRecipient()}, nil)
	if err != nil || !nativePasskeysOnly(ids) {
		t.Fatalf("native keys were not preferred: %v %v", ids, err)
	}
	var note string
	p := Presence{
		Ask: func(string, string) (bool, error) {
			t.Fatal("custom Allow/PIN dialog shown before the native sheet")
			return false, nil
		},
		Note: func(s string) { note = s },
	}
	// An invalid age header stops before any plugin/hardware operation;
	// choosing native presence must still skip the custom approval dialog.
	if _, err := p.OpenSeal([]byte("invalid seal"), "acme/app", "prod", "", []string{c.EncodeRecipient()}, "title", "Asked by: Terminal"); err == nil {
		t.Fatal("invalid seal opened")
	}
	if !strings.Contains(note, "macOS passkey sheet") || strings.Contains(note, "touch") {
		t.Fatalf("native instructions: %q", note)
	}
}
