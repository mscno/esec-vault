package cli

import "testing"

func TestDecryptionPasskeysUseIsolatedSigner(t *testing.T) {
	if got, err := passkeyRP("https://vault.example.com", ""); err != nil || got != "sign.vault.example.com" {
		t.Fatalf("default relying party: %s %v", got, err)
	}
	if _, err := passkeyRP("https://vault.example.com", "vault.example.com"); err == nil {
		t.Fatal("the untrusted vault server's pages could request the decryption PRF")
	}
	if _, err := passkeyRP("https://vault.example.com", "example.com"); err == nil {
		t.Fatal("a parent relying party would also be callable by the vault pages")
	}
	if got, err := passkeyRP("https://vault.example.com", "signer.example.com"); err != nil || got != "signer.example.com" {
		t.Fatalf("custom isolated signer: %s %v", got, err)
	}
	if _, err := passkeyRP("", ""); err == nil {
		t.Fatal("an unconfigured relying party was accepted")
	}
}
