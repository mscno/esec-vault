package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/guard"
	"github.com/mscno/esec-vault/internal/passkeyguard"
)

// SecurityKeysPasskeyCmd enrolls an encryption-capable native macOS passkey.
type SecurityKeysPasskeyCmd struct {
	Name     string `help:"Name for this passkey" default:"esec Vault"`
	Provider string `enum:"platform,security-key" default:"platform" help:"Password manager or a FIDO2 security key"`
	RPID     string `name:"rp-id" help:"Isolated signer domain of the signed Mac app (defaults to sign. plus the vault host)"`
}

// Run implements security-keys passkey.
func (c *SecurityKeysPasskeyCmd) Run(ctx *cliCtx) error {
	bg, cancel := timeout(5 * time.Minute)
	defer cancel()
	_, a, err := myKeys(bg, ctx)
	if err != nil {
		return err
	}
	var server string
	if a != nil {
		server = a.State.Server
	}
	rp, err := passkeyRP(server, c.RPID)
	if err != nil {
		return err
	}
	if _, err := guard.CheckPlugin("passkey"); err != nil {
		return err
	}
	fmt.Println("Choose a passkey in the macOS system sheet. Its encryption support is checked before any vault key changes.")
	credential, err := passkeyguard.Enroll(bg, rp, c.Name, c.Provider)
	if err != nil {
		return err
	}
	h := sha256.Sum256(credential.ID)
	k := chain.SecurityKey{ID: "passkey:" + hex.EncodeToString(h[:16]), Kind: chain.SecurityKeyPasskey, Name: c.Name, Recipient: credential.EncodeRecipient()}
	if err := registerKey(bg, a, k); err != nil {
		return err
	}
	fmt.Printf("Registered %s. Existing guarded seals need to be sealed again to include it.\n", c.Name)
	// Enrollment never initiates a legacy PIV/PIN ceremony as a side effect.
	// Migration is an explicit seal sync/recover operation.
	return nil
}

func passkeyRP(server, requested string) (string, error) {
	var host string
	if server != "" {
		u, err := url.Parse(server)
		if err != nil {
			return "", err
		}
		host = u.Hostname()
	}
	if requested != "" {
		if requested == host || strings.HasSuffix(host, "."+requested) {
			return "", errors.New("use the isolated signer domain, not the vault server's host, for decryption passkeys")
		}
		return requested, nil
	}
	if host == "" {
		return "", errors.New("give --rp-id matching the signed Mac app's isolated signer domain")
	}
	return "sign." + host, nil
}
