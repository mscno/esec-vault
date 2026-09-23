package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/share"
)

// MembersCmd manages team member proofs.
type MembersCmd struct {
	Prove  MembersProveCmd  `cmd:"" help:"Create your identity proof (signed with your GitHub SSH key)."`
	Verify MembersVerifyCmd `cmd:"" help:"Verify committed member proofs against GitHub."`
	Trust  MembersTrustCmd  `cmd:"" help:"Pin a member's identity key (TOFU) after verification."`
	List   MembersListCmd   `cmd:"" help:"List committed proofs and trust status."`
}

// MembersProveCmd creates a member proof.
type MembersProveCmd struct {
	Login  string `help:"Your GitHub login (default: prompt)" short:"l"`
	SSHKey string `help:"SSH private key registered on your GitHub account" type:"path" default:"~/.ssh/id_ed25519"`
}

// Run implements members prove.
func (c *MembersProveCmd) Run(ctx *cliCtx) error {
	id, err := identity.Load(ctx.Keyring)
	if err != nil {
		return err
	}
	login := c.Login
	if login == "" {
		fmt.Print("GitHub login: ")
		if _, err := fmt.Scanln(&login); err != nil {
			return err
		}
	}
	proof, err := share.Prove(login, id.PublicHex(), c.SSHKey)
	if err != nil {
		return err
	}
	data, err := proof.Marshal()
	if err != nil {
		return err
	}
	dir := share.MembersDirName
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	path := filepath.Join(dir, login+".proof")
	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	fmt.Printf("Wrote %s\nCommit it from your own GitHub account and open a PR.\n", path)
	fmt.Printf("Fingerprint: %s\n", id.Fingerprint())
	return nil
}

// MembersVerifyCmd verifies proofs against GitHub.
type MembersVerifyCmd struct {
	Logins []string `arg:"" optional:"" help:"Members to verify (default: all committed proofs)"`
}

// Run implements members verify.
func (c *MembersVerifyCmd) Run(ctx *cliCtx) error {
	logins := c.Logins
	if len(logins) == 0 {
		entries, err := os.ReadDir(share.MembersDirName)
		if err != nil {
			return fmt.Errorf("no committed proofs in %s", share.MembersDirName)
		}
		for _, e := range entries {
			if filepath.Ext(e.Name()) == ".proof" {
				logins = append(logins, e.Name()[:len(e.Name())-len(".proof")])
			}
		}
	}
	trust, err := share.LoadTrust()
	if err != nil {
		return err
	}
	rc := 0
	for _, login := range logins {
		data, err := os.ReadFile(filepath.Join(share.MembersDirName, login+".proof")) //nolint:gosec // login comes from args/dir listing
		if err != nil {
			fmt.Printf("  %s: %v\n", login, err)
			rc = 1
			continue
		}
		proof, err := share.ParseProof(data)
		if err != nil {
			fmt.Printf("  %s: %v\n", login, err)
			rc = 1
			continue
		}
		keys, err := share.FetchGitHubKeys(login, nil, "")
		if err != nil {
			fmt.Printf("  %s: %v\n", login, err)
			rc = 1
			continue
		}
		if err := share.VerifyProof(proof, keys); err != nil {
			fmt.Printf("  %s: INVALID: %v\n", login, err)
			rc = 1
			continue
		}
		status := "verified, NOT trusted (run: esec-vault members trust " + login + ")"
		if err := trust.CheckTrust(login, proof); err == nil {
			status = "verified and trusted"
		}
		fmt.Printf("  %s: %s\n", login, status)
	}
	if rc != 0 {
		return &exitCodeError{code: rc}
	}
	return nil
}

// MembersTrustCmd pins a member key after verification.
type MembersTrustCmd struct {
	Login string `arg:"" help:"Member login to trust"`
}

// Run implements members trust. The proof is verified against GitHub before
// pinning; the fingerprint should additionally be confirmed out-of-band.
func (c *MembersTrustCmd) Run(ctx *cliCtx) error {
	data, err := os.ReadFile(filepath.Join(share.MembersDirName, c.Login+".proof"))
	if err != nil {
		return err
	}
	proof, err := share.ParseProof(data)
	if err != nil {
		return err
	}
	keys, err := share.FetchGitHubKeys(c.Login, nil, "")
	if err != nil {
		return err
	}
	if err := share.VerifyProof(proof, keys); err != nil {
		return fmt.Errorf("refusing to trust: %w", err)
	}
	fmt.Printf("Proof valid. Fingerprint: %s\n", fingerprintOf(proof))
	if !confirm("Have you verified this fingerprint with " + c.Login + " out-of-band? Trust it?") {
		return fmt.Errorf("aborted")
	}
	trust, err := share.LoadTrust()
	if err != nil {
		return err
	}
	if err := trust.Trust(c.Login, proof); err != nil {
		return err
	}
	if err := trust.Save(); err != nil {
		return err
	}
	fmt.Println("Trusted", c.Login)
	return nil
}

// MembersListCmd lists proofs and pins.
type MembersListCmd struct{}

// Run implements members list.
func (c *MembersListCmd) Run(ctx *cliCtx) error {
	trust, err := share.LoadTrust()
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(share.MembersDirName)
	if err != nil {
		return fmt.Errorf("no committed proofs in %s", share.MembersDirName)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".proof" {
			continue
		}
		login := e.Name()[:len(e.Name())-len(".proof")]
		data, err := os.ReadFile(filepath.Join(share.MembersDirName, e.Name()))
		if err != nil {
			continue
		}
		proof, err := share.ParseProof(data)
		if err != nil {
			fmt.Printf("  %s: unparsable proof\n", login)
			continue
		}
		status := "untrusted"
		if err := trust.CheckTrust(login, proof); err == nil {
			status = "trusted"
		}
		fmt.Printf("  %s: %s fingerprint=%s\n", login, status, fingerprintOf(proof))
	}
	return nil
}

func fingerprintOf(p *share.Proof) string {
	pubBytes, err := hexDecode(p.EsecPubkey)
	if err != nil || len(pubBytes) != 32 {
		return "(invalid)"
	}
	var pub [32]byte
	copy(pub[:], pubBytes)
	return identity.Fingerprint(pub)
}
