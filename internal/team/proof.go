package team

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/mscno/esec-vault/internal/share"
)

// ProofNamespace is the SSHSIG namespace of account proofs. It differs from
// every other namespace esec vault signs in.
const ProofNamespace = "esec-vault-account"

// AccountProof binds a GitHub account to an esec vault account: an SSH key
// registered on GitHub signs the account's GitHub id, login and account
// root. An admin checks it against https://github.com/LOGIN.keys before
// adding the account to a project, so the server cannot pass off its own
// account as a colleague's.
type AccountProof struct {
	User      string `json:"user"`
	Login     string `json:"login"`
	Root      string `json:"root"`
	Signature string `json:"signature"`
}

// ProofStatement is the message an account proof signs.
func ProofStatement(user, login, root string) []byte {
	return []byte("esec-vault account v1\n" + user + "\n" + strings.ToLower(login) + "\n" + root + "\n")
}

// Check validates a proof's fields (not its signature).
func (p *AccountProof) Check() error {
	if p == nil {
		return errors.New("no proof")
	}
	if err := validPerson(Person{User: p.User, Login: p.Login, Root: p.Root}); err != nil {
		return err
	}
	if len(p.Signature) == 0 || len(p.Signature) > 8<<10 {
		return errors.New("invalid proof signature")
	}
	return nil
}

// VerifyAccountProof checks that p is signed by one of the GitHub keys of
// its login, for exactly this account.
func VerifyAccountProof(p *AccountProof, person Person, githubKeys []ssh.PublicKey) error {
	if err := p.Check(); err != nil {
		return err
	}
	if p.User != person.User || p.Root != person.Root || !strings.EqualFold(p.Login, person.Login) {
		return errors.New("the proof is for another account")
	}
	if err := share.VerifySSHSIG([]byte(p.Signature), ProofNamespace, ProofStatement(p.User, p.Login, p.Root), githubKeys); err != nil {
		if errors.Is(err, share.ErrUnknownSigner) {
			return fmt.Errorf("the proof is not signed by an SSH key on GitHub account %s", p.Login)
		}
		return err
	}
	return nil
}
