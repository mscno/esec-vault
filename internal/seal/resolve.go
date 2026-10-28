package seal

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/mscno/esec/pkg/projectfile"
	coreseal "github.com/mscno/esec/pkg/seal"
)

// Person is what a person's seals are made to, from their verified chain.
type Person struct {
	// User is "gh:<id>"; empty for the local identity without an account.
	User  string
	Login string
	// EncPub is their user key (hex): their devices hold it.
	EncPub string
	// MasterPub is their recovery key (hex), derived from their phrase.
	MasterPub string
	// SecurityKeys are the recipients of their registered security keys.
	SecurityKeys []string
}

// ErrNoAccount says a GitHub user has no account on the vault server yet.
var ErrNoAccount = errors.New("no esec vault account yet")

// Directory resolves readers to recipients. Self is required; Person and
// Group are nil without a vault server.
type Directory struct {
	Self   func(ctx context.Context) (*Person, error)
	Person func(ctx context.Context, user string) (*Person, error)
	// Group returns a machine group's current public key (hex).
	Group func(ctx context.Context, group string) (string, error)
}

// Resolution is what one reader resolves to.
type Resolution struct {
	Reader     Reader
	Recipients []string
	Recovery   []string
	// Pending says why the reader cannot be sealed in yet.
	Pending string
}

// Resolve resolves one reader for an environment, guarded or not.
func (d Directory) Resolve(ctx context.Context, r Reader, guarded bool) (Resolution, error) {
	out := Resolution{Reader: r}
	switch r.Kind {
	case KindKey:
		if _, err := coreseal.ParseRecipient(r.ID); err != nil {
			return out, fmt.Errorf("reader %s: %w", r, err)
		}
		out.Recipients = []string{r.ID}
		return out, nil
	case KindGroup:
		if guarded {
			out.Pending = "a guarded environment is not sealed to a group: its members would read it without a touch; add the people, or the group's machines as keys"
			return out, nil
		}
		if d.Group == nil {
			out.Pending = "sign in to a vault server to seal for a group"
			return out, nil
		}
		pub, err := d.Group(ctx, r.ID)
		if err != nil {
			return out, fmt.Errorf("group %s: %w", r.ID, err)
		}
		rec, err := coreseal.X25519Recipient(pub)
		if err != nil {
			return out, err
		}
		out.Recipients = []string{rec}
		return out, nil
	case KindMe, KindPerson:
		p, err := d.person(ctx, r)
		if errors.Is(err, ErrNoAccount) {
			out.Pending = "has " + ErrNoAccount.Error() + ": sealed in once they sign in (esec vault seal sync)"
			return out, nil
		}
		if err != nil {
			return out, err
		}
		if p.User != "" {
			out.Reader = Reader{Kind: KindPerson, ID: p.User, Label: p.Login}
		}
		return p.resolve(out, guarded)
	}
	return out, fmt.Errorf("unknown reader %s", r)
}

func (d Directory) person(ctx context.Context, r Reader) (*Person, error) {
	self, err := d.Self(ctx)
	if err != nil {
		return nil, err
	}
	if r.Kind == KindMe || r.ID == self.User {
		return self, nil
	}
	if d.Person == nil {
		return nil, fmt.Errorf("sign in to a vault server to seal for %s", r.Display())
	}
	return d.Person(ctx, r.ID)
}

func (p *Person) resolve(out Resolution, guarded bool) (Resolution, error) {
	if p.MasterPub != "" {
		rec, err := coreseal.X25519Recipient(p.MasterPub)
		if err != nil {
			return out, err
		}
		out.Recovery = []string{rec}
	}
	if guarded {
		if len(p.SecurityKeys) == 0 {
			out.Pending = "has no security key yet: sealed in once they add one (esec vault security-keys add)"
			return out, nil
		}
		out.Recipients = slices.Clone(p.SecurityKeys)
		return out, nil
	}
	rec, err := coreseal.X25519Recipient(p.EncPub)
	if err != nil {
		return out, err
	}
	out.Recipients = []string{rec}
	return out, nil
}

// Guarded reports whether a guard level needs a security key.
func Guarded(level string) bool { return level != "" && level != projectfile.GuardNone }
