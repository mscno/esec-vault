package team

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/envelope"
)

// chainPeople are the admins and members of a group or organisation
// chain: who may sign its links, with their user keys or their delegates.
type chainPeople struct {
	admins, members map[string]*GroupAdminState
	// seqs holds, by signer, the position of their user chain they signed
	// their last link at; it may not go back.
	seqs map[string]uint64
	// leave is the one link type a member signs: leaving.
	leave string
	// what names the chain in errors.
	what string
}

// signedHead is what checking a link's signer needs.
type signedHead struct {
	Seq            uint64
	Type           string
	Signer         string
	SignerKey      uint64
	SignerSeq      uint64
	SignerDelegate string
	CTime          time.Time
}

// userKey returns the user key that must have signed h: its creator's
// (creator) for the first link, otherwise an active admin's, or a
// member's leaving.
func (p chainPeople) userKey(h signedHead, creator *Person, chains Chains) (ed25519.PublicKey, error) {
	if err := chain.ValidUser(h.Signer); err != nil {
		return nil, err
	}
	var root string
	if h.Seq == 1 {
		if creator == nil || creator.User != h.Signer {
			return nil, errors.New("the init link must be signed by its creator")
		}
		root = creator.Root
	} else {
		a, ok := p.admins[h.Signer]
		if !ok || !a.Active {
			m, member := p.members[h.Signer]
			if !member || !m.Active || h.Type != p.leave {
				return nil, fmt.Errorf("%s is not an admin of the %s", h.Signer, p.what)
			}
			a = m
		}
		root = a.Root
	}
	pub, err := SignerKey(chains, h.Signer, root, h.SignerKey, h.SignerSeq)
	if err != nil {
		return nil, err
	}
	if h.SignerSeq < p.seqs[h.Signer] {
		return nil, fmt.Errorf("%s signed as of an earlier position of their user chain than before", h.Signer)
	}
	return pub, nil
}

// delegate checks e, a link h signed by a delegate of an admin: active at
// the position of the admin's user chain it names, with a scope that covers
// the link (scope says which it needs).
func (p chainPeople) delegate(e *envelope.Envelope, kind string, h signedHead, chains Chains, scope func() (string, error)) error {
	return p.delegateUnless(e, kind, h, chains, scope, false)
}

// delegateUnless is delegate; with noServer, a link the server's own key
// signed is refused, as an organisation's rules may ask.
func (p chainPeople) delegateUnless(e *envelope.Envelope, kind string, h signedHead, chains Chains, scope func() (string, error), noServer bool) error {
	a, ok := p.admins[h.Signer]
	if !ok || !a.Active || h.SignerKey != 0 || h.Seq == 1 {
		return fmt.Errorf("only an admin's delegate signs %s links", p.what)
	}
	if h.SignerSeq < p.seqs[h.Signer] {
		return fmt.Errorf("%s signed as of an earlier position of their user chain than before", h.Signer)
	}
	d, err := DelegateSigner(chains, h.Signer, a.Root, h.SignerDelegate, h.SignerSeq, h.CTime)
	if err != nil {
		return err
	}
	if noServer && d.Kind == chain.DelegateServer {
		return fmt.Errorf("the %s's rules let the server sign nothing", p.what)
	}
	need, err := scope()
	if err != nil {
		return err
	}
	if !chain.DelegateAllows(d.Scope, need) {
		return fmt.Errorf("%w: the delegate %s may only sign %s changes", errNotInScope, d.Name, d.Scope)
	}
	return verifyDelegate(e, kind, d)
}
