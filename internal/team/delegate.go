package team

// Links signed by a delegate. A member or group admin may let a passkey or
// the server sign some links for them (chain.Delegate). Such a link names
// the person as its signer, the delegate in signer_delegate, and the
// person's user chain position, at which the delegate must be active; its
// scope must cover the link, judged against the chain before it.

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/passkey"
)

// VerifiedWeb records a member added through the web pages and signed by
// a passkey: nobody's device checked the account yet, so admins' devices
// check the person's GitHub SSH proof before sending them any key.
const VerifiedWeb = "web"

// errNotInScope is returned for a link a delegate may not sign.
var errNotInScope = errors.New("a delegate cannot sign that")

// DelegateSigner returns delegate id of user, active once user's chain
// (whose root must be root) had seq links, and not expired at ctime.
func DelegateSigner(chains Chains, user, root, id string, seq uint64, ctime time.Time) (*chain.DelegateState, error) {
	if chains == nil {
		return nil, errors.New("no user chains to verify signatures with")
	}
	cs, err := chains(user)
	if err != nil {
		return nil, fmt.Errorf("user chain of %s: %w", user, err)
	}
	if cs.User != user || cs.Root() == "" || cs.Root() != root {
		return nil, fmt.Errorf("the account of %s is not the one recorded", user)
	}
	d, ok := cs.DelegateAt(id, seq)
	if !ok {
		return nil, fmt.Errorf("%s had no delegate %s at the position it names", user, id)
	}
	if !d.Expires.IsZero() && !ctime.Before(d.Expires) {
		return nil, fmt.Errorf("the delegate %s of %s had expired", d.Name, user)
	}
	return d, nil
}

// verifyDelegate checks e's signature by delegate d.
func verifyDelegate(e *envelope.Envelope, kind string, d *chain.DelegateState) error {
	if err := e.Check(); err != nil {
		return err
	}
	if e.Kind != kind {
		return fmt.Errorf("expected %s envelope, got %s", kind, e.Kind)
	}
	switch d.Kind {
	case chain.DelegateServer:
		pub, err := chain.ParseSignKey(d.SignPub)
		if err != nil {
			return err
		}
		if e.Passkey != nil || !e.VerifiedBy(pub) {
			return fmt.Errorf("%w: %s", envelope.ErrBadSignature, kind)
		}
		return nil
	case chain.DelegatePasskey:
		if len(e.Sigs) > 0 {
			return errors.New("a passkey's link carries no other signature")
		}
		return passkey.Verify(e.Passkey, &d.Delegate, e.Challenge())
	}
	return fmt.Errorf("unknown delegate kind %q", d.Kind)
}

// subset reports whether every name of a is in b.
func subset(a, b []string) bool {
	for _, n := range a {
		if !slices.Contains(b, n) {
			return false
		}
	}
	return true
}

// projectScope returns the scope a delegate needs to sign l on st, or
// errNotInScope.
func projectScope(st *State, l Link) (string, error) { //nolint:gocyclo // one case per link type
	switch l.Type {
	case TypeMemberRemove:
		var b MemberRemoveBody
		if err := decodeBody(l, &b); err != nil {
			return "", err
		}
		if m, ok := st.Member(b.User); ok && !m.Admin {
			return chain.ScopeRemove, nil
		}
	case TypeMemberUpdate:
		var b MemberUpdateBody
		if err := decodeBody(l, &b); err != nil {
			return "", err
		}
		m, ok := st.Member(b.User)
		if !ok || m.Admin || b.Admin {
			break
		}
		if subset(b.Envs, m.Envs) {
			return chain.ScopeRemove, nil
		}
		return chain.ScopeManage, nil
	case TypeMachineRemove:
		return chain.ScopeRemove, nil
	case TypeGroupSet:
		var b GroupSetBody
		if err := decodeBody(l, &b); err != nil {
			return "", err
		}
		// Only a group the project grants already: which group (its root)
		// is a device's to choose.
		g, ok := st.Group(b.Group)
		if !ok || g.Root != b.Root {
			break
		}
		if subset(b.Envs, g.Envs) {
			return chain.ScopeRemove, nil
		}
		return chain.ScopeManage, nil
	case TypeMemberAdd:
		var b MemberAddBody
		if err := decodeBody(l, &b); err != nil {
			return "", err
		}
		if !b.Admin && b.Verified == VerifiedWeb {
			return chain.ScopeManage, nil
		}
	}
	return "", fmt.Errorf("%w: %s", errNotInScope, l.Type)
}

// groupScope returns the scope a delegate needs to sign l.
func groupScope(l GroupLink) (string, error) {
	switch l.Type {
	case GroupRemove:
		// Only a device may say a machine's keys went with it.
		var b GroupRemoveBody
		if err := decodeGroupBody(l, &b); err != nil {
			return "", err
		}
		if !b.Destroyed {
			return chain.ScopeRemove, nil
		}
	case GroupAccessRemove, GroupMemberRemove:
		return chain.ScopeRemove, nil
	case GroupMemberAdd:
		var b GroupMemberAddBody
		if err := decodeGroupBody(l, &b); err != nil {
			return "", err
		}
		// Like a project member added on the web: admins' devices check the
		// account before sealing the group key to it.
		if b.Verified == VerifiedWeb {
			return chain.ScopeManage, nil
		}
	}
	// Which projects a group trusts (by their roots) is a device's to
	// choose: machines take keys from them.
	return "", fmt.Errorf("%w: %s", errNotInScope, l.Type)
}
