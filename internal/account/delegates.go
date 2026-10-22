package account

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/safetext"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// Delegates lists this account's delegates: passkeys and the server, which
// may sign some project and group changes for it.
func (a *Account) Delegates(ctx context.Context) ([]*chain.DelegateState, error) {
	if err := a.requireConfirmed(); err != nil {
		return nil, err
	}
	st, err := a.VerifiedChain(ctx)
	if err != nil {
		return nil, err
	}
	return st.ActiveDelegates(), nil
}

// appendUserLink signs a link of this account's user chain with the user
// key and commits it.
func (a *Account) appendUserLink(ctx context.Context, typ string, body any) error {
	return a.Locked(func() error {
		st, err := a.VerifiedChain(ctx)
		if err != nil {
			return err
		}
		id, err := a.userKey(ctx, st)
		if err != nil {
			return err
		}
		link, err := st.NewLink(typ, body, a.Now().UTC().Truncate(time.Second), id.Sign)
		if err != nil {
			return err
		}
		next, err := st.Next(link)
		if err != nil {
			return err
		}
		if _, err := a.Client.Commit(ctx, &wire.Commit{Links: []*envelope.Envelope{link}}); err != nil {
			return err
		}
		a.State.pin(next)
		return a.State.Save()
	})
}

// AddPasskey adds a passkey registered on the web pages as a delegate. The
// caller has shown its name, scope and fingerprint words to the person.
func (a *Account) AddPasskey(ctx context.Context, d chain.Delegate) error {
	if d.Kind != chain.DelegatePasskey {
		return errors.New("not a passkey")
	}
	if err := chain.ValidateDelegate(d); err != nil {
		return err
	}
	// It must be bound to the signer page of this account's server, worked
	// out here, not taken from the server: a passkey that works on the
	// server's own pages could be one the server made.
	signer := SignerOrigin(a.State.Server)
	if signer == "" || d.Origin != signer {
		return fmt.Errorf("the passkey is bound to %s, not to the signer page %s; register it there", d.Origin, signer)
	}
	if u, err := url.Parse(signer); err != nil || d.RPID != u.Hostname() {
		return fmt.Errorf("the passkey's relying party %s is not the signer page's", d.RPID)
	}
	return a.appendUserLink(ctx, chain.TypeDelegateAdd, chain.DelegateAddBody{Delegate: d})
}

// AllowServer lets the server sign removals for this account.
func (a *Account) AllowServer(ctx context.Context) error {
	k, err := a.Client.ServerKey(ctx)
	if err != nil {
		return err
	}
	b := make([]byte, 15)
	_, _ = rand.Read(b)
	d := chain.Delegate{ID: "dl_" + base32(b), Kind: chain.DelegateServer, Name: "vault server", Scope: chain.ScopeRemove, SignPub: k.SignPub, Created: a.Now().UTC().Truncate(time.Second)}
	return a.appendUserLink(ctx, chain.TypeDelegateAdd, chain.DelegateAddBody{Delegate: d})
}

// RemoveDelegate removes a delegate by id or name.
func (a *Account) RemoveDelegate(ctx context.Context, idOrName string) (*chain.DelegateState, error) {
	ds, err := a.Delegates(ctx)
	if err != nil {
		return nil, err
	}
	var found []*chain.DelegateState
	for _, d := range ds {
		if d.ID == idOrName || strings.EqualFold(d.Name, idOrName) || (idOrName == "server" && d.Kind == chain.DelegateServer) {
			found = append(found, d)
		}
	}
	switch len(found) {
	case 0:
		return nil, fmt.Errorf("no delegate %s", idOrName)
	case 1:
	default:
		return nil, fmt.Errorf("several delegates are named %s; use its id", idOrName)
	}
	return found[0], a.appendUserLink(ctx, chain.TypeDelegateRemove, chain.DelegateRemoveBody{ID: found[0].ID})
}

// SignerOrigin returns the passkey signer page of a vault server:
// ESEC_VAULT_SIGNER, or https://sign. and the server's host.
func SignerOrigin(server string) string {
	if v := strings.TrimRight(strings.TrimSpace(os.Getenv("ESEC_VAULT_SIGNER")), "/"); v != "" {
		return v
	}
	u, err := url.Parse(server)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return ""
	}
	return "https://sign." + u.Host
}

func base32(b []byte) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	var out strings.Builder
	var buf uint64
	bits := 0
	for _, c := range b {
		buf = buf<<8 | uint64(c)
		bits += 8
		for bits >= 5 {
			out.WriteByte(alphabet[(buf>>(bits-5))&31])
			bits -= 5
		}
	}
	return out.String()
}

// changePasskey decodes the passkey a change adds.
func changePasskey(ch wire.Change) (*chain.Delegate, error) {
	var d chain.Delegate
	if err := envelope.DecodeStrict(ch.Data, &d); err != nil {
		return nil, fmt.Errorf("the change describes no passkey: %w", err)
	}
	return &d, nil
}

// ApplyChange signs a web change on this device and says what it did, one
// line each. The caller showed the change (Describe) and the person agreed.
func (a *Account) ApplyChange(ctx context.Context, ch ChangeView) ([]string, error) { //nolint:gocyclo // one case per kind of change
	switch {
	case ch.Scope == wire.ScopeAccount && ch.Kind == wire.ChangeDelegateAdd:
		d, err := changePasskey(ch.Change)
		if err != nil {
			return nil, err
		}
		if err := a.AddPasskey(ctx, *d); err != nil {
			return nil, err
		}
		return []string{fmt.Sprintf("Added the passkey %s; it signs changes on the web pages.", d.Name)}, nil
	case ch.Scope == wire.ScopeAccount && ch.Kind == wire.ChangeDelegateServer:
		if err := a.AllowServer(ctx); err != nil {
			return nil, err
		}
		return []string{"The server now signs removals made on the web pages for you."}, nil
	case ch.Scope == wire.ScopeAccount && ch.Kind == wire.ChangeDelegateRemove:
		d, err := a.RemoveDelegate(ctx, ch.Subject)
		if err != nil {
			return nil, err
		}
		return []string{fmt.Sprintf("Removed %s; it signs nothing for you any more.", d.Name)}, nil
	case ch.Scope == wire.ScopeGroup && ch.Kind == wire.ChangeAccess:
		res, err := a.GrantGroup(ctx, ch.Target, ch.Project, ch.Envs)
		if err != nil {
			return nil, err
		}
		out := []string{fmt.Sprintf("%s reads %s of %s.", ch.Target, orNothing(ch.Envs), ch.Project)}
		if res.NeedGroupAdmin || res.NeedProjectAdmin {
			out = append(out, "The other side still has to agree: an admin of it signs the same change.")
		}
		if len(res.Exposed) > 0 {
			out = append(out, fmt.Sprintf("Rotate %s of %s: the group may still hold the keys.", strings.Join(res.Exposed, ", "), ch.Project))
		}
		return out, nil
	case ch.Scope == wire.ScopeGroup && ch.Kind == wire.ChangeMemberAdd:
		res, err := a.AddGroupMember(ctx, ch.Target, ch.Subject, "")
		if errors.Is(err, ErrNoProof) {
			return nil, fmt.Errorf("%w. Add them by hand with the account key words they read to you: esec vault group add %s %s --account-key '...'", err, ch.Target, ch.Subject)
		}
		if err != nil {
			return nil, err
		}
		return []string{fmt.Sprintf("Added %s to %s, checked with their GitHub SSH key.", res.Login, ch.Target)}, nil
	case ch.Scope == wire.ScopeGroup && ch.Kind == wire.ChangeMemberRemove:
		res, err := a.RemoveGroupMember(ctx, ch.Target, ch.Subject, "removed on the web")
		if err != nil {
			return nil, err
		}
		out := []string{fmt.Sprintf("Removed %s from %s; the group has a new key.", ch.Subject, ch.Target)}
		for p, envs := range res.Exposed {
			out = append(out, fmt.Sprintf("Rotate %s of %s: they may still hold the keys.", strings.Join(envs, ", "), p))
		}
		return out, nil
	case ch.Scope == wire.ScopeGroup && ch.Kind == wire.ChangeRemove:
		res, err := a.RemoveCred(ctx, ch.Target, ch.Subject, "removed on the web", false)
		if err != nil {
			return nil, err
		}
		out := []string{fmt.Sprintf("Removed %s from %s; the group has a new key.", res.Cred.Name, ch.Target)}
		for p, envs := range res.Exposed {
			out = append(out, fmt.Sprintf("Rotate %s of %s: it may still hold the keys.", strings.Join(envs, ", "), p))
		}
		return out, nil
	case ch.Scope == wire.ScopeProject && ch.Kind == wire.ChangeMemberAdd:
		res, err := a.AddMember(ctx, ch.Target, ch.Subject, ch.Admin, ch.Envs, "")
		if errors.Is(err, ErrNoProof) {
			return nil, fmt.Errorf("%w. Add them by hand with the account key words they read to you: esec vault access add %s --account-key '...' --project %s", err, ch.Subject, ch.Target)
		}
		if err != nil {
			return nil, err
		}
		return []string{fmt.Sprintf("Added %s to %s, checked with their GitHub SSH key.", res.Login, ch.Target)}, nil
	case ch.Scope == wire.ScopeProject && ch.Kind == wire.ChangeMemberSet:
		res, err := a.UpdateMember(ctx, ch.Target, ch.Subject, ch.Admin, ch.Envs)
		if err != nil {
			return nil, err
		}
		out := []string{fmt.Sprintf("%s now reads %s of %s.", ch.Subject, readsText(ch.Change), ch.Target)}
		if len(res.Exposed) > 0 {
			out = append(out, fmt.Sprintf("Rotate %s of %s: they may still hold the keys.", strings.Join(res.Exposed, ", "), ch.Target))
		}
		return out, nil
	case ch.Scope == wire.ScopeProject && ch.Kind == wire.ChangeMachineRemove:
		m, err := a.RemoveMachine(ctx, ch.Target, ch.Subject, "removed on the web")
		if err != nil {
			return nil, err
		}
		return []string{fmt.Sprintf("Removed the machine %s from %s. Rotate %s: it may still hold the keys.", m.Name, ch.Target, strings.Join(m.Envs, ", "))}, nil
	case ch.Scope == wire.ScopeProject && ch.Kind == wire.ChangeMemberRemove:
		envs, err := a.RemoveMember(ctx, ch.Target, ch.Subject, "removed on the web")
		if err != nil {
			return nil, err
		}
		out := []string{fmt.Sprintf("Removed %s from %s.", ch.Subject, ch.Target)}
		if len(envs) > 0 {
			out = append(out, fmt.Sprintf("Rotate %s of %s: they may still hold the keys.", strings.Join(envs, ", "), ch.Target))
		}
		return out, nil
	}
	return nil, fmt.Errorf("this version cannot sign a %s change; update esec-vault", ch.Kind)
}

// Narrows reports whether a change, checked against the verified chains,
// only takes access away: a member or group left reading less. Removes
// tells that from the change alone; this covers what needs the chain.
func (a *Account) Narrows(ctx context.Context, ch ChangeView) bool {
	if ch.Removes() {
		return true
	}
	switch {
	case ch.Scope == wire.ScopeProject && ch.Kind == wire.ChangeMemberSet && !ch.Admin:
		v, err := a.Team(ctx, ch.Target)
		if err != nil {
			return false
		}
		m, err := member(v.State, ch.Subject)
		return err == nil && !m.Admin && subsetOf(ch.Envs, m.Envs)
	case ch.Scope == wire.ScopeGroup && ch.Kind == wire.ChangeAccess:
		v, err := a.Team(ctx, ch.Project)
		if err != nil {
			return false
		}
		pg, ok := v.State.Group(ch.Target)
		return ok && subsetOf(ch.Envs, pg.Envs)
	}
	return false
}

func subsetOf(a, b []string) bool {
	for _, n := range a {
		if !slices.Contains(b, n) {
			return false
		}
	}
	return true
}

// Removes reports whether a change only takes access away.
func (ch ChangeView) Removes() bool {
	switch ch.Kind {
	case wire.ChangeRemove, wire.ChangeMemberRemove, wire.ChangeDelegateRemove, wire.ChangeMachineRemove:
		return true
	case wire.ChangeAccess:
		return len(ch.Envs) == 0
	}
	return false
}

// Describe says what signing a change does, on one line.
func (ch ChangeView) Describe() string { return strings.Join(ch.DescribeLines(), "; ") }

// AskedBy is who made the change, as safe text: a GitHub login, or
// "someone" for anything else the server says.
func (ch ChangeView) AskedBy() string {
	if team.ValidLogin(ch.By) != nil {
		return "someone"
	}
	return ch.By
}

// DescribeLines says what signing a change does, from the change itself
// (what the person sees is what gets signed), as lines safe to show: no
// control or bidirectional characters, nothing cut.
func (ch ChangeView) DescribeLines() []string {
	lines := ch.describe()
	for i, l := range lines {
		lines[i] = safetext.CleanN(l, 2000)
	}
	return lines
}

func (ch ChangeView) describe() []string {
	switch ch.Kind {
	case wire.ChangeAccess:
		if len(ch.Envs) == 0 {
			return []string{fmt.Sprintf("%s: stop reading %s", ch.Target, ch.Project)}
		}
		return []string{fmt.Sprintf("%s: read %s of %s", ch.Target, strings.Join(ch.Envs, ", "), ch.Project)}
	case wire.ChangeRemove:
		name := ch.Name
		if name == "" {
			name = ch.Subject
		}
		return []string{fmt.Sprintf("%s: remove %s (blocked by the server already)", ch.Target, name)}
	case wire.ChangeMemberAdd:
		if ch.Scope == wire.ScopeGroup {
			return []string{fmt.Sprintf("%s: add %s, who reads what the group reads", ch.Target, ch.Subject)}
		}
		return []string{fmt.Sprintf("%s: add %s, who reads %s", ch.Target, ch.Subject, readsText(ch.Change))}
	case wire.ChangeMemberSet:
		return []string{fmt.Sprintf("%s: let %s read %s", ch.Target, ch.Subject, readsText(ch.Change))}
	case wire.ChangeMemberRemove:
		return []string{fmt.Sprintf("%s: remove %s", ch.Target, ch.Subject)}
	case wire.ChangeMachineRemove:
		return []string{fmt.Sprintf("%s: remove the machine %s", ch.Target, ch.Subject)}
	case wire.ChangeDelegateAdd:
		d, err := changePasskey(ch.Change)
		if err != nil {
			return []string{"add a passkey (damaged)"}
		}
		what := "members, access and removals"
		if d.Scope == chain.ScopeRemove {
			what = "removals only"
		}
		return []string{
			"ADD A PASSKEY to your account, which signs " + what + " for you",
			"on " + d.Origin + ", named " + strconvQuote(d.Name),
			"fingerprint: " + chain.DelegateWords(*d),
		}
	case wire.ChangeDelegateServer:
		return []string{"let the server sign removals for you (never additions, never from admins)"}
	case wire.ChangeDelegateRemove:
		return []string{"remove the delegate " + ch.Subject}
	}
	return []string{ch.Kind}
}

func strconvQuote(s string) string { return fmt.Sprintf("%q", s) }

func readsText(c wire.Change) string {
	if c.Admin {
		return "every environment, as an admin"
	}
	return orNothing(c.Envs)
}

func orNothing(envs []string) string {
	if len(envs) == 0 {
		return "nothing"
	}
	return strings.Join(envs, ", ")
}
