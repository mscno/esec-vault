package server

// Delegates (chain.Delegate): keys a person lets sign some changes for them.
//
//   - The server's own key, with scope "remove": changes made on the web
//     pages that only take access away are signed and applied at once.
//   - Passkeys, signing in the browser: each change a person makes or sees
//     on the pages can be signed with one touch.
//
// The links are built here, from the verified chains, and committed through
// the same checks as a device's. Clients verify the delegate and its scope
// themselves; the server can sign only what a person's chain lets it.

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// serverSigner holds the server's signing key once loaded.
type serverSigner struct {
	mu  sync.Mutex
	key ed25519.PrivateKey
}

// signingKey loads the server's key, creating it the first time. A failure
// is not kept: the next call tries again.
func (s *Server) signingKey(ctx context.Context) (ed25519.PrivateKey, error) {
	s.signer.mu.Lock()
	defer s.signer.mu.Unlock()
	if s.signer.key != nil {
		return s.signer.key, nil
	}
	// Not the request's context: a page the person left must not fail it.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	var seed []byte
	err := s.db.sql.QueryRowContext(ctx, `SELECT seed FROM server_keys WHERE id = 'delegate'`).Scan(&seed)
	if errors.Is(err, sql.ErrNoRows) {
		seed = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		if _, err := s.db.sql.ExecContext(ctx, `INSERT INTO server_keys (id, seed, created_at) VALUES ('delegate', ?, ?) ON CONFLICT DO NOTHING`, seed, s.now().Unix()); err != nil {
			return nil, err
		}
		err = s.db.sql.QueryRowContext(ctx, `SELECT seed FROM server_keys WHERE id = 'delegate'`).Scan(&seed)
	}
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("stored server key is damaged")
	}
	s.signer.key = ed25519.NewKeyFromSeed(seed)
	return s.signer.key, nil
}

func (s *Server) apiServerKey(w http.ResponseWriter, r *http.Request) {
	k, err := s.signingKey(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	pub, _ := k.Public().(ed25519.PublicKey)
	writeJSON(w, http.StatusOK, wire.ServerKey{SignPub: hex.EncodeToString(pub)})
}

// personDelegates are a person's delegates in use now.
type personDelegates struct {
	cs       *chain.State
	server   *chain.DelegateState
	passkeys []*chain.DelegateState
}

func (s *Server) delegatesOf(ctx context.Context, user string) (*personDelegates, error) {
	cs, err := s.db.userChains(ctx, s.db.sql)(user)
	if err != nil {
		return nil, err
	}
	k, err := s.signingKey(ctx)
	if err != nil {
		return nil, err
	}
	pub, _ := k.Public().(ed25519.PublicKey)
	out := &personDelegates{cs: cs}
	now := s.now()
	for _, d := range cs.ActiveDelegates() {
		if !d.Expires.IsZero() && !now.Before(d.Expires) {
			continue
		}
		switch {
		case d.Kind == chain.DelegateServer && d.SignPub == hex.EncodeToString(pub):
			out.server = d
		case d.Kind == chain.DelegatePasskey:
			out.passkeys = append(out.passkeys, d)
		}
	}
	slices.SortFunc(out.passkeys, func(a, b *chain.DelegateState) int { return cmp.Compare(a.AddedSeq, b.AddedSeq) })
	return out, nil
}

// passkey returns the person's passkey delegate id.
func (p *personDelegates) passkey(id string) *chain.DelegateState {
	for _, d := range p.passkeys {
		if d.ID == id {
			return d
		}
	}
	return nil
}

// errNeedsDevice is returned for a change only a device can sign.
var errNeedsDevice = clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "Only your device can sign this change: esec vault changes")

// changeLinks builds the links that make change c, for delegate d of user
// to sign, from the current verified chains.
func (s *Server) changeLinks(ctx context.Context, user string, cs *chain.State, d *chain.DelegateState, c wire.Change) ([]*envelope.Envelope, error) { //nolint:gocyclo // one case per kind of change
	now, seq := s.now(), cs.Seq
	switch c.Scope {
	case wire.ScopeProject:
		st, _, err := s.db.projectState(ctx, s.db.sql, c.Target)
		if err != nil {
			return nil, err
		}
		if st == nil || !st.Admin(user) {
			return nil, clientErr(http.StatusForbidden, wire.ErrForbidden, "Only an admin of %s can change who reads it.", c.Target)
		}
		var typ string
		var body any
		switch c.Kind {
		case wire.ChangeMemberAdd:
			if c.Admin {
				return nil, errNeedsDevice
			}
			p, err := s.personByLogin(ctx, c.Subject)
			if err != nil {
				return nil, err
			}
			typ, body = team.TypeMemberAdd, team.MemberAddBody{Member: p, Envs: team.SortEnvs(c.Envs), Verified: team.VerifiedWeb}
		case wire.ChangeMemberSet, wire.ChangeMemberRemove:
			m := memberOf(st, c.Subject)
			if m == nil {
				return nil, clientErr(http.StatusNotFound, wire.ErrNotFound, "%s is not a member.", c.Subject)
			}
			if m.Admin || c.Admin {
				return nil, errNeedsDevice
			}
			typ, body = team.TypeMemberRemove, team.MemberRemoveBody{User: m.User, Reason: "removed on the web"}
			if c.Kind == wire.ChangeMemberSet {
				typ, body = team.TypeMemberUpdate, team.MemberUpdateBody{User: m.User, Envs: team.SortEnvs(c.Envs)}
			}
		default:
			return nil, errNeedsDevice
		}
		e, err := st.DelegateLink(typ, body, now, user, d.ID, seq)
		if err != nil {
			return nil, err
		}
		return []*envelope.Envelope{e}, nil
	case wire.ScopeGroup:
		gs, _, err := s.db.groupState(ctx, s.db.sql, c.Target)
		if err != nil {
			return nil, err
		}
		if gs == nil {
			return nil, clientErr(http.StatusNotFound, wire.ErrNotFound, "There is no group %s.", c.Target)
		}
		switch c.Kind {
		case wire.ChangeMemberAdd:
			if !gs.Admin(user) {
				return nil, clientErr(http.StatusForbidden, wire.ErrForbidden, "Only an admin of %s can add people.", c.Target)
			}
			p, err := s.personByLogin(ctx, c.Subject)
			if err != nil {
				return nil, err
			}
			e, err := gs.DelegateLink(team.GroupMemberAdd, team.GroupMemberAddBody{Member: p, Verified: team.VerifiedWeb}, now, user, d.ID, seq)
			if err != nil {
				return nil, err
			}
			return []*envelope.Envelope{e}, nil
		case wire.ChangeMemberRemove:
			if !gs.Admin(user) {
				return nil, clientErr(http.StatusForbidden, wire.ErrForbidden, "Only an admin of %s can remove people.", c.Target)
			}
			var who string
			for _, m := range gs.ActiveMembers() {
				if strings.EqualFold(m.Login, c.Subject) {
					who = m.User
				}
			}
			if who == "" {
				return nil, clientErr(http.StatusNotFound, wire.ErrNotFound, "%s is not a member of %s.", c.Subject, c.Target)
			}
			e, err := gs.DelegateLink(team.GroupMemberRemove, team.GroupMemberRemoveBody{User: who, Reason: "removed on the web"}, now, user, d.ID, seq)
			if err != nil {
				return nil, err
			}
			return []*envelope.Envelope{e}, nil
		case wire.ChangeRemove:
			if !gs.Admin(user) {
				return nil, clientErr(http.StatusForbidden, wire.ErrForbidden, "Only an admin of %s can remove its machines.", c.Target)
			}
			e, err := gs.DelegateLink(team.GroupRemove, team.GroupRemoveBody{ID: c.Subject, Reason: "removed on the web"}, now, user, d.ID, seq)
			if err != nil {
				return nil, err
			}
			return []*envelope.Envelope{e}, nil
		case wire.ChangeAccess:
			return s.accessLinks(ctx, user, gs, d, c, now, seq)
		}
	}
	return nil, errNeedsDevice
}

// accessLinks builds the links that make a group read c.Envs of c.Project:
// the group's side (it takes keys from the project) when user administers
// the group, and the project's (its grant) when user administers it.
func (s *Server) accessLinks( //nolint:gocyclo // both sides, each only when user administers it
	ctx context.Context, user string, gs *team.GroupState, d *chain.DelegateState, c wire.Change, now time.Time, seq uint64) ([]*envelope.Envelope, error) {
	ps, _, err := s.db.projectState(ctx, s.db.sql, c.Project)
	if err != nil {
		return nil, err
	}
	if ps == nil {
		return nil, clientErr(http.StatusNotFound, wire.ErrNotFound, "There is no shared project %s.", c.Project)
	}
	envs := team.SortEnvs(c.Envs)
	root, trusted := gs.Access[c.Project]
	pg, granted := ps.Group(gs.Group)
	if (trusted && root != ps.Root()) || (granted && pg.Root != gs.Root()) {
		return nil, errNeedsDevice
	}
	// A new project for the group, or a new group for the project, is a
	// device's to sign: which chain (root) is trusted matters.
	if len(envs) > 0 && (!trusted || !granted) {
		return nil, errNeedsDevice
	}
	var out []*envelope.Envelope
	if ps.Admin(user) && (granted || len(envs) > 0) && (!granted || !slices.Equal(pg.Envs, envs)) {
		e, err := ps.DelegateLink(team.TypeGroupSet, team.GroupSetBody{Group: gs.Group, Root: gs.Root(), Envs: envs}, now, user, d.ID, seq)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if gs.Admin(user) && len(envs) == 0 && trusted {
		e, err := gs.DelegateLink(team.GroupAccessRemove, team.GroupAccessRemoveBody{Project: c.Project}, now, user, d.ID, seq)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if len(out) == 0 {
		return nil, clientErr(http.StatusConflict, wire.ErrConflict, "Nothing to change that you administer.")
	}
	return out, nil
}

// personByLogin returns the account of a GitHub login on this server, as a
// chain records it.
func (s *Server) personByLogin(ctx context.Context, login string) (team.Person, error) {
	u, err := s.db.userByLogin(ctx, login)
	if err != nil {
		return team.Person{}, err
	}
	if u == nil {
		return team.Person{}, clientErr(http.StatusNotFound, wire.ErrNotFound, "%s has no account on this server.", login)
	}
	first, err := s.db.firstLink(ctx, u.ID)
	if err != nil {
		return team.Person{}, err
	}
	if first == nil {
		return team.Person{}, clientErr(http.StatusNotFound, wire.ErrNotFound, "%s has not created a vault account yet.", login)
	}
	return team.Person{User: u.ID, Login: u.Login, Root: first.Hash()}, nil
}

// checkDelegateLinks verifies signed delegate links against the current
// chains, without storing them.
func (s *Server) checkDelegateLinks(ctx context.Context, links []*envelope.Envelope) error {
	chains := s.db.userChains(ctx, s.db.sql)
	for _, e := range links {
		switch e.Kind {
		case team.KindLink:
			l, err := team.PeekLink(e)
			if err != nil {
				return err
			}
			st, _, err := s.db.projectState(ctx, s.db.sql, l.Project)
			if err != nil || st == nil {
				return errors.Join(err, errors.New("no such project"))
			}
			if _, err := st.Next(e, chains); err != nil {
				return err
			}
		case team.KindGroupLink:
			l, err := team.PeekGroupLink(e)
			if err != nil {
				return err
			}
			gs, _, err := s.db.groupState(ctx, s.db.sql, l.Group)
			if err != nil || gs == nil {
				return errors.Join(err, errors.New("no such group"))
			}
			if _, err := gs.Next(e, chains); err != nil {
				return err
			}
		default:
			return errors.New("not a project or group link")
		}
	}
	return nil
}

// commitDelegateLinks stores links signed by user's delegates, in order and
// in one transaction, through the checks a device's links pass.
func (s *Server) commitDelegateLinks(ctx context.Context, user, ip string, links []*envelope.Envelope) error { //nolint:gocyclo // two kinds of chain, each checked in order
	now := s.now()
	wake := map[string]bool{}
	err := s.db.tx(ctx, func(tx *sql.Tx) error {
		chains := s.db.userChains(ctx, tx)
		for _, e := range links {
			switch e.Kind {
			case team.KindLink:
				l, err := team.PeekLink(e)
				if err != nil || l.Signer != user || l.SignerDelegate == "" {
					return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "not a link of your delegate")
				}
				stored, err := s.db.projectLinks(ctx, tx, l.Project, 0)
				if err != nil {
					return err
				}
				st, err := team.Verify(l.Project, stored, chains)
				if err != nil {
					return err
				}
				if l.Seq != st.Seq+1 {
					return clientErr(http.StatusConflict, wire.ErrConflict, "%s changed meanwhile; try again", l.Project)
				}
				if err := linkClock(l.CTime, now); err != nil {
					return err
				}
				next, err := s.appendProjectLink(ctx, tx, st, e, *l, chains, user, ip, now)
				if err != nil {
					return err
				}
				if err := s.db.mirrorProject(ctx, tx, next, now); err != nil {
					return err
				}
				for _, m := range next.ActiveMembers() {
					if err := s.db.addEvent(ctx, tx, m.User, wire.EventProject, next.Project, now); err != nil {
						return err
					}
					wake[m.User] = true
				}
			case team.KindGroupLink:
				l, err := team.PeekGroupLink(e)
				if err != nil || l.Signer != user || l.SignerDelegate == "" {
					return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "not a link of your delegate")
				}
				stored, err := s.db.groupLinks(ctx, tx, l.Group)
				if err != nil {
					return err
				}
				gs, err := team.VerifyGroup(l.Group, stored, chains)
				if err != nil {
					return err
				}
				if l.Seq != gs.Seq+1 {
					return clientErr(http.StatusConflict, wire.ErrConflict, "%s changed meanwhile; try again", l.Group)
				}
				if err := linkClock(l.CTime, now); err != nil {
					return err
				}
				next, err := gs.Next(e, chains)
				if err != nil {
					return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "link rejected: %v", err)
				}
				if err := s.checkGroupLink(ctx, tx, gs, *l, chains, now); err != nil {
					return err
				}
				if err := s.storeGroupLink(ctx, tx, gs, next, e, *l, user, ip, now); err != nil {
					return err
				}
				if err := s.db.mirrorGroup(ctx, tx, next, now); err != nil {
					return err
				}
				users, err := s.groupWake(ctx, tx, gs, next, now)
				if err != nil {
					return err
				}
				for _, u := range users {
					wake[u] = true
				}
			default:
				return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "not a project or group link")
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for u := range wake {
		s.notify.wake(u)
	}
	s.kickAlerts()
	return nil
}

// serverSigns applies change c at once, signed by the server, when user let
// the server sign removals and c is one. It reports whether it did.
func (s *Server) serverSigns(ctx context.Context, user, ip string, c wire.Change) (bool, error) {
	ds, err := s.delegatesOf(ctx, user)
	if err != nil || ds.server == nil {
		return false, err
	}
	links, err := s.changeLinks(ctx, user, ds.cs, ds.server, c)
	if err != nil {
		return false, nil //nolint:nilerr // not something the server may sign: propose it instead
	}
	key, err := s.signingKey(ctx)
	if err != nil {
		return false, err
	}
	for _, e := range links {
		e.AddSignature(key)
	}
	// Anything beyond its scope fails here, and is proposed instead.
	if s.checkDelegateLinks(ctx, links) != nil {
		return false, nil //nolint:nilerr // see above
	}
	if err := s.commitDelegateLinks(ctx, user, ip, links); err != nil {
		return false, err
	}
	return true, nil
}
