package account

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/client"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/share"
	"github.com/mscno/esec-vault/internal/storage"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// Shared projects, from this device's side. Everything the server returns
// is verified: project chains from their first link, each signer's key from
// that signer's own user chain, and every grant against the chain. Heads of
// project chains and colleagues' user chains are pinned in teams.toml, so the
// server cannot roll either back once this device has seen them.

// Pin is a verified chain head.
type Pin struct {
	Seq  uint64 `toml:"seq"`
	Head string `toml:"head"`
	Root string `toml:"root"`
}

// TeamPins is teams.toml.
type TeamPins struct {
	Projects map[string]Pin `toml:"projects"`
	Peers    map[string]Pin `toml:"peers"`
	// Accepted lists the projects whose keys this device takes in: ones it
	// created, or that the person accepted when first added.
	Accepted map[string]bool `toml:"accepted"`
	// Held records, by project and environment, the public keys this device
	// got from or gave to the project. Only such a key may be replaced by a
	// newer key of the project without asking.
	Held map[string]map[string][]string `toml:"held"`
	// Signed lists the hashes of project links this device signed, so it
	// can tell the person about changes their account made elsewhere.
	Signed map[string]bool `toml:"signed"`
	// Groups pins machine group chains.
	Groups map[string]Pin `toml:"groups"`
}

// hold records that this device holds pub as env of project.
func (p *TeamPins) hold(project, env, pub string) {
	if p.Held[project] == nil {
		p.Held[project] = map[string][]string{}
	}
	if !slices.Contains(p.Held[project][env], pub) {
		p.Held[project][env] = append(p.Held[project][env], pub)
	}
}

func teamPinsPath() string { return filepath.Join(paths.Home(), "teams.toml") }

func loadTeamPins() (*TeamPins, error) {
	p := &TeamPins{}
	data, err := os.ReadFile(teamPinsPath())
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := toml.Unmarshal(data, p); err != nil {
			return nil, fmt.Errorf("invalid %s: %w", teamPinsPath(), err)
		}
	}
	if p.Projects == nil {
		p.Projects = map[string]Pin{}
	}
	if p.Peers == nil {
		p.Peers = map[string]Pin{}
	}
	if p.Accepted == nil {
		p.Accepted = map[string]bool{}
	}
	if p.Held == nil {
		p.Held = map[string]map[string][]string{}
	}
	if p.Signed == nil {
		p.Signed = map[string]bool{}
	}
	if p.Groups == nil {
		p.Groups = map[string]Pin{}
	}
	return p, nil
}

func (p *TeamPins) save() error {
	data, err := toml.Marshal(p)
	if err != nil {
		return err
	}
	return storage.Write(teamPinsPath(), data)
}

// teamCtx holds what one team operation verified: this account's chain and
// user key, colleagues' chains, and the pins to save afterwards.
type teamCtx struct {
	a *Account
	// ctx is the context of the one call this operation lives for.
	ctx    context.Context //nolint:containedctx // see above
	own    *chain.State
	id     *identity.Identity
	pins   *TeamPins
	peers  map[string]*chain.State
	given  map[string][]*envelope.Envelope
	states map[string]*team.State
	groups map[string]*team.GroupState
	// groupKeys caches group private keys this operation opened.
	groupKeys map[string][32]byte
	// elsewhere describes new links this account signed on another device.
	elsewhere []string
}

// team starts a team operation. It must run under a.Locked.
func (a *Account) team(ctx context.Context) (*teamCtx, error) {
	own, err := a.VerifiedChain(ctx)
	if err != nil {
		return nil, err
	}
	if _, ok := own.ActiveDevice(a.State.DeviceID); !ok {
		return nil, errors.New("this device is not active in the account's chain")
	}
	id, err := a.userKey(ctx, own)
	if err != nil {
		return nil, err
	}
	a.State.pin(own)
	pins, err := loadTeamPins()
	if err != nil {
		return nil, err
	}
	return &teamCtx{a: a, ctx: ctx, own: own, id: id, pins: pins, peers: map[string]*chain.State{a.State.User: own}, given: map[string][]*envelope.Envelope{}, states: map[string]*team.State{}, groups: map[string]*team.GroupState{}, groupKeys: map[string][32]byte{}}, nil
}

func (t *teamCtx) save() error { return errors.Join(t.pins.save(), t.a.State.Save()) }

// chains verifies colleagues' user chains: from links the server sent with
// a project chain, or fetched on demand, and against this device's pins.
func (t *teamCtx) chains(user string) (*chain.State, error) {
	if st, ok := t.peers[user]; ok {
		return st, nil
	}
	links, ok := t.given[user]
	if !ok {
		p, err := t.a.Client.PersonByID(t.ctx, user)
		if err != nil {
			return nil, err
		}
		links = p.Links
	}
	return t.peer(user, links)
}

// peer verifies a colleague's chain against its pin and moves the pin.
func (t *teamCtx) peer(user string, links []*envelope.Envelope) (*chain.State, error) {
	st, err := chain.Verify(user, links)
	if err != nil {
		return nil, fmt.Errorf("the user chain of %s does not verify: %w", user, err)
	}
	if st.Seq == 0 {
		return nil, fmt.Errorf("%s has no account", user)
	}
	if pin, ok := t.pins.Peers[user]; ok {
		if pin.Root != st.Root() {
			return nil, fmt.Errorf("%w: the account of %s is not the one this device saw before", chain.ErrRollback, user)
		}
		if err := st.CheckPin(pin.Seq, pin.Head); err != nil {
			return nil, fmt.Errorf("user chain of %s: %w", user, err)
		}
	}
	t.pins.Peers[user] = Pin{Seq: st.Seq, Head: st.Head(), Root: st.Root()}
	t.peers[user] = st
	return st, nil
}

// state fetches and verifies a project chain and moves its pin. It returns
// nil, nil for a project that does not exist.
func (t *teamCtx) state(project string) (*team.State, error) {
	if st, ok := t.states[project]; ok {
		return st, nil
	}
	pc, err := t.a.Client.ProjectChain(t.ctx, project)
	if client.IsCode(err, wire.ErrNotFound) {
		return nil, nil
	}
	if client.IsCode(err, wire.ErrForbidden) {
		return nil, fmt.Errorf("%w %s", errNotMember, project)
	}
	if err != nil {
		return nil, err
	}
	for u, links := range pc.Chains {
		t.given[u] = links
	}
	st, err := team.Verify(project, pc.Links, t.chains)
	if err != nil {
		return nil, fmt.Errorf("the server's chain for %s does not verify: %w", project, err)
	}
	pin, ok := t.pins.Projects[project]
	if err := t.checkPin(pin, ok, project, "project", st, st.Hashes, func(i uint64) (string, string) { return st.Links[i].Signer, describeLink(st, st.Links[i]) }); err != nil {
		return nil, err
	}
	t.pin(st)
	return st, nil
}

// pinnedChain is a verified project or group chain.
type pinnedChain interface {
	Root() string
	CheckPin(seq uint64, hash string) error
}

// checkPin refuses a chain that does not extend this device's pin of it,
// and notes the links since that this account signed on another device.
// link returns the signer and description of the link at an index.
func (t *teamCtx) checkPin(pin Pin, pinned bool, id, kind string, c pinnedChain, hashes []string, link func(i uint64) (signer, text string)) error {
	if !pinned {
		return nil
	}
	if pin.Root != c.Root() {
		return fmt.Errorf("%w: %s is not the %s this device saw before", team.ErrRollback, id, kind)
	}
	if err := c.CheckPin(pin.Seq, pin.Head); err != nil {
		return err
	}
	for i := pin.Seq; i < uint64(len(hashes)); i++ {
		if signer, text := link(i); signer == t.a.State.User && !t.pins.Signed[hashes[i]] {
			t.elsewhere = append(t.elsewhere, id+": "+text)
		}
	}
	return nil
}

// errNotMember is returned for a project this account is not a member of.
var errNotMember = errors.New("you are not a member of")

func (t *teamCtx) pin(st *team.State) {
	t.pins.Projects[st.Project] = Pin{Seq: st.Seq, Head: st.Head(), Root: st.Root()}
	t.states[st.Project] = st
}

// requireAdmin loads a project the caller administers.
func (t *teamCtx) requireAdmin(project string) (*team.State, error) {
	st, err := t.state(project)
	if err != nil {
		return nil, err
	}
	if st == nil {
		return nil, fmt.Errorf("%s is not a shared project yet; create it with 'esec vault team create'", project)
	}
	if !st.Admin(t.a.State.User) {
		return nil, fmt.Errorf("only an admin of %s can do that", project)
	}
	return st, nil
}

// link signs the next link of st.
func (t *teamCtx) link(st *team.State, typ string, body any) (*envelope.Envelope, *team.State, error) {
	now := t.a.Now()
	if typ == team.TypeEnvSet {
		now = t.afterRemovals(st, now)
	}
	e, err := st.NewLink(typ, body, now, t.a.State.User, t.own.UKeyVersion, t.own.Seq, t.id.Sign)
	if err != nil {
		return nil, nil, err
	}
	next, err := st.Next(e, t.chains)
	if err != nil {
		return nil, nil, err
	}
	return e, next, nil
}

// afterRemovals returns now, or a second after the latest removal from a
// group reading st that this device knows of. Link times have whole
// seconds, and a removal in the same second as a new key counts as
// exposing it, so a new key must be dated after the removals it answers.
func (t *teamCtx) afterRemovals(st *team.State, now time.Time) time.Time {
	now = now.UTC().Truncate(time.Second)
	for _, pg := range st.ActiveGroups() {
		gs, err := t.group(pg.Group)
		if err != nil || gs == nil {
			continue
		}
		for _, c := range gs.Creds {
			if !c.Active && !c.RemovedTime.Before(now) && c.RemovedTime.Sub(now) < 10*time.Minute {
				now = c.RemovedTime.Add(time.Second)
			}
		}
	}
	return now
}

// commit sends links and grants, and pins the new state.
func (t *teamCtx) commit(next *team.State, links, grants []*envelope.Envelope) error {
	for _, e := range links {
		t.pins.Signed[e.Hash()] = true
	}
	for len(links) > 0 || len(grants) > 0 {
		n := min(len(grants), 200)
		cm := &wire.ProjectCommit{Links: links, Grants: grants[:n]}
		if _, err := t.a.Client.ProjectCommit(t.ctx, next.Project, cm); err != nil {
			return err
		}
		links, grants = nil, grants[n:]
	}
	t.pin(next)
	return nil
}

// localKeys returns this device's keys for the environments of st, by
// name, when they are the project's current keys.
func (t *teamCtx) localKeys(st *team.State) map[string]string {
	entries, err := t.a.KS.Read(st.Project)
	if err != nil {
		return map[string]string{}
	}
	out := map[string]string{}
	for name, e := range st.Envs {
		for _, entry := range []string{team.EnvKey(name), team.PubKeyEntry(e.PublicKey)} {
			if priv, ok := entries[entry]; ok {
				if pub, err := team.PublicHex(priv); err == nil && pub == e.PublicKey {
					out[name] = priv
					break
				}
			}
		}
	}
	return out
}

// recipient returns the key a member's, machine's or group's grant is
// sealed to.
func (t *teamCtx) recipient(st *team.State, holder string) (team.Recipient, error) {
	if id, ok := strings.CutPrefix(holder, team.GroupHolderPrefix); ok {
		return t.groupRecipient(st, id)
	}
	if m, ok := st.Machine(holder); ok {
		pub, err := chain.ParseKey32(m.EncPub)
		return team.Recipient{ID: holder, EncPub: pub}, err
	}
	m, ok := st.Member(holder)
	if !ok {
		return team.Recipient{}, fmt.Errorf("%s is not in %s", holder, st.Project)
	}
	cs, err := t.chains(holder)
	if err != nil {
		return team.Recipient{}, err
	}
	if cs.Root() != m.Root {
		return team.Recipient{}, fmt.Errorf("the account of %s is not the one the project recorded", m.Login)
	}
	return team.Recipient{ID: holder, Version: cs.UKeyVersion, EncPub: cs.EncPub}, nil
}

// grant seals the given environments (those this device holds) to holder.
// It returns nil when there is nothing to send.
func (t *teamCtx) grant(st *team.State, holder string, envs []string) (*envelope.Envelope, []string, error) {
	have := t.localKeys(st)
	keys := map[string]string{}
	var missing []string
	for _, n := range envs {
		if priv, ok := have[n]; ok && st.HasAccess(holder, n) {
			keys[n] = priv
		} else {
			missing = append(missing, n)
		}
	}
	if len(keys) == 0 {
		return nil, missing, nil
	}
	to, err := t.recipient(st, holder)
	if err != nil {
		return nil, nil, err
	}
	g, err := team.NewGrant(st, t.a.State.User, t.own.UKeyVersion, t.id.Sign, to, keys, t.a.Now())
	return g, missing, err
}

// ackOwn records the current keys this device holds as the caller's.
func (t *teamCtx) ackOwn(st *team.State) error {
	var hs []wire.Holding
	for name := range t.localKeys(st) {
		if st.HasAccess(t.a.State.User, name) {
			hs = append(hs, wire.Holding{Project: st.Project, Env: name, PublicKey: st.Envs[name].PublicKey})
		}
	}
	if len(hs) == 0 {
		return nil
	}
	sort.Slice(hs, func(i, j int) bool { return hs[i].Env < hs[j].Env })
	return t.a.Client.AckGrants(t.ctx, wire.GrantAck{IDs: []int64{}, Holdings: hs})
}

// withTeam runs fn as one locked team operation and saves the pins.
func (a *Account) withTeam(ctx context.Context, fn func(t *teamCtx) error) error {
	return a.Locked(func() error {
		t, err := a.team(ctx)
		if err != nil {
			return err
		}
		err = fn(t)
		return errors.Join(err, t.save())
	})
}

// localEnvs lists the named environments of a project's keyring.
func (a *Account) localEnvs(project string) (map[string]string, error) {
	entries, err := a.KS.Read(project)
	if err != nil {
		return nil, fmt.Errorf("no keyring for %s on this device: %w", project, err)
	}
	out := map[string]string{}
	for k, v := range entries {
		suffix, ok := strings.CutPrefix(k, "ESEC_PRIVATE_KEY_")
		if !ok || hexEntry.MatchString(suffix) {
			continue
		}
		name := strings.ToLower(strings.ReplaceAll(suffix, "_", "."))
		if team.ValidEnv(name) != nil || team.EnvKey(name) != k {
			continue
		}
		if _, err := team.PublicHex(v); err != nil {
			continue
		}
		out[name] = v
	}
	return out, nil
}

var hexEntry = regexp.MustCompile(`^[0-9A-F]{64}$`)

// ---- operations ----

// TeamSummaries lists this account's shared projects.
func (a *Account) TeamSummaries(ctx context.Context) ([]wire.ProjectSummary, error) {
	if err := a.requireConfirmed(); err != nil {
		return nil, err
	}
	return a.Client.Projects(ctx)
}

// TeamView is a verified project with key delivery status.
type TeamView struct {
	State  *team.State
	Status *wire.ProjectStatus
	// Logins maps holders (users and machines) to display names.
	Names map[string]string
	// GroupExposed lists, by environment, machines removed from groups
	// that read it, who may hold its current key.
	GroupExposed map[string][]team.Exposure
}

// Team verifies a project and returns it with its delivery status.
func (a *Account) Team(ctx context.Context, project string) (*TeamView, error) {
	var out *TeamView
	err := a.withTeam(ctx, func(t *teamCtx) error {
		st, err := t.state(project)
		if err != nil {
			return err
		}
		if st == nil {
			return fmt.Errorf("%s is not a shared project", project)
		}
		status, err := a.Client.ProjectStatus(ctx, project)
		if err != nil {
			return err
		}
		names := map[string]string{}
		for id, m := range st.Members {
			names[id] = m.Login
		}
		for id, m := range st.Machines {
			names[id] = m.Name
		}
		out = &TeamView{State: st, Status: status, Names: names, GroupExposed: map[string][]team.Exposure{}}
		for _, pg := range st.ActiveGroups() {
			if gs, err := t.group(pg.Group); err == nil && gs != nil {
				for env, ex := range team.GroupExposures(st, gs) {
					out.GroupExposed[env] = append(out.GroupExposed[env], ex...)
				}
			}
		}
		return nil
	})
	return out, err
}

// CreateTeam shares project with this account as its first admin. envs
// lists the environments to include (default: every environment in this
// device's keyring for the project).
func (a *Account) CreateTeam(ctx context.Context, project string, envs []string) (*team.State, error) {
	if err := team.ValidProject(project); err != nil {
		return nil, err
	}
	var out *team.State
	err := a.withTeam(ctx, func(t *teamCtx) error {
		existing, err := t.state(project)
		if err != nil && !errors.Is(err, errNotMember) {
			return err
		}
		if existing != nil || err != nil {
			return fmt.Errorf("%s is already a shared project; ask one of its admins to add you", project)
		}
		local, err := a.localEnvs(project)
		if err != nil {
			return err
		}
		if len(envs) == 0 {
			for n := range local {
				envs = append(envs, n)
			}
		}
		envs = team.SortEnvs(envs)
		if len(envs) == 0 {
			return fmt.Errorf("the keyring of %s has no named environments; add one with 'esec vault env add ENV'", project)
		}
		body := team.InitBody{Creator: team.Person{User: a.State.User, Login: a.State.Login, Root: t.own.Root()}}
		for _, n := range envs {
			priv, ok := local[n]
			if !ok {
				return fmt.Errorf("this device has no %s key for %s", n, project)
			}
			pub, _ := team.PublicHex(priv)
			body.Envs = append(body.Envs, team.Env{Name: n, PublicKey: pub})
		}
		e, next, err := t.link(team.New(project), team.TypeInit, body)
		if err != nil {
			return err
		}
		if err := t.commit(next, []*envelope.Envelope{e}, nil); err != nil {
			return err
		}
		t.pins.Accepted[project] = true
		for _, env := range body.Envs {
			t.pins.hold(project, env.Name, env.PublicKey)
		}
		out = next
		return t.ackOwn(next)
	})
	return out, err
}

// AddResult describes a new member.
type AddResult struct {
	Login        string
	AccountWords string
	Verified     string
	Granted      []string
	// Missing lists environments this device had no current key for; an
	// admin who has them sends them on their next sync.
	Missing []string
}

// ErrNoProof is returned when a new member has published no GitHub proof
// and no account key was given.
var ErrNoProof = errors.New("no way to check the account")

// AddMember adds login to project. The account is checked with its GitHub
// SSH proof against github.com/LOGIN.keys, or with accountKey: the account
// key words the person reads out from 'esec vault status'.
func (a *Account) AddMember(ctx context.Context, project, login string, admin bool, envs []string, accountKey string) (*AddResult, error) {
	if err := team.ValidLogin(login); err != nil {
		return nil, err
	}
	var out *AddResult
	err := a.withTeam(ctx, func(t *teamCtx) error {
		st, err := t.requireAdmin(project)
		if err != nil {
			return err
		}
		p, err := a.Client.Person(ctx, login)
		if err != nil {
			return err
		}
		// The server chose this account: it must be the login asked for.
		if !strings.EqualFold(p.User.Login, login) || p.User.ID != fmt.Sprintf("gh:%d", p.User.GitHubID) {
			return fmt.Errorf("the server returned the account of %q for %q; not adding it", p.User.Login, login)
		}
		cs, err := t.peer(p.User.ID, p.Links)
		if err != nil {
			return err
		}
		person := team.Person{User: p.User.ID, Login: p.User.Login, Root: cs.Root()}
		if m, ok := st.Member(person.User); ok {
			return fmt.Errorf("%s is already a member (use 'esec vault team set' to change what they read)", m.Login)
		}
		verified, err := checkPerson(person, p.Proof, cs, accountKey)
		if err != nil {
			return err
		}
		envs = team.SortEnvs(envs)
		if admin {
			envs = nil
		}
		e, next, err := t.link(st, team.TypeMemberAdd, team.MemberAddBody{Member: person, Admin: admin, Envs: envs, Verified: verified})
		if err != nil {
			return err
		}
		out = &AddResult{Login: person.Login, AccountWords: cs.AccountWords(), Verified: verified}
		var grants []*envelope.Envelope
		g, missing, err := t.grant(next, person.User, next.Access(person.User))
		if err != nil {
			return err
		}
		if g != nil {
			grants = append(grants, g)
			gr, _ := team.PeekGrant(g)
			for _, env := range gr.Envs {
				out.Granted = append(out.Granted, env.Name)
			}
		}
		out.Missing = missing
		return t.commit(next, []*envelope.Envelope{e}, grants)
	})
	return out, err
}

// checkPerson checks that an account belongs to its GitHub login.
func checkPerson(person team.Person, proof *wire.AccountProof, cs *chain.State, accountKey string) (string, error) {
	if accountKey != "" {
		if normalizeWords(accountKey) != cs.AccountWords() {
			return "", fmt.Errorf("those are not the account key words of %s's account on this server; do not add it", person.Login)
		}
		return team.VerifiedAccountKey, nil
	}
	if proof == nil {
		return "", fmt.Errorf("%w: %s has not published a GitHub SSH proof. Ask them to run 'esec vault team prove', or add them with --account-key and the words their 'esec vault status' shows", ErrNoProof, person.Login)
	}
	tp := team.AccountProof(*proof)
	if err := tp.Check(); err != nil || !strings.EqualFold(proof.Login, person.Login) {
		return "", fmt.Errorf("the GitHub proof of %s is not for that login", person.Login)
	}
	keys, err := share.FetchGitHubKeys(person.Login, &http.Client{Timeout: 15 * time.Second}, "")
	if err != nil {
		return "", err
	}
	if err := team.VerifyAccountProof(&tp, person, keys); err != nil {
		return "", fmt.Errorf("the GitHub proof of %s does not check out: %w", person.Login, err)
	}
	return team.VerifiedGitHubSSH, nil
}

// member finds an active member by login.
func member(st *team.State, login string) (*team.MemberState, error) {
	for _, m := range st.ActiveMembers() {
		if strings.EqualFold(m.Login, login) {
			return m, nil
		}
	}
	return nil, fmt.Errorf("%s is not a member of %s", login, st.Project)
}

// UpdateResult describes a change of access.
type UpdateResult struct {
	Granted, Missing []string
	// Exposed lists environments the member can no longer read; their
	// keys need replacing.
	Exposed []string
}

// UpdateMember changes a member's role and environments, and sends the keys
// they gained.
func (a *Account) UpdateMember(ctx context.Context, project, login string, admin bool, envs []string) (*UpdateResult, error) {
	var out *UpdateResult
	err := a.withTeam(ctx, func(t *teamCtx) error {
		st, err := t.requireAdmin(project)
		if err != nil {
			return err
		}
		m, err := member(st, login)
		if err != nil {
			return err
		}
		envs = team.SortEnvs(envs)
		if admin {
			envs = nil
		}
		before := st.Access(m.User)
		e, next, err := t.link(st, team.TypeMemberUpdate, team.MemberUpdateBody{User: m.User, Admin: admin, Envs: envs})
		if err != nil {
			return err
		}
		after := next.Access(m.User)
		out = &UpdateResult{}
		var gained []string
		for _, n := range after {
			if !slices.Contains(before, n) {
				gained = append(gained, n)
			}
		}
		for _, n := range before {
			if !slices.Contains(after, n) {
				out.Exposed = append(out.Exposed, n)
			}
		}
		var grants []*envelope.Envelope
		if len(gained) > 0 {
			g, missing, err := t.grant(next, m.User, gained)
			if err != nil {
				return err
			}
			out.Missing = missing
			if g != nil {
				grants = append(grants, g)
				out.Granted = slices.DeleteFunc(slices.Clone(gained), func(n string) bool { return slices.Contains(missing, n) })
			}
		}
		return t.commit(next, []*envelope.Envelope{e}, grants)
	})
	return out, err
}

// RemoveMember removes a member (or, for this account's own login, leaves
// the project). It returns the environments the member could read, whose
// keys now need replacing.
func (a *Account) RemoveMember(ctx context.Context, project, login, reason string) ([]string, error) {
	var out []string
	err := a.withTeam(ctx, func(t *teamCtx) error {
		st, err := t.state(project)
		if err != nil {
			return err
		}
		if st == nil {
			return fmt.Errorf("%s is not a shared project", project)
		}
		m, err := member(st, login)
		if err != nil {
			return err
		}
		if m.User != a.State.User && !st.Admin(a.State.User) {
			return fmt.Errorf("only an admin of %s can remove others", project)
		}
		out = st.Access(m.User)
		e, next, err := t.link(st, team.TypeMemberRemove, team.MemberRemoveBody{User: m.User, Reason: reason})
		if err != nil {
			return err
		}
		return t.commit(next, []*envelope.Envelope{e}, nil)
	})
	return out, err
}

// PublishResult describes a published environment key.
type PublishResult struct {
	PublicKey string
	Sent      []string
}

// PublishEnv makes this device's key for env the project's key: a new
// environment, or a key replaced with 'env rotate'. It sends the key to
// everyone who reads env.
func (a *Account) PublishEnv(ctx context.Context, project, env, reason string) (*PublishResult, error) {
	var out *PublishResult
	err := a.withTeam(ctx, func(t *teamCtx) error {
		st, err := t.requireAdmin(project)
		if err != nil {
			return err
		}
		local, err := a.localEnvs(project)
		if err != nil {
			return err
		}
		priv, ok := local[env]
		if !ok {
			return fmt.Errorf("this device has no %s key for %s", env, project)
		}
		pub, _ := team.PublicHex(priv)
		if cur, ok := st.Envs[env]; ok && cur.PublicKey == pub {
			out = &PublishResult{PublicKey: pub}
			return nil
		}
		e, next, err := t.link(st, team.TypeEnvSet, team.EnvSetBody{Env: team.Env{Name: env, PublicKey: pub}, Reason: reason})
		if err != nil {
			return err
		}
		out = &PublishResult{PublicKey: pub}
		grants, sent, err := t.grantsOf(next, env)
		if err != nil {
			return err
		}
		out.Sent = sent
		if err := t.commit(next, []*envelope.Envelope{e}, grants); err != nil {
			return err
		}
		t.pins.hold(project, env, pub)
		return t.ackOwn(next)
	})
	return out, err
}

// grantsOf seals the current key of env to everyone in st who reads it
// but this account, and names them.
func (t *teamCtx) grantsOf(st *team.State, env string) ([]*envelope.Envelope, []string, error) {
	var grants []*envelope.Envelope
	var sent []string
	for _, m := range st.ActiveMembers() {
		if m.User == t.a.State.User || !m.Has(env) {
			continue
		}
		g, _, err := t.grant(st, m.User, []string{env})
		if err != nil {
			return nil, nil, err
		}
		if g != nil {
			grants, sent = append(grants, g), append(sent, m.Login)
		}
	}
	for _, m := range st.ActiveMachines() {
		if !m.Has(env) {
			continue
		}
		g, missing, err := t.grant(st, m.ID, m.Envs)
		if err != nil {
			return nil, nil, err
		}
		if g != nil && len(missing) == 0 {
			grants, sent = append(grants, g), append(sent, m.Name)
		}
	}
	for _, pg := range st.ActiveGroups() {
		if !pg.Has(env) {
			continue
		}
		// A group's machines need the new key at once; a group this device
		// cannot read is left to its admins' next sync.
		g, missing, err := t.grant(st, team.GroupHolder(pg.Group), pg.Envs)
		if err == nil && g != nil && len(missing) == 0 {
			grants, sent = append(grants, g), append(sent, "group "+pg.Group)
		}
	}
	return grants, sent, nil
}

// SharedRole reports whether project is shared and whether this account is
// one of its admins. It does not verify anything; commands use it to decide
// whether to involve the team at all.
func (a *Account) SharedRole(ctx context.Context, project string) (shared, admin bool, err error) {
	list, err := a.Client.Projects(ctx)
	if err != nil {
		return false, false, err
	}
	for _, p := range list {
		if p.ID == project {
			return true, p.Admin, nil
		}
	}
	return false, false, nil
}

// TeamSyncOptions configures TeamSync.
type TeamSyncOptions struct {
	// Interactive lets TeamSync ask before replacing a key this device
	// already holds under another value.
	Interactive bool
	// Accept decides whether to take in the keys of a project this device
	// never accepted; nil accepts none. It is told who added this account
	// and what it may read.
	Accept func(Invite) bool
}

// Invite is a shared project this account was added to that this device
// has not accepted yet.
type Invite struct {
	Project string
	AddedBy string
	Admin   bool
	Envs    []string
}

// TeamSyncResult summarizes a team sync.
type TeamSyncResult struct {
	// Imported lists "project env" keys received.
	Imported []string
	// Sent lists "name: project envs" keys sent to others.
	Sent []string
	// Conflicts lists received keys left alone because this device holds
	// another key for the environment.
	Conflicts []string
	// Dropped lists grants that no longer applied.
	Dropped []string
	// Rotations maps projects to the environments this account reads that
	// need a new key; Admin says which of those projects it administers.
	Rotations map[string][]string
	Admin     map[string]bool
	// Unsent lists keys no admin device here could send.
	Unsent []string
	// Invites lists projects whose keys wait until this device accepts
	// them.
	Invites []Invite
	// Elsewhere describes changes this account made to its projects from
	// another device. A revoked device still holds an old user key, so one
	// the person does not recognize needs checking.
	Elsewhere []string
	// Problems lists projects that could not be synced, such as a chain
	// that does not verify.
	Problems []string
	// GroupTodos lists machine groups with machines waiting to join or web
	// changes waiting to be signed; GroupRotations those whose key a
	// removed machine still holds.
	GroupTodos     []GroupTodo
	GroupRotations []string
}

// TeamSync imports keys waiting for this account and, as an admin, sends
// keys that members and machines are missing.
func (a *Account) TeamSync(ctx context.Context, opts TeamSyncOptions) (*TeamSyncResult, error) {
	res := &TeamSyncResult{Rotations: map[string][]string{}, Admin: map[string]bool{}}
	err := a.withTeam(ctx, func(t *teamCtx) error {
		if err := t.importGrants(res, opts); err != nil {
			return err
		}
		t.fulfilGroups(res)
		err := t.fulfil(res)
		res.Elsewhere = t.elsewhere
		return err
	})
	return res, err
}

func (t *teamCtx) importGrants(res *TeamSyncResult, opts TeamSyncOptions) error {
	items, err := t.a.Client.Grants(t.ctx)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return nil
	}
	me := team.Recipient{ID: t.a.State.User, Version: t.own.UKeyVersion, EncPub: t.id.Public}
	ack := wire.GrantAck{IDs: []int64{}}
	for _, it := range items {
		st, err := t.state(it.Project)
		if err != nil {
			res.problem(it.Project, err)
			continue
		}
		if st == nil {
			ack.IDs = append(ack.IDs, it.ID)
			continue
		}
		_, keys, err := team.Open(it.Grant, st, t.chains, me, t.id.Private)
		if err != nil {
			res.Dropped = append(res.Dropped, fmt.Sprintf("%s: %v", it.Project, err))
			ack.IDs = append(ack.IDs, it.ID)
			continue
		}
		if !t.accept(st, res, opts) {
			continue
		}
		imported, conflicts, err := t.a.importKeys(st, keys, t.pins, opts.Interactive)
		if err != nil {
			return err
		}
		res.Imported = append(res.Imported, imported...)
		res.Conflicts = append(res.Conflicts, conflicts...)
		if len(conflicts) > 0 {
			continue
		}
		ack.IDs = append(ack.IDs, it.ID)
		for name := range keys {
			ack.Holdings = append(ack.Holdings, wire.Holding{Project: st.Project, Env: name, PublicKey: st.Envs[name].PublicKey})
		}
	}
	if len(ack.IDs) == 0 {
		return nil
	}
	return t.a.Client.AckGrants(t.ctx, ack)
}

func (r *TeamSyncResult) problem(project string, err error) {
	for _, p := range r.Problems {
		if strings.HasPrefix(p, project+": ") {
			return
		}
	}
	r.Problems = append(r.Problems, project+": "+err.Error())
}

// describeLink says what a link did, for people.
func describeLink(st *team.State, l team.Link) string {
	var b struct {
		Member  team.Person  `json:"member"`
		User    string       `json:"user"`
		Env     team.Env     `json:"env"`
		Machine team.Machine `json:"machine"`
		ID      string       `json:"id"`
	}
	_ = json.Unmarshal(l.Body, &b)
	switch l.Type {
	case team.TypeMemberAdd:
		return "added " + b.Member.Login
	case team.TypeMemberUpdate:
		return "changed what " + loginOf(st, b.User) + " reads"
	case team.TypeMemberRemove:
		return "removed " + loginOf(st, b.User)
	case team.TypeEnvSet:
		return "set a new key for " + b.Env.Name
	case team.TypeMachineAdd:
		return "added the machine " + b.Machine.Name
	case team.TypeMachineRemove:
		if m := st.Machines[b.ID]; m != nil {
			return "removed the machine " + m.Name
		}
	case team.TypeGroupSet:
		var g team.GroupSetBody
		_ = json.Unmarshal(l.Body, &g)
		if len(g.Envs) == 0 {
			return "took away the machine group " + g.Group + "'s access"
		}
		return "let the machine group " + g.Group + " read " + strings.Join(g.Envs, ", ")
	}
	return l.Type
}

// accept reports whether this device takes in keys of st. Someone who can
// create a shared project can name it after any repository; taking its keys
// without asking would let them hand this device keys for a project it
// already has, or will create. So a project's first keys wait until the
// person accepts the project.
func (t *teamCtx) accept(st *team.State, res *TeamSyncResult, opts TeamSyncOptions) bool {
	if t.pins.Accepted[st.Project] {
		return true
	}
	// A project this account already acted in (created, or changed as an
	// admin) was accepted on one of its devices.
	for _, l := range st.Links {
		if l.Signer == t.a.State.User {
			t.pins.Accepted[st.Project] = true
			return true
		}
	}
	m, ok := st.Member(t.a.State.User)
	if !ok {
		return false
	}
	inv := Invite{Project: st.Project, AddedBy: loginOf(st, m.AddedBy), Admin: m.Admin, Envs: st.Access(m.User)}
	if opts.Accept == nil || !opts.Accept(inv) {
		for _, seen := range res.Invites {
			if seen.Project == inv.Project {
				return false
			}
		}
		res.Invites = append(res.Invites, inv)
		return false
	}
	t.pins.Accepted[st.Project] = true
	return true
}

func loginOf(st *team.State, user string) string {
	if m := st.Members[user]; m != nil {
		return m.Login
	}
	return user
}

// importKeys merges granted keys into the project's keyring. A key replaces
// the one this device holds when that one is an earlier key of the same
// environment that this device got from or gave to the project; the
// replaced key stays under its public key, so older files still decrypt.
// Any other key is kept unless the person agrees: a grant must not quietly
// swap a key this device made, nor one a chain merely claims was earlier.
func (a *Account) importKeys(st *team.State, keys map[string]string, pins *TeamPins, interactive bool) (imported, conflicts []string, err error) {
	entries, err := a.KS.Read(st.Project)
	if errors.Is(err, os.ErrNotExist) {
		entries, err = map[string]string{}, nil
	}
	if err != nil {
		return nil, nil, err
	}
	changed := false
	names := make([]string, 0, len(keys))
	for n := range keys {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		priv := keys[n]
		pub := st.Envs[n].PublicKey
		entry := team.EnvKey(n)
		cur, ok := entries[entry]
		switch {
		case ok && cur == priv:
		case ok:
			oldPub, perr := team.PublicHex(cur)
			known := perr == nil && slices.Contains(st.Envs[n].Retired, oldPub) && slices.Contains(pins.Held[st.Project][n], oldPub)
			if !known && (!interactive || !a.UI.Confirm(fmt.Sprintf("Your %s key of %s is not one the team ever used. Replace it with the team's key? Yours is kept under its public key.", n, st.Project))) {
				conflicts = append(conflicts, st.Project+" "+n)
				continue
			}
			if perr == nil {
				entries[team.PubKeyEntry(oldPub)] = cur
			}
			entries[entry] = priv
			changed = true
			imported = append(imported, st.Project+" "+n+" (new key)")
		default:
			entries[entry] = priv
			changed = true
			imported = append(imported, st.Project+" "+n)
		}
		if entries[team.PubKeyEntry(pub)] != priv {
			entries[team.PubKeyEntry(pub)] = priv
			changed = true
		}
		pins.hold(st.Project, n, pub)
	}
	if changed {
		if err := a.KS.Write(st.Project, entries, true); err != nil {
			return nil, nil, err
		}
	}
	return imported, conflicts, nil
}

// fulfil sends, for every project this account administers, the keys its
// members and machines are missing, and reports keys to rotate.
func (t *teamCtx) fulfil(res *TeamSyncResult) error {
	list, err := t.a.Client.Projects(t.ctx)
	if err != nil {
		return err
	}
	for _, p := range list {
		st, err := t.state(p.ID)
		if err != nil {
			res.problem(p.ID, err)
			continue
		}
		if st == nil {
			continue
		}
		if err := t.ackMissingOwn(st, p.ID); err != nil {
			return err
		}
		for _, n := range t.rotations(st) {
			if st.HasAccess(t.a.State.User, n) {
				res.Rotations[p.ID] = append(res.Rotations[p.ID], n)
			}
		}
		if !st.Admin(t.a.State.User) {
			continue
		}
		res.Admin[p.ID] = true
		if err := t.fulfilProject(st, res); err != nil {
			return err
		}
	}
	return nil
}

// fulfilProject sends the keys the server reports missing in one project,
// after checking each against the verified chain.
func (t *teamCtx) fulfilProject(st *team.State, res *TeamSyncResult) error {
	status, err := t.a.Client.ProjectStatus(t.ctx, st.Project)
	if err != nil {
		return err
	}
	var grants []*envelope.Envelope
	for _, h := range status.Holders {
		if h.ID == t.a.State.User {
			continue
		}
		var want []string
		for n, v := range h.Envs {
			if v == wire.KeyMissing && st.HasAccess(h.ID, n) {
				want = append(want, n)
			}
		}
		if len(want) == 0 {
			continue
		}
		name := h.ID
		m, isMachine := st.Machine(h.ID)
		if isMachine {
			// A machine's grant carries all of its environments.
			want, name = m.Envs, m.Name
		} else if mem, ok := st.Members[h.ID]; ok {
			name = mem.Login
		} else if id, ok := strings.CutPrefix(h.ID, team.GroupHolderPrefix); ok {
			pg, ok := st.Group(id)
			if !ok {
				continue
			}
			// So does a group's.
			want, name, isMachine = pg.Envs, "group "+id, true
		}
		sort.Strings(want)
		g, missing, err := t.grant(st, h.ID, want)
		if err != nil {
			if strings.HasPrefix(h.ID, team.GroupHolderPrefix) {
				res.Unsent = append(res.Unsent, fmt.Sprintf("%s: %s: %v", name, st.Project, err))
				continue
			}
			return err
		}
		if len(missing) > 0 {
			res.Unsent = append(res.Unsent, fmt.Sprintf("%s: %s %s", name, st.Project, strings.Join(missing, ",")))
			if isMachine {
				continue
			}
		}
		if g != nil {
			grants = append(grants, g)
			sent := slices.DeleteFunc(slices.Clone(want), func(n string) bool { return slices.Contains(missing, n) })
			res.Sent = append(res.Sent, fmt.Sprintf("%s: %s %s", name, st.Project, strings.Join(sent, ",")))
		}
	}
	if len(grants) == 0 {
		return nil
	}
	return t.commit(st, nil, grants)
}

// ackMissingOwn records keys this device holds that the server does not
// know the account has (for example after it created or rotated them).
func (t *teamCtx) ackMissingOwn(st *team.State, project string) error {
	have := t.localKeys(st)
	if len(have) == 0 {
		return nil
	}
	status, err := t.a.Client.ProjectStatus(t.ctx, project)
	if err != nil {
		return err
	}
	for _, h := range status.Holders {
		if h.ID != t.a.State.User {
			continue
		}
		for n, v := range h.Envs {
			if _, ok := have[n]; ok && v != wire.KeyHeld {
				return t.ackOwn(st)
			}
		}
	}
	return nil
}

// ProveAccount publishes a proof that this account belongs to its GitHub
// login: sign signs the statement with an SSH key registered on GitHub and
// returns the armored SSHSIG.
func (a *Account) ProveAccount(ctx context.Context, sign func(message []byte) ([]byte, error)) error {
	if err := a.requireConfirmed(); err != nil {
		return err
	}
	own, err := a.VerifiedChain(ctx)
	if err != nil {
		return err
	}
	p := team.AccountProof{User: a.State.User, Login: a.State.Login, Root: own.Root()}
	sig, err := sign(team.ProofStatement(p.User, p.Login, p.Root))
	if err != nil {
		return err
	}
	p.Signature = string(sig)
	keys, err := share.FetchGitHubKeys(p.Login, &http.Client{Timeout: 15 * time.Second}, "")
	if err != nil {
		return err
	}
	if err := team.VerifyAccountProof(&p, team.Person{User: p.User, Login: p.Login, Root: p.Root}, keys); err != nil {
		return fmt.Errorf("that key cannot prove the account: %w", err)
	}
	return a.Client.PutProof(ctx, wire.AccountProof(p))
}

// ---- machines ----

// CreateMachine adds a machine to project that reads envs, and sends it
// their keys. The returned key is the machine's secret.
func (a *Account) CreateMachine(ctx context.Context, project, name string, envs []string, policy *team.OIDCPolicy) (*team.MachineKey, error) {
	var out *team.MachineKey
	err := a.withTeam(ctx, func(t *teamCtx) error {
		st, err := t.requireAdmin(project)
		if err != nil {
			return err
		}
		for _, m := range st.ActiveMachines() {
			if m.Name == name {
				return fmt.Errorf("%s already has a machine named %s", project, name)
			}
		}
		key, m, err := team.NewMachineKey(a.State.Server, project, st.Root(), name, a.Now())
		if err != nil {
			return err
		}
		envs = team.SortEnvs(envs)
		e, next, err := t.link(st, team.TypeMachineAdd, team.MachineAddBody{Machine: m, Envs: envs, OIDC: policy})
		if err != nil {
			return err
		}
		g, missing, err := t.grant(next, m.ID, envs)
		if err != nil {
			return err
		}
		if len(missing) > 0 {
			return fmt.Errorf("this device has no current key for %s of %s", strings.Join(missing, ", "), project)
		}
		if err := t.commit(next, []*envelope.Envelope{e}, []*envelope.Envelope{g}); err != nil {
			return err
		}
		out = key
		return nil
	})
	return out, err
}

// RemoveMachine removes a machine by id or name and returns the
// environments it could read.
func (a *Account) RemoveMachine(ctx context.Context, project, nameOrID, reason string) (*team.MachineState, error) {
	var out *team.MachineState
	err := a.withTeam(ctx, func(t *teamCtx) error {
		st, err := t.requireAdmin(project)
		if err != nil {
			return err
		}
		var found []*team.MachineState
		for _, m := range st.ActiveMachines() {
			if m.ID == nameOrID || m.Name == nameOrID {
				found = append(found, m)
			}
		}
		switch len(found) {
		case 0:
			return fmt.Errorf("%s has no machine %s", project, nameOrID)
		case 1:
		default:
			return fmt.Errorf("several machines are named %s; use its id", nameOrID)
		}
		e, next, err := t.link(st, team.TypeMachineRemove, team.MachineRemoveBody{ID: found[0].ID, Reason: reason})
		if err != nil {
			return err
		}
		out = found[0]
		return t.commit(next, []*envelope.Envelope{e}, nil)
	})
	return out, err
}
