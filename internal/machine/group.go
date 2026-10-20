package machine

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/client"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/storage"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// FileEnv names the machine key file of a host that joined a group.
const FileEnv = "ESEC_VAULT_MACHINE_FILE"

// DefaultFile is where a host keeps the key it joined a group with:
// /etc/esec-vault/machine.key for root on Linux, else machine.key in the
// esec configuration directory.
func DefaultFile() string {
	if f := os.Getenv(FileEnv); f != "" {
		return f
	}
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		return "/etc/esec-vault/machine.key"
	}
	home := os.Getenv("ESEC_VAULT_HOME")
	if home == "" {
		if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			home = filepath.Join(xdg, "esec")
		} else if h, err := os.UserHomeDir(); err == nil {
			home = filepath.Join(h, ".config", "esec")
		}
	}
	return filepath.Join(home, "machine.key")
}

// Credential is what a machine identifies with: a project machine key
// (esecm1_) or a machine group key (esecg1_).
type Credential struct {
	Project *team.MachineKey
	Group   *team.CredKey
	// From says where it was found.
	From string
}

// LoadCredential reads the machine's key from ESEC_VAULT_MACHINE_KEY (a key,
// or @file), or else from the key file a host joined a group with.
func LoadCredential() (*Credential, error) {
	v := strings.TrimSpace(os.Getenv(KeyEnv))
	from := KeyEnv
	if path, ok := strings.CutPrefix(v, "@"); ok {
		data, err := os.ReadFile(path) //nolint:gosec // the operator names the file
		if err != nil {
			return nil, err
		}
		v, from = strings.TrimSpace(string(data)), path
	}
	if v == "" {
		path := DefaultFile()
		data, err := os.ReadFile(path) //nolint:gosec // this host's own key file
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no machine key: set %s to a key from 'esec vault machine create' or 'esec vault group token', or join a group with 'esec-vault machine join'", KeyEnv)
		}
		if err != nil {
			return nil, err
		}
		v, from = strings.TrimSpace(string(data)), path
	}
	if strings.HasPrefix(v, team.CredPrefix) {
		k, err := team.ParseCredKey(v)
		if err != nil {
			return nil, err
		}
		return &Credential{Group: k, From: from}, nil
	}
	k, err := team.ParseToken(v)
	if err != nil {
		return nil, err
	}
	return &Credential{Project: k, From: from}, nil
}

// Fetch gets the keys of either kind of credential.
func (c *Credential) Fetch(ctx context.Context, oidcToken string) (*Keys, error) {
	if c.Group != nil {
		return FetchGroup(ctx, c.Group, oidcToken)
	}
	return Fetch(ctx, c.Project, oidcToken)
}

// Server returns the credential's server.
func (c *Credential) Server() string {
	if c.Group != nil {
		return c.Group.Server
	}
	return c.Project.Server
}

func nonce() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// FetchGroup gets a group machine's or token's keys and verifies them.
func FetchGroup(ctx context.Context, key *team.CredKey, oidcToken string) (*Keys, error) {
	c, err := client.New(key.Server)
	if err != nil {
		return nil, err
	}
	n, err := nonce()
	if err != nil {
		return nil, err
	}
	req := wire.GroupKeysRequest{Group: key.Group, ID: key.ID, Timestamp: time.Now().Unix(), Nonce: n, OIDCToken: oidcToken}
	req.Sig = ed25519.Sign(key.Sign(), team.GroupKeysMessage(req.Group, req.ID, req.Timestamp, req.Nonce, hashToken(oidcToken)))
	resp, err := c.FleetKeys(ctx, req)
	if err != nil {
		return nil, err
	}
	return VerifyGroup(key, resp, time.Now())
}

// chainsFrom verifies the user chains a server sent, each once.
func chainsFrom(sent map[string][]*envelope.Envelope) team.Chains {
	verified := map[string]*chain.State{}
	return func(user string) (*chain.State, error) {
		if st, ok := verified[user]; ok {
			return st, nil
		}
		links, ok := sent[user]
		if !ok {
			return nil, fmt.Errorf("the server sent no user chain for %s", user)
		}
		st, err := chain.Verify(user, links)
		if err != nil {
			return nil, err
		}
		verified[user] = st
		return st, nil
	}
}

// VerifyGroup checks a server response against a group credential: the
// group chain must start at the credential's root and list it; the group
// key must match the chain; each project must be one the group chain
// trusts, verified from the root it names, and grant the group its keys.
// A project that fails is reported in Problems; the others still count.
func VerifyGroup(key *team.CredKey, resp *wire.GroupKeys, now time.Time) (*Keys, error) {
	chains := chainsFrom(resp.Chains)
	if len(resp.Links) == 0 || resp.Links[0].Hash() != key.Root {
		return nil, errors.New("the server's group chain does not start where this machine key's does; refusing it")
	}
	gs, err := team.VerifyGroup(key.Group, resp.Links, chains)
	if err != nil {
		return nil, fmt.Errorf("the group chain does not verify: %w", err)
	}
	cred, ok := gs.Cred(key.ID)
	if !ok || !key.Matches(cred.Credential) {
		return nil, fmt.Errorf("this machine is no longer part of %s", key.Group)
	}
	if cred.Expired(now) {
		return nil, fmt.Errorf("this token of %s expired on %s", key.Group, cred.Expires.Format(time.RFC3339))
	}
	if resp.KeyGrant == nil {
		return nil, errors.New("the server sent no group key")
	}
	pub, priv := key.Keys()
	gpriv, err := team.OpenKeyGrant(resp.KeyGrant, gs, chains, team.Recipient{ID: key.ID, EncPub: pub}, priv)
	if err != nil {
		return nil, fmt.Errorf("the group key does not verify: %w", err)
	}
	gpub, err := chain.ParseKey32(gs.Key.EncPub)
	if err != nil {
		return nil, err
	}
	me := team.Recipient{ID: team.GroupHolder(key.Group), Version: gs.Key.Version, EncPub: gpub}
	out := &Keys{Group: key.Group, Machine: key.ID, Name: cred.Name, Projects: map[string]map[string]string{}}
	for _, p := range resp.Projects {
		keys, err := openProject(p, gs, chains, me, gpriv)
		if err != nil {
			out.Problems = append(out.Problems, p.Project+": "+err.Error())
			continue
		}
		out.Projects[p.Project] = keys
	}
	sort.Strings(out.Problems)
	return out, nil
}

func openProject(p wire.GroupProjectKeys, gs *team.GroupState, chains team.Chains, me team.Recipient, gpriv [32]byte) (map[string]string, error) {
	root, ok := gs.Access[p.Project]
	if !ok {
		return nil, errors.New("the group does not take keys from this project")
	}
	if len(p.Links) == 0 || p.Links[0].Hash() != root {
		return nil, errors.New("the project chain does not start where the group chain says")
	}
	ps, err := team.Verify(p.Project, p.Links, chains)
	if err != nil {
		return nil, fmt.Errorf("the project chain does not verify: %w", err)
	}
	pg, ok := ps.Group(gs.Group)
	if !ok || pg.Root != gs.Root() {
		return nil, errors.New("the project does not grant this group anything")
	}
	if p.Grant == nil {
		return nil, errors.New("no admin's device has sealed its keys to the group's current key yet")
	}
	_, keys, err := team.Open(p.Grant, ps, chains, me, gpriv)
	if err != nil {
		return nil, fmt.Errorf("its keys do not verify: %w", err)
	}
	return keys, nil
}

// ---- joining ----

// JoinOptions configures Join.
type JoinOptions struct {
	Server string
	Group  string
	Name   string
	// Token enrolls the machine at once instead of asking an admin.
	Token *team.CredKey
	// Fingerprint, when set, are the group's words (team.GroupWords) from
	// an admin's device; the group the server names must match them.
	Fingerprint string
	// OIDCToken proves the workload to a token with an OIDC policy.
	OIDCToken string
	// Wait is called with the words to compare while the machine waits for
	// an admin; it returns false to stop waiting.
	Wait func(words string) bool
	// Poll is how often to ask whether the machine was let in.
	Poll time.Duration
}

// Join creates this host's machine key and joins a group: at once with an
// enrollment token, or by asking an admin, who compares the words this
// machine shows. It returns the new key; the caller saves it.
func Join(ctx context.Context, opts JoinOptions) (*team.CredKey, error) {
	if opts.Token != nil {
		return enroll(ctx, opts)
	}
	if err := team.ValidGroup(opts.Group); err != nil {
		return nil, err
	}
	c, err := client.New(opts.Server)
	if err != nil {
		return nil, err
	}
	// The root is filled in once the server names it; the words the admin
	// compares prove it.
	key, cred, err := team.NewCredKey(c.Base, opts.Group, strings.Repeat("0", 64), team.KindMachine, opts.Name, time.Now())
	if err != nil {
		return nil, err
	}
	ask := func(status bool) (*wire.GroupJoinResult, error) {
		n, err := nonce()
		if err != nil {
			return nil, err
		}
		action := "join"
		if status {
			action = "status"
		}
		req := wire.GroupJoin{Group: opts.Group, Machine: cred.ID, Name: cred.Name, EncPub: cred.EncPub, SignPub: cred.SignPub, Timestamp: time.Now().Unix(), Nonce: n}
		req.Sig = ed25519.Sign(key.Sign(), team.JoinMessage(action, opts.Group, cred, req.Timestamp, req.Nonce))
		return c.FleetJoin(ctx, req, status)
	}
	res, err := ask(false)
	if err != nil {
		return nil, err
	}
	if res.Root == "" || team.ValidGroup(opts.Group) != nil {
		return nil, errors.New("the server named no group root")
	}
	if opts.Fingerprint != "" && normalizeWords(opts.Fingerprint) != team.GroupWords(opts.Group, res.Root) {
		return nil, fmt.Errorf("the server's %s is not the group with that fingerprint; do not use this server", opts.Group)
	}
	key.Root = res.Root
	if res, err = waitForAdmin(ctx, opts, team.JoinWords(opts.Group, res.Root, cred), res, ask); err != nil {
		return nil, err
	}
	if res.Status != wire.JoinApproved {
		return nil, fmt.Errorf("an admin of %s turned the request down, or it expired", opts.Group)
	}
	// Check it for real: the group chain must start at the root and list
	// this machine with its key, and the group key must open.
	if _, err := FetchGroup(ctx, key, ""); err != nil {
		return nil, fmt.Errorf("let in, but the group does not check out: %w", err)
	}
	return key, nil
}

// waitForAdmin asks whether the machine was let in until it no longer
// waits, showing the words through opts.Wait.
func waitForAdmin(ctx context.Context, opts JoinOptions, words string, res *wire.GroupJoinResult, ask func(status bool) (*wire.GroupJoinResult, error)) (*wire.GroupJoinResult, error) {
	poll := opts.Poll
	if poll == 0 {
		poll = 3 * time.Second
	}
	for res.Status == wire.JoinPending {
		if opts.Wait != nil && !opts.Wait(words) {
			return nil, errors.New("stopped waiting; run the command again to ask again")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(poll):
		}
		var err error
		if res, err = ask(true); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// enroll adds this host to a group with an enrollment token: it signs the
// machine_add link and seals the group key to the new machine with the
// token's keys.
func enroll(ctx context.Context, opts JoinOptions) (*team.CredKey, error) {
	tok := opts.Token
	if tok.Kind() != team.KindToken {
		return nil, errors.New("that is a machine key, not an enrollment token; use it as ESEC_VAULT_MACHINE_KEY directly")
	}
	c, err := client.New(tok.Server)
	if err != nil {
		return nil, err
	}
	// Sign the next link against the latest verified chain; retry when
	// another machine enrolled in between.
	var last error
	for range 3 {
		n, err := nonce()
		if err != nil {
			return nil, err
		}
		req := wire.GroupKeysRequest{Group: tok.Group, ID: tok.ID, Timestamp: time.Now().Unix(), Nonce: n, OIDCToken: opts.OIDCToken}
		req.Sig = ed25519.Sign(tok.Sign(), team.GroupKeysMessage(req.Group, req.ID, req.Timestamp, req.Nonce, hashToken(opts.OIDCToken)))
		gk, err := c.FleetKeys(ctx, req)
		if err != nil {
			return nil, err
		}
		chains := chainsFrom(gk.Chains)
		if len(gk.Links) == 0 || gk.Links[0].Hash() != tok.Root {
			return nil, errors.New("the server's group chain does not start where the token's does; refusing it")
		}
		gs, err := team.VerifyGroup(tok.Group, gk.Links, chains)
		if err != nil {
			return nil, err
		}
		pub, priv := tok.Keys()
		gpriv, err := team.OpenKeyGrant(gk.KeyGrant, gs, chains, team.Recipient{ID: tok.ID, EncPub: pub}, priv)
		if err != nil {
			return nil, fmt.Errorf("the token's group key does not verify: %w", err)
		}
		t, _ := gs.Cred(tok.ID)
		key, cred, err := team.NewCredKey(tok.Server, tok.Group, tok.Root, team.KindMachine, opts.Name, time.Now())
		if err != nil {
			return nil, err
		}
		cred.OIDC = t.OIDC
		link, err := gs.NewLink(team.GroupMachineAdd, team.GroupMachineAddBody{Machine: cred}, time.Now(), tok.ID, 0, 0, tok.Sign())
		if err != nil {
			return nil, err
		}
		next, err := gs.Next(link, chains)
		if err != nil {
			return nil, err
		}
		mpub, _ := key.Keys()
		kg, err := team.NewKeyGrant(next, tok.ID, 0, tok.Sign(), team.Recipient{ID: key.ID, EncPub: mpub}, gpriv, time.Now())
		if err != nil {
			return nil, err
		}
		err = c.FleetEnroll(ctx, wire.GroupEnroll{Group: tok.Group, Link: link, KeyGrant: kg, OIDCToken: opts.OIDCToken})
		if client.IsCode(err, wire.ErrConflict) {
			last = err
			continue
		}
		if err != nil {
			return nil, err
		}
		return key, nil
	}
	return nil, last
}

// SaveKey writes a host's machine key to path (0600), refusing to replace
// another one.
func SaveKey(path string, key *team.CredKey) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s exists already; this host has a machine key (remove the file to join again)", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return storage.Write(path, []byte(key.String()+"\n"))
}

// normalizeWords accepts words separated by spaces, dashes or commas.
func normalizeWords(s string) string {
	return strings.Join(strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return r == '-' || r == ' ' || r == ',' }), "-")
}

// hashToken is the hex SHA-256 of an OIDC token, or "" for none.
func hashToken(token string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
