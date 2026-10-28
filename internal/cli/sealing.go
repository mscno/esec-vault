package cli

// Sealing environment keys in the repository (.esec/<env>.age): who seals
// (this machine's identity, its account), the directory that resolves
// readers to keys, and opening keys: from this device's cache, from the
// seal with this identity, or with a touch of a security key.

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/mscno/esec/pkg/projectfile"
	coreseal "github.com/mscno/esec/pkg/seal"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/caller"
	"github.com/mscno/esec-vault/internal/guard"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/seal"
	"github.com/mscno/esec-vault/internal/securitykey"
)

// sealing is what a command needs to seal and open environment keys.
type sealing struct {
	ctx  *cliCtx
	acct *account.Account // nil when not signed in
	id   *identity.Identity
	self *seal.Person
	dir  seal.Directory
	sign seal.Signer
	ks   *keystore.Store
}

// newSealing sets up sealing for this machine's identity, and its account
// when it is signed in. Signed in, people are resolved through their
// chains; otherwise only this identity and keys named directly can be
// readers.
func newSealing(ctx *cliCtx) (*sealing, error) {
	id, err := identity.Load(ctx.Keyring)
	if errors.Is(err, identity.ErrNotFound) {
		return nil, errors.New("no identity on this machine to seal keys with: esec vault setup")
	}
	if err != nil {
		return nil, err
	}
	if id.Sign == nil {
		if id, _, err = identity.EnsureSigningKey(ctx.Keyring); err != nil {
			return nil, err
		}
	}
	_, master, err := identity.BackupMaterial(id)
	if err != nil {
		return nil, fmt.Errorf("your recovery key: %w", err)
	}
	recovery, err := coreseal.X25519Recipient(hex.EncodeToString(master[:]))
	if err != nil {
		return nil, err
	}
	s := &sealing{ctx: ctx, id: id, ks: keystore.New()}
	s.self = &seal.Person{EncPub: id.PublicHex(), MasterPub: hex.EncodeToString(master[:])}
	s.sign = seal.Signer{By: "key:" + id.Fingerprint()[:16], Key: id.Sign, Recovery: recovery}
	if st, err := account.LoadState(); err == nil && st.User != "" {
		a, err := openAccount(ctx)
		if err != nil {
			return nil, err
		}
		s.acct = a
		s.self.User, s.self.Login = st.User, st.Login
		s.sign.By = st.User
		s.dir.Person = a.SealPersonByID
		s.dir.Group = a.SealGroupPublic
	}
	s.dir.Self = func(ctx context.Context) (*seal.Person, error) {
		if s.self.SecurityKeys == nil {
			keys, err := mySecurityKeys(ctx, s.acct)
			if err != nil {
				return nil, err
			}
			s.self.SecurityKeys = append([]string{}, keys...)
		}
		return s.self, nil
	}
	return s, nil
}

// bg is the context sealing's lookups run in.
func (s *sealing) bg() context.Context { return context.Background() }

// mySecurityKeys returns the recipients of this person's security keys:
// registered ones (the account's chain, or the local list), and the
// software stand-ins ESEC_VAULT_GUARD_IDENTITIES names (tests).
func mySecurityKeys(ctx context.Context, a *account.Account) ([]string, error) {
	keys, err := securitykey.Mine(ctx, a)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, k := range keys {
		out = append(out, k.Recipient)
	}
	standIns, err := guard.StandInRecipients()
	if err != nil {
		return nil, err
	}
	return append(out, standIns...), nil
}

// defaultReaders are the readers of a new environment: this person.
func (s *sealing) defaultReaders() []seal.Reader {
	if s.self.User != "" {
		return []seal.Reader{{Kind: seal.KindPerson, ID: s.self.User, Label: s.self.Login}}
	}
	return []seal.Reader{{Kind: seal.KindMe, ID: "me"}}
}

// seal seals env's key for readers and records it, in esec.toml too. It
// says which readers could not be sealed in yet.
func (s *sealing) seal(root string, pf *projectfile.File, env, priv, level string, readers []seal.Reader) error {
	if len(readers) == 0 {
		readers = s.defaultReaders()
	}
	res, err := seal.Make(s.bg(), s.dir, seal.Env{Project: pf.Project, Name: env, Root: root, Private: priv, Guard: level, Readers: readers}, s.sign)
	if err != nil {
		if strings.Contains(err.Error(), "plugin not found") {
			return fmt.Errorf("sealing %s for a reader's YubiKey needs age-plugin-yubikey on this machine: brew install age-plugin-yubikey (%w)", env, err)
		}
		return err
	}
	if seal.Guarded(level) && sealedTo(res) == 0 {
		return fmt.Errorf("no reader of %s has a security key yet, so a guarded seal would open only with a recovery phrase: add one first (esec vault security-keys add)", env)
	}
	if err := seal.Write(root, pf, env, res); err != nil {
		return err
	}
	for _, p := range res.Pending {
		fmt.Fprintf(os.Stderr, "! %s %s: %s\n", env, p.Reader, p.Pending)
	}
	return nil
}

// sealedTo counts the recipients a seal's readers resolved to, recovery
// keys aside.
func sealedTo(res *seal.Result) int {
	n := 0
	for _, r := range res.Record.Readers {
		n += len(r.Recipients)
	}
	return n
}

// readersOf returns the readers esec.toml names for env.
func readersOf(pf *projectfile.File, env string) ([]seal.Reader, error) {
	return seal.ParseReaders(pf.Env[env].Readers)
}

// cache files an unguarded key in this device's keyring, where esec finds
// it without a vault.
func (s *sealing) cache(project, env, priv string) error {
	entries, err := s.ks.Read(project)
	if errors.Is(err, os.ErrNotExist) {
		entries, err = map[string]string{}, nil
	}
	if err != nil {
		return err
	}
	pub, err := keystore.PublicHex(priv)
	if err != nil {
		return err
	}
	if entries[keystore.EnvEntry(env)] == priv && entries[keystore.PubEntry(pub)] == priv {
		return nil
	}
	if old := entries[keystore.EnvEntry(env)]; old != "" && old != priv {
		// The environment moved on (rotated elsewhere): keep the old key
		// filed under its public key, point the name at the new one.
		if oldPub, err := keystore.PublicHex(old); err == nil {
			entries[keystore.PubEntry(oldPub)] = old
		}
	}
	entries[keystore.EnvEntry(env)] = priv
	entries[keystore.PubEntry(pub)] = priv
	return s.ks.Write(project, entries, true)
}

// softwareIDs are the identities that open unguarded seals here: this
// person's user key, and the keys of groups the seal was made for.
func (s *sealing) softwareIDs(rec *seal.Record) []age.Identity {
	var ids []age.Identity
	if x, err := coreseal.X25519Identity(hex.EncodeToString(s.id.Private[:])); err == nil {
		ids = append(ids, x)
	}
	if s.acct == nil || rec == nil {
		return ids
	}
	for _, sf := range rec.Readers {
		r, err := seal.ParseReader(sf.Reader)
		if err != nil || r.Kind != seal.KindGroup {
			continue
		}
		if k, err := s.acct.SealGroupPrivate(s.bg(), r.ID); err == nil {
			if x, err := coreseal.X25519Identity(hex.EncodeToString(k[:])); err == nil {
				ids = append(ids, x)
			}
		}
	}
	return ids
}

// opened is a key opened for a command.
type opened struct {
	Private string
	Guard   string
}

// open returns env's private key: from this device's cache, else from its
// seal with this person's keys, else, for a guarded environment, after a
// dialog and a touch of a security key. Unguarded keys opened from a seal
// are cached. why says what the key is opened for, in the dialog.
func (s *sealing) open(root string, pf *projectfile.File, env, why string) (*opened, error) {
	e := pf.Env[env]
	if !seal.Guarded(e.Guard) {
		if priv, ok := s.cached(pf.Project, env, e.Key); ok {
			return &opened{Private: priv, Guard: projectfile.GuardNone}, nil
		}
	}
	data, err := coreseal.Read(root, env)
	if err != nil {
		return nil, err
	}
	recs, err := seal.LoadRecords(root)
	if err != nil {
		return nil, err
	}
	rec := recs[env]
	if p, err := coreseal.Open(data, pf.Project, env, e.Key, s.softwareIDs(rec)...); err == nil {
		if !seal.Guarded(p.Guard) {
			if err := s.cache(pf.Project, env, p.Private); err != nil {
				fmt.Fprintln(os.Stderr, "! keyring:", err)
			}
		}
		return &opened{Private: p.Private, Guard: p.Guard}, nil
	}
	var recipients []string
	if rec != nil {
		recipients = rec.Recipients()
	} else if recipients, err = mySecurityKeys(s.bg(), s.acct); err != nil {
		return nil, err
	}
	text := fmt.Sprintf("Asked by: %s\n\nOpen: %s %s\nFor: %s\n\nAllow, then touch your security key, only if you started this.", caller.Describe(nil), pf.Project, env, why)
	p, err := guard.DefaultPresence.OpenSeal(data, pf.Project, env, e.Key, recipients, "esec: open a guarded key?", text)
	if err != nil {
		return nil, err
	}
	return &opened{Private: p.Private, Guard: p.Guard}, nil
}

// cached returns a key from this device's keyring: the environment's, when
// it is the key esec.toml names (or esec.toml names none).
func (s *sealing) cached(project, env, pub string) (string, bool) {
	entries, err := s.ks.Read(project)
	if err != nil {
		return "", false
	}
	if pub != "" {
		v := entries[keystore.PubEntry(pub)]
		return v, v != ""
	}
	v := entries[keystore.EnvEntry(env)]
	return v, v != ""
}

// projectRoot finds the project of dir: its esec.toml and directory.
func projectRoot(dir string) (*projectfile.File, string, error) {
	if dir == "" {
		dir = "."
	}
	pf, path, err := projectfile.Find(dir)
	if err != nil {
		return nil, "", err
	}
	return pf, filepath.Dir(path), nil
}

// unsealAll opens into this device's cache every unguarded key of a
// project it can open and does not hold yet, quietly: esec then finds
// them without a vault. It returns how many it opened.
func (s *sealing) unsealAll(root string, pf *projectfile.File) int {
	n := 0
	for _, env := range pf.Envs() {
		e := pf.Env[env]
		if e.Key == "" || seal.Guarded(e.Guard) {
			continue
		}
		if _, ok := s.cached(pf.Project, env, e.Key); ok {
			continue
		}
		data, err := coreseal.Read(root, env)
		if err != nil {
			continue
		}
		recs, _ := seal.LoadRecords(root)
		p, err := coreseal.Open(data, pf.Project, env, e.Key, s.softwareIDs(recs[env])...)
		if err != nil || seal.Guarded(p.Guard) {
			continue
		}
		if s.cache(pf.Project, env, p.Private) == nil {
			n++
		}
	}
	return n
}
