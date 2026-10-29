package account

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/crypto"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/client"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/storage"
	"github.com/mscno/esec-vault/internal/vaultfile"
	"github.com/mscno/esec-vault/internal/wire"
)

func sha(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func normalizeMnemonic(s string) string { return strings.Join(strings.Fields(strings.ToLower(s)), " ") }

// SyncOptions configures Sync.
type SyncOptions struct {
	// Interactive lets Sync ask how to resolve conflicting entries. Without
	// it, conflicts are recorded and nothing is pushed.
	Interactive bool
}

// SyncResult summarizes a sync.
type SyncResult struct {
	Pulled       bool
	Pushed       bool
	VaultVersion uint64
	Generation   uint64
	Added        []string
	Conflicts    []string
	KeyChanged   bool
}

// ErrConflicts is returned when a non-interactive sync left conflicts.
var ErrConflicts = errors.New("vault sync found conflicting keyring entries; run 'esec vault sync' in a terminal to resolve them")

// entryName limits what a vault may write into a keyring.
var entryName = regexp.MustCompile(`^(ESEC_PRIVATE_KEY(_[A-Z0-9_]{1,128})?|ESEC_GUARD_[A-Z0-9_]{1,128}|ESEC_ACTIVE_KEY|ESEC_ACTIVE_ENVIRONMENT)$`)

// Sync verifies the chain, refreshes the user key if it rotated, pulls the
// server vault and merges it into the local keyrings, then pushes the local
// keyrings if they hold anything the server does not.
func (a *Account) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	var res *SyncResult
	err := a.Locked(func() error {
		var err error
		res, err = a.sync(ctx, opts)
		return err
	})
	return res, err
}

func (a *Account) sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	st, err := a.VerifiedChain(ctx)
	if err != nil {
		return nil, err
	}
	if _, ok := st.ActiveDevice(a.State.DeviceID); !ok {
		return nil, errors.New("this device is not active in the account's chain (it may have been revoked)")
	}
	before := a.State.Chain.UKeyVersion
	id, err := a.userKey(ctx, st)
	if err != nil {
		return nil, err
	}
	a.State.pin(st)
	res := &SyncResult{KeyChanged: before != 0 && before != st.UKeyVersion}
	for attempt := 0; attempt < 4; attempt++ {
		done, err := a.syncOnce(ctx, st, id, opts, res)
		if err != nil {
			return res, errors.Join(err, a.State.Save())
		}
		if done {
			return res, a.State.Save()
		}
	}
	return res, errors.Join(errors.New("the vault kept changing on the server; try again"), a.State.Save())
}

func (a *Account) syncOnce(ctx context.Context, st *chain.State, id *identity.Identity, opts SyncOptions, res *SyncResult) (bool, error) {
	remote, err := a.Client.Vault(ctx)
	if client.IsCode(err, wire.ErrNotFound) {
		remote = nil
	} else if err != nil {
		return false, err
	}
	var remoteVault *vaultfile.Vault
	ifMatch := uint64(0)
	if remote != nil {
		remoteVault, err = a.openRemote(st, id, remote)
		if err != nil {
			return false, err
		}
		ifMatch = remote.Version
		if remote.Version != a.State.Vault.Version || len(a.State.Vault.Conflicts) > 0 {
			added, conflicts, err := a.merge(remoteVault.Projects, a.base(id), opts.Interactive)
			if err != nil {
				return false, err
			}
			res.Pulled = true
			res.Added = append(res.Added, added...)
			res.Conflicts = conflicts
			a.State.Vault.Conflicts = conflicts
			if len(conflicts) > 0 {
				return false, ErrConflicts
			}
		}
	}
	local, err := a.localProjects()
	if err != nil {
		return false, err
	}
	if remoteVault != nil && reflect.DeepEqual(local, remoteVault.Projects) {
		if err := saveBase(remote.Blob); err != nil {
			return false, err
		}
		a.State.Vault = VaultPin{Version: remote.Version, Generation: remoteVault.Generation, SHA256: remote.SHA256, SyncedAt: a.Now()}
		res.VaultVersion, res.Generation = remote.Version, remoteVault.Generation
		return true, nil
	}
	gen := a.State.Vault.Generation + 1
	if remoteVault != nil && remoteVault.Generation >= gen {
		gen = remoteVault.Generation + 1
	}
	wrapped, err := identity.WrappedFile()
	if err != nil {
		return false, err
	}
	put, gen, err := a.vaultPut(st, id, wrapped, ifMatch, gen)
	if err != nil {
		return false, err
	}
	v, err := a.Client.PutVault(ctx, *put)
	if client.IsCode(err, wire.ErrConflict) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := saveBase(put.Blob); err != nil {
		return false, err
	}
	a.State.Vault = VaultPin{Version: v.Version, Generation: gen, SHA256: v.SHA256, SyncedAt: a.Now()}
	res.Pushed, res.VaultVersion, res.Generation = true, v.Version, gen
	return true, nil
}

// basePath holds the last vault version this machine synced. It is the
// common ancestor for three-way merges. It is the server's own blob, sealed
// to the user key, so it adds no new plaintext copy of any key.
func basePath() string { return filepath.Join(paths.Home(), "vault-server.esec") }

func saveBase(blob []byte) error { return storage.Write(basePath(), blob) }

// base returns the projects of the last synced vault, or nil when unknown
// (first sync, or the user key rotated since).
func (a *Account) base(id *identity.Identity) map[string]map[string]string {
	raw, err := os.ReadFile(basePath())
	if err != nil {
		return nil
	}
	v, err := vaultfile.Open(raw, &id.Public, &id.Private)
	if err != nil {
		return nil
	}
	return v.Projects
}

// openRemote authenticates and opens a server vault: it must be signed by
// the current user key, open with it, and not be older than what this
// machine already applied.
func (a *Account) openRemote(st *chain.State, id *identity.Identity, remote *wire.Vault) (*vaultfile.Vault, error) {
	if !ed25519.Verify(st.SignPub, wire.VaultMessage(a.State.User, remote.Blob), remote.Sig) {
		return nil, errors.New("the server's vault is not signed by the current user key; refusing it")
	}
	v, err := vaultfile.Open(remote.Blob, &id.Public, &id.Private)
	if err != nil {
		return nil, fmt.Errorf("open the server's vault: %w", err)
	}
	if v.Generation < a.State.Vault.Generation {
		return nil, fmt.Errorf("the server's vault (generation %d) is older than one this machine already applied (%d); refusing a rollback", v.Generation, a.State.Vault.Generation)
	}
	return v, nil
}

// vaultPut seals the current local keyrings into a signed vault upload.
func (a *Account) vaultPut(st *chain.State, id *identity.Identity, wrapped []byte, ifMatch, gen uint64) (*wire.VaultPut, uint64, error) {
	local, err := a.localProjects()
	if err != nil {
		return nil, 0, err
	}
	h, err := identity.ReadHeader(wrapped)
	if err != nil {
		return nil, 0, err
	}
	if h.IdentityPublic != id.Public {
		return nil, 0, errors.New("identity.esec does not match the user key")
	}
	master := h.MasterPublic
	if master != st.MasterPub {
		return nil, 0, errors.New("identity.esec is wrapped to a different master key than the account's")
	}
	blob, err := vaultfile.Seal(&vaultfile.Vault{Projects: local, Identity: wrapped, IdentityFingerprint: id.Fingerprint(), Generation: gen, CreatedAt: a.Now().UTC()}, &id.Public, &master)
	if err != nil {
		return nil, 0, err
	}
	sig := ed25519.Sign(id.Sign, wire.VaultMessage(a.State.User, blob))
	put := &wire.VaultPut{Blob: blob, Sig: sig, IfMatch: ifMatch}
	if !a.State.NoIndex {
		index, err := json.Marshal(BuildIndex(local, gen))
		if err != nil {
			return nil, 0, err
		}
		put.Index, put.IndexSig = index, ed25519.Sign(id.Sign, wire.IndexMessage(a.State.User, index))
	}
	return put, gen, nil
}

var hexName = regexp.MustCompile(`^[0-9A-F]{64}$`)

// BuildIndex summarizes keyrings without any private material: environment
// names come from ESEC_PRIVATE_KEY_<ENV> entries and public keys are derived
// from the private keys.
func BuildIndex(projects map[string]map[string]string, gen uint64) wire.VaultIndex {
	idx := wire.VaultIndex{Generation: gen, Projects: []wire.IndexProject{}}
	ids := make([]string, 0, len(projects))
	for p := range projects {
		ids = append(ids, p)
	}
	sort.Strings(ids)
	for _, p := range ids {
		ip := wire.IndexProject{ID: p, Environments: []wire.IndexEnv{}}
		names := make([]string, 0, len(projects[p]))
		for k := range projects[p] {
			names = append(names, k)
		}
		sort.Strings(names)
		namedPubs := map[string]bool{}
		var byPubKey []string
		for _, k := range names {
			if env, ok := keystore.EnvName(k); ok && strings.HasPrefix(k, "ESEC_GUARD_ENV_") {
				pub := strings.ToLower(projects[p][k])
				namedPubs[pub] = true
				ip.Environments = append(ip.Environments, wire.IndexEnv{Name: env, PublicKey: pub})
				continue
			}
			if keystore.IsGuardEntry(k) {
				byPubKey = append(byPubKey, strings.ToLower(strings.TrimPrefix(k, "ESEC_GUARD_")))
				continue
			}
			suffix, named := strings.CutPrefix(k, esec.EsecPrivateKey+"_")
			if k == esec.EsecPrivateKey {
				suffix, named = "default", true
			}
			if !named {
				continue
			}
			if hexName.MatchString(suffix) {
				byPubKey = append(byPubKey, strings.ToLower(suffix))
				continue
			}
			pub, err := publicHex(projects[p][k])
			if err != nil {
				continue
			}
			namedPubs[pub] = true
			ip.Environments = append(ip.Environments, wire.IndexEnv{Name: strings.ToLower(strings.ReplaceAll(suffix, "_", ".")), PublicKey: pub})
		}
		// Public-key entries of named environments are aliases; count the rest.
		for _, pub := range byPubKey {
			if !namedPubs[pub] {
				ip.OtherKeys++
			}
		}
		idx.Projects = append(idx.Projects, ip)
	}
	return idx
}

func publicHex(priv string) (string, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(priv))
	if err != nil || len(raw) != 32 {
		return "", errors.New("malformed key")
	}
	var k [32]byte
	copy(k[:], raw)
	pub, err := crypto.PublicFromPrivate(k)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(pub[:]), nil
}

func (a *Account) localProjects() (map[string]map[string]string, error) {
	projects, err := a.KS.List()
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]string{}
	for _, p := range projects {
		e, err := a.KS.Read(p)
		if err != nil {
			return nil, err
		}
		out[p] = e
	}
	return out, nil
}

// merge applies the server vault to local keyrings with a three-way merge
// against base, the last version this machine synced:
//
//   - an entry changed only on the server is taken from the server (another
//     device added or rotated a key);
//   - an entry changed only here is kept, and pushed afterwards;
//   - an entry changed on both sides, or with no base to tell, is a conflict:
//     asked about when interactive, otherwise reported and left alone.
//
// Entries missing here are added, except a key this machine keeps guarded:
// another device that has not guarded it yet still sends it in the clear.
// Nothing local is ever deleted.
func (a *Account) merge(remote, base map[string]map[string]string, interactive bool) (added, conflicts []string, err error) { //nolint:gocyclo // the merge table is clearer in one place
	names := make([]string, 0, len(remote))
	for p := range remote {
		names = append(names, p)
	}
	sort.Strings(names)
	for _, project := range names {
		entries := remote[project]
		for k := range entries {
			if !entryName.MatchString(k) {
				return nil, nil, fmt.Errorf("vault entry %q in %s is not a keyring entry name", k, project)
			}
		}
		local, err := a.KS.Read(project)
		if errors.Is(err, os.ErrNotExist) {
			// A key guarded on another device comes guarded only, even
			// where a device that has not guarded it yet sent it clear.
			fresh := map[string]string{}
			for k, v := range entries {
				if !guardedHere(entries, v) {
					fresh[k] = v
				}
			}
			if err := a.KS.Write(project, fresh, false); err != nil {
				return nil, nil, fmt.Errorf("write %s: %w", project, err)
			}
			added = append(added, project)
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		changed := false
		guardChanged, guardConflict := a.mergeGuard(project, local, entries, base[project], interactive)
		changed = changed || guardChanged
		if guardConflict != "" {
			conflicts = append(conflicts, guardConflict)
		}
		keys := make([]string, 0, len(entries))
		for k := range entries {
			if !guardUnit[k] {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			rv := entries[k]
			lv, ok := local[k]
			if !ok && (guardedHere(local, rv) || guardedHere(entries, rv)) {
				continue
			}
			if !ok {
				local[k] = rv
				changed = true
				added = append(added, project+" "+k)
				continue
			}
			if lv == rv {
				continue
			}
			bv, known := base[project][k]
			switch {
			case known && lv == bv:
				local[k] = rv
				changed = true
				added = append(added, project+" "+k+" (updated)")
			case known && rv == bv:
				// Changed only here; the push that follows carries it.
			case interactive && a.UI.Confirm(fmt.Sprintf("%s %s was changed both here and on another device. Replace this machine's value with the vault's?", project, k)):
				local[k] = rv
				changed = true
			case interactive:
				// Keep this machine's value; the push that follows wins.
			default:
				conflicts = append(conflicts, project+" "+k)
			}
		}
		if changed {
			if err := a.KS.Write(project, local, true); err != nil {
				return nil, nil, fmt.Errorf("write %s: %w", project, err)
			}
		}
	}
	return added, conflicts, nil
}

// guardUnit are the guard's own entries (package guard), merged together:
// the identity and its holders only make sense with their recipient.
var guardUnit = map[string]bool{"ESEC_GUARD_IDENTITY": true, "ESEC_GUARD_RECIPIENT": true, "ESEC_GUARD_HOLDERS": true}

// mergeGuard merges the guard entries as one unit into local. A guard with
// another recipient is never taken over this machine's: every guarded key
// here is wrapped to it. That is a conflict to resolve by hand. Under the
// same recipient, a rewrap (new holders) is merged like any entry.
func (a *Account) mergeGuard(project string, local, remote, base map[string]string, interactive bool) (changed bool, conflict string) {
	const id, rcpt, holders = "ESEC_GUARD_IDENTITY", "ESEC_GUARD_RECIPIENT", "ESEC_GUARD_HOLDERS"
	if remote[id] == "" {
		return false, ""
	}
	take := func() bool {
		for k := range guardUnit {
			local[k] = remote[k]
		}
		return true
	}
	switch {
	case local[id] == "":
		return take(), ""
	case local[rcpt] != remote[rcpt]:
		return false, project + " guard: another device set up a different guard (" + short(remote[rcpt]) + "); this one (" + short(local[rcpt]) + ") is kept, and keys guarded there open only with that guard"
	case local[id] == remote[id] && local[holders] == remote[holders]:
		return false, ""
	case local[id] == base[id] && local[holders] == base[holders]:
		return take(), ""
	case remote[id] == base[id] && remote[holders] == base[holders]:
		return false, ""
	case interactive && a.UI.Confirm(project+" guard holders were changed both here and on another device. Take the vault's holders?"):
		return take(), ""
	case interactive:
		return false, ""
	}
	return false, project + " guard holders"
}

func short(s string) string {
	if len(s) > 16 {
		return s[:16] + "…"
	}
	return s
}

// guardedHere reports whether value is a private key this keyring holds
// only in its guarded form.
func guardedHere(local map[string]string, value string) bool {
	pub, err := keystore.PublicHex(value)
	return err == nil && local[keystore.GuardEntry(pub)] != ""
}

// LastSync reports when the vault last synced.
func (a *Account) LastSync() time.Time { return a.State.Vault.SyncedAt }

// ServerProjects downloads and opens the vault stored on the server,
// without applying it, and returns its keyrings: what a new device would
// get. It checks the vault's signature like a sync does.
func (a *Account) ServerProjects(ctx context.Context) (map[string]map[string]string, error) {
	st, err := a.VerifiedChain(ctx)
	if err != nil {
		return nil, err
	}
	id, err := a.userKey(ctx, st)
	if err != nil {
		return nil, err
	}
	remote, err := a.Client.Vault(ctx)
	if client.IsCode(err, wire.ErrNotFound) {
		return map[string]map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	v, err := a.openRemote(st, id, remote)
	if err != nil {
		return nil, err
	}
	return v.Projects, nil
}
