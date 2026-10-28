package daemon

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/mscno/esec/pkg/projectfile"
	coreseal "github.com/mscno/esec/pkg/seal"

	"github.com/mscno/esec-vault/internal/guard"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/seal"
	"github.com/mscno/esec-vault/internal/securitykey"
	"github.com/mscno/esec-vault/internal/workspace"
)

// localSecurityKeys returns the recipients of this person's security keys
// as this machine knows them (commands refresh the list from the account),
// and the software stand-ins of tests.
func localSecurityKeys() ([]string, error) {
	keys, err := securitykey.Mine(context.Background(), nil)
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

// unseal opens an unguarded key from the seal in the project of path with
// this person's identity, for a key the broker does not hold yet (a new
// checkout, a key rotated elsewhere), and caches it in the keyring.
func unseal(kr keyring.Keyring, project, env, pub, path string) (string, error) {
	pf, marker, err := projectfile.Find(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	if pf.Project != project {
		return "", fmt.Errorf("%s belongs to %s, not %s", path, pf.Project, project)
	}
	root := filepath.Dir(marker)
	data, err := coreseal.Read(root, env)
	if err != nil {
		return "", err
	}
	id, err := identity.Load(kr)
	if err != nil {
		return "", err
	}
	x, err := coreseal.X25519Identity(hex.EncodeToString(id.Private[:]))
	if err != nil {
		return "", err
	}
	p, err := coreseal.Open(data, project, env, pub, x)
	if err != nil {
		return "", err
	}
	if seal.Guarded(p.Guard) {
		return "", errors.New("the key is guarded")
	}
	ks := keystore.New()
	entries, err := ks.Read(project)
	if errors.Is(err, fs.ErrNotExist) {
		entries, err = map[string]string{}, nil
	}
	if err == nil {
		k, _ := keystore.PublicHex(p.Private)
		entries[keystore.PubEntry(k)] = p.Private
		if entries[keystore.EnvEntry(env)] == "" {
			entries[keystore.EnvEntry(env)] = p.Private
		}
		_ = ks.Write(project, entries, true)
	}
	return p.Private, nil
}

// unsealEvery is how often the daemon opens new checkouts' keys.
const unsealEvery = 5 * time.Minute

// unsealLoop opens into the keyring, now and every few minutes, the
// unguarded keys of every checkout this machine knows that are sealed to
// this person and not cached yet: a new clone, a key rotated or shared on
// another machine. esec then finds them with no vault. Guarded keys are
// never cached. ESEC_VAULT_UNSEAL=off turns it off.
func (s *Server) unsealLoop(ctx context.Context) {
	if os.Getenv("ESEC_VAULT_UNSEAL") == "off" {
		return
	}
	t := time.NewTimer(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if n := unsealCheckouts(s.Keyring); n > 0 {
			s.Logger.Info("opened sealed keys into the keyring", "keys", n)
		}
		t.Reset(unsealEvery)
	}
}

// unsealCheckouts opens what unsealLoop opens, once. It returns how many
// keys it cached.
func unsealCheckouts(kr keyring.Keyring) int {
	reg, err := workspace.Load()
	if err != nil {
		return 0
	}
	ks := keystore.New()
	n := 0
	for _, co := range reg.Checkouts {
		if workspace.Check(co) != workspace.StatusOK {
			continue
		}
		pf, err := projectfile.Load(co.Path)
		if err != nil {
			continue
		}
		entries, _ := ks.Read(pf.Project)
		for _, env := range pf.Envs() {
			e := pf.Env[env]
			if e.Key == "" || seal.Guarded(e.Guard) || entries[keystore.PubEntry(e.Key)] != "" {
				continue
			}
			if _, err := unseal(kr, pf.Project, env, e.Key, filepath.Join(co.Path, projectfile.ProjectFileName)); err == nil {
				n++
			}
		}
	}
	return n
}
