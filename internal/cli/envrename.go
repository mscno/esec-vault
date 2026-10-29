package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mscno/esec/pkg/projectfile"
	coreseal "github.com/mscno/esec/pkg/seal"
	"github.com/pelletier/go-toml/v2"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/envrename"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/seal"
	"github.com/mscno/esec-vault/internal/team"
)

// EnvRenameCmd preserves a vault environment's key, access and guard policy.
type EnvRenameCmd struct {
	Old string `arg:"" help:"Existing environment"`
	New string `arg:"" help:"New environment name"`
	Dir string `type:"path" default:"." help:"Project checkout to update and search recursively"`
	Yes bool   `help:"Skip confirmation"`
}

// Run implements env rename. A journal lets the exact command resume safely.
func (c *EnvRenameCmd) Run(ctx *cliCtx) error {
	if err := team.ValidEnv(c.Old); err != nil {
		return err
	}
	if err := team.ValidEnv(c.New); err != nil {
		return err
	}
	if c.Old == c.New {
		return fmt.Errorf("old and new environments are identical")
	}
	_, root, err := projectfile.FindProjectFile(c.Dir)
	if err != nil {
		return err
	}
	root, err = filepath.Abs(filepath.Dir(root))
	if err != nil {
		return err
	}
	ks := keystore.New()
	ks.Locked = ctx.keyringLocked
	j, err := envrename.Load(root)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if j != nil && (j.Old != c.Old || j.New != c.New) {
		return fmt.Errorf("an interrupted rename exists; resume env rename %s %s first", j.Old, j.New)
	}
	a, err := renameAccount(ctx)
	if err != nil {
		return err
	}
	if j == nil {
		j, err = c.planRename(ctx, root, ks, a)
		if err != nil {
			return err
		}
		if !c.Yes && !confirm(fmt.Sprintf("Rename %s to %s, preserving its key and access, and update %d local paths?", c.Old, c.New, len(j.Changes))) {
			return errors.New("cancelled")
		}
		if err := j.Save(root); err != nil {
			return err
		}
	} else {
		fmt.Fprintln(os.Stderr, "Resuming interrupted environment rename.")
	}
	return c.finishRename(root, ks, j, a)
}

func (c *EnvRenameCmd) finishRename(root string, ks *keystore.Store, j *envrename.Journal, a *account.Account) error {
	pf, err := projectfile.Load(root)
	if err != nil {
		return err
	}
	if pf.Project != j.Project {
		return fmt.Errorf("rename journal belongs to a different project")
	}
	if j.Shared {
		if a == nil {
			return fmt.Errorf("sign in to the vault before resuming this shared rename")
		}
		bg, cancel := timeout(time.Minute)
		defer cancel()
		if err := a.RenameEnv(bg, j.Project, j.Old, j.New, j.Public); err != nil {
			return fmt.Errorf("vault rename not confirmed; no local files changed; rerun this command: %w", err)
		}
	}
	if err := ks.RenameEnv(j.Project, j.Old, j.New, j.Public, false); err != nil {
		return fmt.Errorf("rename pending; rerun after resolving keyring conflict: %w", err)
	}
	if err := j.Apply(root); err != nil {
		return fmt.Errorf("rename pending; do not delete %s; resolve the conflict and rerun: %w", envrename.Path(root), err)
	}
	if err := os.Remove(envrename.Path(root)); err != nil {
		return err
	}
	fmt.Printf("✓ Renamed %s to %s in %s; key and access unchanged. Update external CI/deployment references manually.\n", c.Old, c.New, j.Project)
	return nil
}

func renameAccount(ctx *cliCtx) (*account.Account, error) {
	_, err := account.LoadState()
	if errors.Is(err, account.ErrNotLoggedIn) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return openAccount(ctx)
}

func (c *EnvRenameCmd) planRename(ctx *cliCtx, root string, ks *keystore.Store, a *account.Account) (*envrename.Journal, error) {
	pf, err := projectfile.Load(root)
	if err != nil {
		return nil, err
	}
	e, ok := pf.Env[c.Old]
	if !ok {
		return nil, fmt.Errorf("unknown environment %s in esec.toml", c.Old)
	}
	if _, ok := pf.Env[c.New]; ok {
		return nil, fmt.Errorf("environment %s exists", c.New)
	}
	if err := ks.RenameEnv(pf.Project, c.Old, c.New, e.Key, true); err != nil {
		return nil, err
	}
	j := &envrename.Journal{Project: pf.Project, Old: c.Old, New: c.New, Public: e.Key}
	if err := c.checkSharedRename(a, pf, j); err != nil {
		return nil, err
	}
	files, err := envrename.Find(root, c.Old, c.New)
	if err != nil {
		return nil, err
	}
	for _, pair := range files {
		if err := j.Add(root, pair[0], pair[1], nil); err != nil {
			return nil, err
		}
	}
	if err := c.planSealRename(ctx, root, pf, j); err != nil {
		return nil, err
	}
	marker := filepath.Join(root, projectfile.ProjectFileName)
	raw, err := os.ReadFile(marker) //nolint:gosec // fixed marker filename in the discovered project
	if err != nil {
		return nil, err
	}
	updated, err := renameMarker(raw, pf, c.Old, c.New)
	if err != nil {
		return nil, err
	}
	if err := j.Add(root, marker, marker, updated); err != nil {
		return nil, err
	}
	return j, nil
}

func (c *EnvRenameCmd) checkSharedRename(a *account.Account, pf *projectfile.File, j *envrename.Journal) error {
	if a != nil {
		bg, cancel := timeout(time.Minute)
		defer cancel()
		shared, admin, err := a.SharedRole(bg, pf.Project)
		if err != nil {
			return err
		}
		if shared && !admin {
			return fmt.Errorf("only project admins may rename shared environments")
		}
		j.Shared = shared
		if shared {
			view, err := a.Team(bg, pf.Project)
			if err != nil {
				return err
			}
			st := view.State
			if st.Archived {
				return fmt.Errorf("project is archived")
			}
			if st.Envs[c.New] != nil || st.EnvRenames[c.New] != "" {
				return fmt.Errorf("destination environment exists or is retired in the vault")
			}
			if old := st.Envs[c.Old]; old == nil || old.PublicKey != j.Public {
				return fmt.Errorf("local environment does not match vault; sync first")
			}
		}
	}
	return nil
}

func (c *EnvRenameCmd) planSealRename(ctx *cliCtx, root string, pf *projectfile.File, j *envrename.Journal) error {
	recs, err := seal.LoadRecords(root)
	if err != nil {
		return err
	}
	if recs[c.New] != nil {
		return fmt.Errorf("destination sealing record exists")
	}
	oldPath, newPath := coreseal.Path(root, c.Old), coreseal.Path(root, c.New)
	if _, err := os.Lstat(newPath); err == nil {
		return fmt.Errorf("destination seal exists: %s", newPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := coreseal.Read(root, c.Old)
	if errors.Is(err, coreseal.ErrNotSealed) {
		if recs[c.Old] != nil {
			return fmt.Errorf("recorded source seal is missing")
		}
		return nil
	}
	if err != nil {
		return err
	}
	for _, problem := range seal.Check(pf, recs, func(env string) ([]byte, error) { return coreseal.Read(root, env) }) {
		if problem.Env == c.Old && problem.Level == seal.Fail {
			return fmt.Errorf("cannot rename invalid seal: %s", problem.Detail)
		}
	}
	s, err := newSealing(ctx)
	if err != nil {
		return err
	}
	key, err := s.openOnce(root, pf, c.Old, "rename this environment while retaining its recipients")
	if err != nil {
		return err
	}
	sealed, rec, err := seal.Rename(pf.Project, c.Old, c.New, key.Private, data, recs[c.Old], s.sign)
	if err != nil {
		return err
	}
	if err := j.Add(root, oldPath, newPath, sealed); err != nil {
		return err
	}
	delete(recs, c.Old)
	recs[c.New] = rec
	raw, err := toml.Marshal(recs)
	if err != nil {
		return err
	}
	p := filepath.Join(root, coreseal.Dir, seal.RecordsFile)
	return j.Add(root, p, p, raw)
}

// Rewrite only the table header, refusing layouts that would lose comments.
func renameMarker(raw []byte, pf *projectfile.File, old, next string) ([]byte, error) {
	pattern := regexp.MustCompile(`(?m)^(\s*\[\s*env\s*\.\s*)("(?:[^"\\]|\\.)*"|'[^']*'|[a-zA-Z0-9_-]+)(\s*\][^\n]*)$`)
	updated := pattern.ReplaceAllFunc(raw, func(line []byte) []byte {
		parts := pattern.FindSubmatch(line)
		name := string(parts[2])
		if strings.HasPrefix(name, "\"") {
			v, err := strconv.Unquote(name)
			if err != nil {
				return line
			}
			name = v
		} else {
			name = strings.Trim(name, "'")
		}
		if name != old {
			return line
		}
		return []byte(string(parts[1]) + strconv.Quote(next) + string(parts[3]))
	})
	if bytes.Equal(updated, raw) {
		return nil, fmt.Errorf("cannot preserve this esec.toml layout; use a separate [env.%s] table before renaming", strconv.Quote(old))
	}
	parsed, err := projectfile.Parse(updated)
	if err != nil {
		return nil, err
	}
	want := map[string]projectfile.Env{}
	for n, e := range pf.Env {
		if n == old {
			n = next
		}
		want[n] = e
	}
	if !reflect.DeepEqual(parsed.Env, want) || parsed.Project != pf.Project || parsed.Files != pf.Files {
		return nil, fmt.Errorf("environment table rename did not preserve project metadata")
	}
	return updated, nil
}
