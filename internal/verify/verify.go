// Package verify checks that no key is ever lost: every public key that any
// secrets file uses, in a checkout or anywhere in its git history, must have
// its private key on this device and in at least one other place (the vault
// server, a backup), and no key may serve two projects.
package verify

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/fileutils"
	"github.com/mscno/esec/pkg/projectfile"

	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/secretfile"
)

// Use is one secrets file encrypted to a key.
type Use struct {
	Project string `json:"project"`
	Env     string `json:"env"`
	Path    string `json:"path"`
	// Commit is set for a file found only in git history.
	Commit string `json:"commit,omitempty"`
}

// Source is a place keys are kept, as Build gets it: nil Projects means it
// was not checked (Err says why, when it failed).
type Source struct {
	Name     string
	Projects map[string]map[string]string
	Err      error
}

// Key is the report on one public key.
type Key struct {
	Public string `json:"public_key"`
	Uses   []Use  `json:"uses"`
	// Held maps each source's name to the projects whose keyrings hold the
	// key there (guarded or in the clear).
	Held map[string][]string `json:"held"`
	// Places counts the sources holding it.
	Places   int      `json:"places"`
	Problems []string `json:"problems,omitempty"`
}

// SourceStatus says what became of one source.
type SourceStatus struct {
	Name    string `json:"name"`
	Checked bool   `json:"checked"`
	Error   string `json:"error,omitempty"`
}

// Report is the result of a check.
type Report struct {
	Checkouts int            `json:"checkouts"`
	Files     int            `json:"files"`
	Sources   []SourceStatus `json:"sources"`
	Keys      []Key          `json:"keys"`
	// Problems counts keys with problems; Lost those held nowhere.
	Problems int `json:"problems"`
	Lost     int `json:"lost"`
}

// OK reports whether every key is safe.
func (r *Report) OK() bool { return r.Problems == 0 }

// Collect finds every key the secrets files under the checkouts use, and,
// with history, every key their git history ever used.
func Collect(ctx context.Context, checkouts []string, history bool) (map[string][]Use, int, error) {
	uses := map[string][]Use{}
	seen := map[string]bool{}
	add := func(pub string, u Use) {
		k := pub + "\x00" + u.Project + "\x00" + u.Path + "\x00" + u.Commit
		if !seen[k] {
			seen[k] = true
			uses[pub] = append(uses[pub], u)
		}
	}
	files := 0
	var errs []error
	for _, root := range checkouts {
		found, err := secretfile.Scan(root)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", root, err))
			continue
		}
		for _, f := range found {
			if f.PublicKey == "" {
				continue
			}
			files++
			add(strings.ToLower(f.PublicKey), Use{Project: f.Project, Env: f.Env, Path: f.Path})
		}
		if history {
			hist, err := historyUses(ctx, root)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s history: %w", root, err))
			}
			for pub, us := range hist {
				for _, u := range us {
					add(pub, u)
				}
			}
		}
	}
	return uses, files, errors.Join(errs...)
}

// historyUses reads every secrets file in every commit of the repository
// holding root, once per distinct content.
func historyUses(ctx context.Context, root string) (map[string][]Use, error) {
	top, err := git(ctx, root, nil, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, nil //nolint:nilerr // not a git checkout: no history to read
	}
	top = strings.TrimSpace(top)
	project := ""
	if f, _, err := projectfile.Find(root); err == nil {
		project = f.Project
	}
	objects, err := git(ctx, top, nil, "rev-list", "--all", "--objects")
	if err != nil {
		return nil, err
	}
	type blob struct{ sha, path string }
	var blobs []blob
	for _, line := range strings.Split(objects, "\n") {
		sha, path, ok := strings.Cut(line, " ")
		if !ok || path == "" {
			continue
		}
		if _, err := fileutils.ParseFormat(filepath.Base(path)); err != nil {
			continue
		}
		blobs = append(blobs, blob{sha, path})
	}
	out := map[string][]Use{}
	if len(blobs) == 0 {
		return out, nil
	}
	var in bytes.Buffer
	for _, b := range blobs {
		in.WriteString(b.sha + "\n")
	}
	raw, err := git(ctx, top, &in, "cat-file", "--batch")
	if err != nil {
		return nil, err
	}
	r := bufio.NewReader(strings.NewReader(raw))
	for _, b := range blobs {
		header, err := r.ReadString('\n')
		if err != nil {
			return out, err
		}
		fields := strings.Fields(header)
		if len(fields) < 3 {
			continue // missing object
		}
		size, err := strconv.Atoi(fields[2])
		if err != nil {
			return out, err
		}
		data := make([]byte, size)
		if _, err := io.ReadFull(r, data); err != nil {
			return out, err
		}
		_, _ = r.ReadByte() // the newline after the content
		if fields[1] != "blob" {
			continue
		}
		format, _ := fileutils.ParseFormat(filepath.Base(b.path))
		pub, err := esec.ExtractPublicKey(data, esec.FileFormat(format))
		if err != nil {
			continue
		}
		env, _, _ := secretfile.EnvOf(b.path)
		pubHex := fmt.Sprintf("%x", pub[:])
		out[pubHex] = append(out[pubHex], Use{Project: project, Env: env, Path: filepath.Join(top, b.path), Commit: "history"})
	}
	return out, nil
}

func git(ctx context.Context, dir string, stdin io.Reader, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, "git", append([]string{"-C", dir}, args...)...)
	cmd.Stdin = stdin
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

// holders indexes a source: public key → projects holding it.
func holders(projects map[string]map[string]string) map[string][]string {
	out := map[string][]string{}
	for project, entries := range projects {
		pubs := map[string]bool{}
		for k, v := range entries {
			switch {
			case keystore.IsPubEntry(k):
				pubs[strings.ToLower(strings.TrimPrefix(k, "ESEC_PRIVATE_KEY_"))] = true
			case keystore.IsGuardEntry(k):
				pubs[strings.ToLower(strings.TrimPrefix(k, "ESEC_GUARD_"))] = true
			case strings.HasPrefix(k, "ESEC_PRIVATE_KEY"):
				// A key filed under a name only (older keyrings).
				if pub, err := keystore.PublicHex(v); err == nil {
					pubs[pub] = true
				}
			}
		}
		for pub := range pubs {
			out[pub] = append(out[pub], project)
		}
	}
	for pub := range out {
		sort.Strings(out[pub])
	}
	return out
}

// Build checks the keys in uses against the sources. The first source is
// this device.
func Build(uses map[string][]Use, sources []Source) *Report { //nolint:gocyclo // one pass over keys and sources
	rep := &Report{Keys: []Key{}}
	indexes := make([]map[string][]string, len(sources))
	for i, s := range sources {
		st := SourceStatus{Name: s.Name, Checked: s.Projects != nil}
		if s.Err != nil {
			st.Error = s.Err.Error()
		}
		rep.Sources = append(rep.Sources, st)
		if s.Projects != nil {
			indexes[i] = holders(s.Projects)
		}
	}
	pubs := make([]string, 0, len(uses))
	for pub := range uses {
		pubs = append(pubs, pub)
	}
	sort.Strings(pubs)
	for _, pub := range pubs {
		k := Key{Public: pub, Uses: uses[pub], Held: map[string][]string{}}
		projects := map[string]bool{}
		for _, u := range k.Uses {
			if u.Project != "" {
				projects[u.Project] = true
			}
		}
		for i, s := range sources {
			if indexes[i] == nil {
				continue
			}
			if held := indexes[i][pub]; len(held) > 0 {
				k.Held[s.Name] = held
				k.Places++
				for _, p := range held {
					projects[p] = true
				}
			}
		}
		checked := 0
		for _, ix := range indexes {
			if ix != nil {
				checked++
			}
		}
		switch {
		case k.Places == 0:
			k.Problems = append(k.Problems, "lost: no copy of its private key in any place checked; files encrypted to it cannot be decrypted")
			rep.Lost++
		case len(k.Held[sources[0].Name]) == 0:
			k.Problems = append(k.Problems, "not on this device")
		}
		if k.Places == 1 && checked > 1 {
			k.Problems = append(k.Problems, "in one place only: "+onlyPlace(k.Held))
		}
		if checked == 1 && k.Places == 1 {
			k.Problems = append(k.Problems, "in one place only (no vault server or backup to check: esec vault login, or esec vault remote add)")
		}
		if len(projects) > 1 {
			names := make([]string, 0, len(projects))
			for p := range projects {
				names = append(names, p)
			}
			sort.Strings(names)
			k.Problems = append(k.Problems, "one key serves several projects: "+strings.Join(names, ", ")+"; give each its own (esec vault env rotate)")
		}
		if len(k.Problems) > 0 {
			rep.Problems++
		}
		rep.Keys = append(rep.Keys, k)
	}
	return rep
}

func onlyPlace(held map[string][]string) string {
	for name := range held {
		return name
	}
	return ""
}

// LocalProjects reads every keyring on this device.
func LocalProjects(ks *keystore.Store) (map[string]map[string]string, error) {
	ids, err := ks.List()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	out := map[string]map[string]string{}
	for _, id := range ids {
		e, err := ks.Read(id)
		if err != nil {
			return nil, err
		}
		out[id] = e
	}
	return out, nil
}
