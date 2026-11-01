package verify

import (
	"context"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/mscno/esec/pkg/projectfile"
	coreseal "github.com/mscno/esec/pkg/seal"

	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/seal"
)

// A signed seal with recovery recipients preserves the key without a local
// cache, server keyring or vault backup. Check the encrypted file's hash as
// well as the signature: the record alone is not a copy of the key.
func (s *Source) addSeals(project string, recs seal.Records, read func(string) ([]byte, error)) {
	for env, rec := range recs {
		if rec == nil || rec.Key == "" || len(rec.Recovery) == 0 || rec.Verify(project, env) != nil {
			continue
		}
		data, err := read(env)
		if err != nil || coreseal.Hash(data) != rec.Sealed {
			continue
		}
		if s.Projects[project] == nil {
			s.Projects[project] = map[string]string{}
		}
		s.Projects[project][keystore.GuardEntry(rec.Key)] = "sealed"
	}
}

// sealedSource includes working trees and, when requested, the signed seals
// alongside older encrypted files in Git. A rotation replaces today's seal;
// it does not remove the previous seal from the repository's history.
func sealedSource(ctx context.Context, checkouts []string, history bool) (Source, error) {
	s := Source{Name: SourceSealed, Projects: map[string]map[string]string{}}
	var errs []error
	for _, dir := range checkouts {
		pf, err := projectfile.Load(dir)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		recs, err := seal.LoadRecords(dir)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		s.addSeals(pf.Project, recs, func(env string) ([]byte, error) { return coreseal.Read(dir, env) })
	}
	if history {
		for _, repo := range repos(ctx, checkouts) {
			if err := repo.collectSeals(ctx, &s); err != nil {
				errs = append(errs, err)
			}
		}
	}
	s.Err = errors.Join(errs...)
	return s, s.Err
}

func (r *repo) collectSeals(ctx context.Context, s *Source) error {
	seen := map[string]bool{}
	for _, rt := range r.roots {
		recordPath := path.Join(rt.rel, coreseal.Dir, seal.RecordsFile)
		if seen[recordPath] {
			continue
		}
		seen[recordPath] = true
		commits, err := git(ctx, r.top, nil, "log", "--all", "--format=%H", "--", ":(literal)"+recordPath)
		if err != nil {
			return fmt.Errorf("%s sealed key history: %w", r.top, err)
		}
		for _, commit := range strings.Fields(commits) {
			raw, err := git(ctx, r.top, nil, "show", commit+":"+recordPath)
			if err != nil {
				continue // a commit that deleted the records
			}
			recs, err := seal.ParseRecords([]byte(raw))
			if err != nil {
				continue // invalid old records cannot establish preservation
			}
			s.addSeals(rt.project, recs, func(env string) ([]byte, error) {
				// Record keys are untrusted paths, even in local Git history.
				if env == "" || filepath.Base(env) != env || strings.ContainsAny(env, `/\\`) {
					return nil, errors.New("invalid seal environment")
				}
				data, err := git(ctx, r.top, nil, "show", commit+":"+path.Join(rt.rel, coreseal.Dir, env+".age"))
				return []byte(data), err
			})
		}
	}
	return nil
}
