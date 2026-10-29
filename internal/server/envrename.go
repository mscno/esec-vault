package server

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/team"
)

// Only live projections change; signed envelopes and audit history stay intact.
func renameEnvironmentMetadata(ctx context.Context, tx *sql.Tx, project string, l team.Link) error {
	var b team.EnvRenameBody
	if err := envelope.DecodeStrict(l.Body, &b); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE project_holdings SET env=? WHERE project=? AND env=?`, b.New, project, b.Old); err != nil {
		return err
	}
	jobs := []struct {
		read, write string
		grants      bool
	}{
		{`SELECT id,envs FROM project_grants WHERE project=?`, `UPDATE project_grants SET envs=? WHERE id=?`, true},
		{`SELECT id,envs FROM access_expiries WHERE project=? AND status='open'`, `UPDATE access_expiries SET envs=? WHERE id=?`, false},
		{`SELECT id,envs FROM access_requests WHERE project=? AND status='open'`, `UPDATE access_requests SET envs=? WHERE id=?`, false},
		{`SELECT id,envs FROM invites WHERE scope='project' AND target=? AND status='open'`, `UPDATE invites SET envs=? WHERE id=?`, false},
		{`SELECT id,envs FROM changes WHERE ((scope='project' AND target=?) OR project=?) AND status='open'`, `UPDATE changes SET envs=? WHERE id=?`, false},
	}
	for i, job := range jobs {
		args := []any{project}
		if i == len(jobs)-1 {
			args = append(args, project)
		}
		type row struct {
			id  int64
			raw string
		}
		var updates []row
		if err := scanAll(ctx, tx, job.read, args, func(r *sql.Rows) error {
			var id int64
			var raw string
			if err := r.Scan(&id, &raw); err != nil {
				return err
			}
			var data []byte
			if job.grants {
				var envs []team.Env
				if err := json.Unmarshal([]byte(raw), &envs); err != nil {
					return err
				}
				for j := range envs {
					if envs[j].Name == b.Old {
						envs[j].Name = b.New
					}
				}
				var err error
				data, err = json.Marshal(envs)
				if err != nil {
					return err
				}
			} else {
				var envs []string
				if err := json.Unmarshal([]byte(raw), &envs); err != nil {
					return err
				}
				for j := range envs {
					if envs[j] == b.Old {
						envs[j] = b.New
					}
				}
				var err error
				data, err = json.Marshal(envs)
				if err != nil {
					return err
				}
			}
			updates = append(updates, row{id, string(data)})
			return nil
		}); err != nil {
			return err
		}
		for _, r := range updates {
			if _, err := tx.ExecContext(ctx, job.write, r.raw, r.id); err != nil {
				return err
			}
		}
	}
	return nil
}
