package account_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/mscno/esec-vault/internal/team"
)

func TestSharedEnvironmentRenameAndMachineGrant(t *testing.T) {
	h, a := setup(t)
	ctx := context.Background()
	st, err := a.CreateTeam(ctx, project, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateMachine(ctx, project, "rename-ci", []string{"dev"}, nil); err != nil {
		t.Fatal(err)
	}
	var before []byte
	if err := h.DB.SQL().QueryRow(`SELECT envelope FROM project_grants WHERE project=? ORDER BY id DESC LIMIT 1`, project).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := h.DB.SQL().Exec(`INSERT INTO access_expiries(project,subject,envs,expires_at,created_by,created_at) VALUES (?,?,'["dev"]',9999999999,?,0)`, project, a.State.User, a.State.User); err != nil {
		t.Fatal(err)
	}
	if err := a.RenameEnv(ctx, project, "dev", "development", st.Envs["dev"].PublicKey); err != nil {
		t.Fatal(err)
	}
	if err := a.RenameEnv(ctx, project, "dev", "development", st.Envs["dev"].PublicKey); err != nil {
		t.Fatalf("retry failed: %v", err)
	}
	v, err := a.Team(ctx, project)
	if err != nil {
		t.Fatal(err)
	}
	if v.State.Envs["dev"] != nil || v.State.Envs["development"].PublicKey != st.Envs["dev"].PublicKey {
		t.Fatal("vault environment not renamed")
	}
	for _, m := range v.State.ActiveMachines() {
		if len(m.Envs) != 1 || m.Envs[0] != "development" {
			t.Fatal("machine access not renamed")
		}
	}
	var after []byte
	var raw string
	if err := h.DB.SQL().QueryRow(`SELECT envelope,envs FROM project_grants WHERE project=? ORDER BY id DESC LIMIT 1`, project).Scan(&after, &raw); err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("signed grant ciphertext rewritten")
	}
	var envs []team.Env
	if err := json.Unmarshal([]byte(raw), &envs); err != nil || envs[0].Name != "development" {
		t.Fatalf("grant projection not renamed: %s %v", raw, err)
	}
	if err := h.DB.SQL().QueryRow(`SELECT envs FROM access_expiries WHERE project=?`, project).Scan(&raw); err != nil || raw != `["development"]` {
		t.Fatalf("timed access not renamed: %s %v", raw, err)
	}
	if err := a.RenameEnv(ctx, project, "development", "dev", st.Envs["dev"].PublicKey); err == nil {
		t.Fatal("destination collision accepted")
	}
}
