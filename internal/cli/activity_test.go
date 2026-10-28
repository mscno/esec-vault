package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadAuditNewestFirstAndFiltered(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	now := time.Now().UTC()
	line := func(ts time.Time, project, env, decision string) string {
		return `{"ts":"` + ts.Format(time.RFC3339Nano) + `","op":"get","project":"` + project + `","env":"` + env + `","decision":"` + decision + `","caller":"zsh ▸ claude"}` + "\n"
	}
	data := line(now.Add(-48*time.Hour), "acme/store", "prod", "allow") +
		line(now.Add(-2*time.Hour), "acme/store", "prod", "ask") +
		"{torn\n" +
		line(now.Add(-time.Hour), "acme/store", "prod", "deny") +
		line(now.Add(-time.Minute), "acme/web", "dev", "allow")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	all, err := readAudit(path, auditFilter{since: now.Add(-24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 || all[0].Project != "acme/web" || all[2].Decision != "ask" || all[0].Caller != "zsh ▸ claude" {
		t.Fatalf("entries = %+v", all)
	}
	denied, _ := readAudit(path, auditFilter{since: now.Add(-24 * time.Hour), denied: true})
	if len(denied) != 1 || denied[0].Decision != "deny" {
		t.Fatalf("denied = %+v", denied)
	}
	one, _ := readAudit(path, auditFilter{project: "acme/store", env: "prod", limit: 1})
	if len(one) != 1 || one[0].Decision != "deny" {
		t.Fatalf("limited = %+v", one)
	}
	missing, err := readAudit(filepath.Join(t.TempDir(), "none"), auditFilter{})
	if err != nil || missing != nil {
		t.Fatalf("missing log = %v, %v", missing, err)
	}
}
