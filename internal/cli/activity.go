package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/mscno/esec-vault/internal/broker"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/safetext"
)

// ActivityCmd shows which programs asked the background service for keys:
// the local audit log, newest first.
type ActivityCmd struct {
	Project string        `help:"Only this project"`
	Env     string        `help:"Only this environment"`
	Since   time.Duration `default:"168h" help:"How far back"`
	Limit   int           `default:"50" help:"At most this many entries"`
	Denied  bool          `help:"Only refused requests"`
	JSON    bool          `help:"Print JSON, for scripts, agents and the Mac app"`
}

// Run implements activity.
func (c *ActivityCmd) Run(_ *cliCtx) error {
	entries, err := readAudit(paths.AuditPath(), auditFilter{
		project: c.Project, env: c.Env, since: time.Now().Add(-c.Since), limit: c.Limit, denied: c.Denied,
	})
	if err != nil {
		return err
	}
	if c.JSON {
		return printJSON(nonNil(entries))
	}
	if len(entries) == 0 {
		fmt.Println("No key requests in that time.")
		return nil
	}
	for _, e := range entries {
		what := e.Project
		if e.Env != "" {
			what += " " + e.Env
		}
		fmt.Printf("%s  %-6s %-24s %s", e.Time.Local().Format("Jan _2 15:04"), e.Decision, safetext.Clean(what), safetext.Clean(e.Caller)) //nolint:gosmopolitan // shown to the local user
		if e.Session != "" {
			fmt.Printf(" [%s]", safetext.Clean(e.Session))
		}
		if e.Detail != "" {
			fmt.Printf("  %s", safetext.Clean(e.Detail))
		}
		fmt.Println()
	}
	return nil
}

type auditFilter struct {
	project, env string
	since        time.Time
	limit        int
	denied       bool
}

// readAudit reads the audit log's matching entries, newest first. Lines
// that do not parse (a torn last write) are skipped.
func readAudit(path string, f auditFilter) ([]broker.AuditEntry, error) {
	file, err := os.Open(path) //nolint:gosec // the audit log in the vault's home
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var out []broker.AuditEntry
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var e broker.AuditEntry
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		switch {
		case e.Time.Before(f.since),
			f.project != "" && e.Project != f.project,
			f.env != "" && e.Env != f.env,
			f.denied && e.Decision != "deny":
			continue
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	if f.limit > 0 && len(out) > f.limit {
		out = out[:f.limit]
	}
	return out, nil
}
