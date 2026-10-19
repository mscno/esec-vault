package server

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/mscno/esec-vault/internal/wire"
)

func TestRelTime(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	for d, want := range map[time.Duration]string{
		10 * time.Second:      "just now",
		-10 * time.Second:     "in under a minute",
		time.Minute:           "1 minute ago",
		90 * time.Minute:      "1 hour ago",
		47 * time.Hour:        "47 hours ago",
		3 * 24 * time.Hour:    "3 days ago",
		-5 * 24 * time.Hour:   "in 5 days",
		100 * 24 * time.Hour:  "3 months ago",
		800 * 24 * time.Hour:  "2 years ago",
		-400 * 24 * time.Hour: "in 13 months",
	} {
		if got := relTime(now, now.Add(-d)); got != want {
			t.Errorf("relTime(-%v) = %q, want %q", d, got, want)
		}
	}
	if got := relTime(now, time.Time{}); got != "never" {
		t.Errorf("zero time: %q", got)
	}
	if got := durationText(720 * time.Hour); got != "30 days" {
		t.Errorf("durationText: %q", got)
	}
}

func TestBrowserSummary(t *testing.T) {
	for ua, want := range map[string]string{
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:131.0) Gecko/20100101 Firefox/131.0":                                                    "Firefox on macOS",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0":           "Edge on Windows",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1": "Safari on iOS",
		"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36":                            "Chrome on Android",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36":                                   "Chrome on Linux",
		"Go-http-client/1.1": "Unknown browser",
		"":                   "Unknown browser",
	} {
		if got := browserSummary(ua); got != want {
			t.Errorf("browserSummary(%q) = %q, want %q", ua, got, want)
		}
	}
}

func TestAuditViews(t *testing.T) {
	names := map[string]string{"d_a": "laptop", "d_b": "vm"}
	rows := []auditRow{
		{Action: "device_added", DeviceID: "d_a", Detail: "d_b via approval"},
		{Action: "device_suspended", Detail: "d_b"},
		{Action: "commit", Detail: "links=1 boxes=2 identity=false vault=true slots=0"},
		{Action: "login_denied", Detail: "gh:7 stranger"},
		{Action: "chain_device_revoke", Detail: "4"},
		{Action: "something_new", Detail: "raw"},
	}
	want := []struct{ label, subject, text, device string }{
		{"Device approved", "vm", "via approval from another device", "laptop"},
		{"Device suspended", "vm", "", ""},
		{"Account change saved", "", "1 chain link, 2 device keys, vault", ""},
		{"Sign-in refused: not allowed", "", "stranger (GitHub 7)", ""},
		{"Device revoked", "", "chain link 4", ""},
		{"something_new", "", "raw", ""},
	}
	for i, v := range auditViews(rows, names, nil) {
		w := want[i]
		if v.Label != w.label || v.SubjectName != w.subject || v.Text != w.text || v.DeviceName != w.device {
			t.Errorf("%s: got %q %q %q %q, want %v", rows[i].Action, v.Label, v.SubjectName, v.Text, v.DeviceName, w)
		}
	}
}

func TestFilterIndex(t *testing.T) {
	idx := &wire.VaultIndex{Projects: []wire.IndexProject{
		{ID: "acme/store", Environments: []wire.IndexEnv{{Name: "production", PublicKey: "aa11"}, {Name: "staging", PublicKey: "bb22"}}},
		{ID: "acme/billing", Environments: []wire.IndexEnv{{Name: "Production", PublicKey: "cc33"}}},
	}}
	count := func(q string) (projects, envs int) {
		out := filterIndex(idx, q)
		for _, p := range out.Projects {
			envs += len(p.Environments)
		}
		return len(out.Projects), envs
	}
	for q, want := range map[string][2]int{"": {2, 3}, "STORE": {1, 2}, "production": {2, 2}, "BB22": {1, 1}, "zz": {0, 0}} {
		if p, e := count(q); p != want[0] || e != want[1] {
			t.Errorf("filterIndex(%q): %d projects, %d environments, want %v", q, p, e, want)
		}
	}
}

// TestOldDatabasesGainColumns opens a database made before the browser list
// existed.
func TestOldDatabasesGainColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	old, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`CREATE TABLE web_sessions (id_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, csrf TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`INSERT INTO web_sessions VALUES ('h', 'gh:1', 'c', 1, 2)`); err != nil {
		t.Fatal(err)
	}
	old.Close()
	for range 2 {
		db, err := OpenDB(path)
		if err != nil {
			t.Fatal(err)
		}
		var agent, ip string
		if err := db.sql.QueryRow(`SELECT user_agent, ip FROM web_sessions WHERE id_hash = 'h'`).Scan(&agent, &ip); err != nil {
			t.Fatal(err)
		}
		db.Close()
	}
}
