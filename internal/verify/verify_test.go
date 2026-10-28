package verify

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/projectfile"

	"github.com/mscno/esec-vault/internal/keystore"
)

func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.email=t@example.com", "-c", "user.name=t", "-c", "commit.gpgsign=false"}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
}

func TestVerifyFindsLostReusedAndHistoricKeys(t *testing.T) { //nolint:gocyclo // one story, step by step
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv("ESEC_CONFIG", "")
	repo := t.TempDir()
	gitRun(t, repo, "init", "-q")
	if err := projectfile.WriteProjectFile(repo, "acme/store"); err != nil {
		t.Fatal(err)
	}
	oldPub, oldPriv, _ := esec.GenerateKeypair()
	newPub, newPriv, _ := esec.GenerateKeypair()
	file := filepath.Join(repo, ".env.prod")
	write := func(pub string) {
		if err := os.WriteFile(file, []byte("ESEC_PUBLIC_KEY="+pub+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(oldPub)
	gitRun(t, repo, "add", "-A")
	gitRun(t, repo, "commit", "-q", "-m", "old")
	write(newPub) // rotated: the old key now only in history
	gitRun(t, repo, "commit", "-q", "-am", "new")

	uses, files, err := Collect(context.Background(), []string{repo}, true)
	if err != nil {
		t.Fatal(err)
	}
	if files != 1 || len(uses[oldPub]) == 0 || len(uses[newPub]) == 0 {
		t.Fatalf("uses: %v (files %d)", uses, files)
	}

	local := map[string]map[string]string{"acme/store": {keystore.PubEntry(newPub): newPriv, keystore.PubEntry(oldPub): oldPriv}}
	server := map[string]map[string]string{"acme/store": {keystore.EnvEntry("prod"): newPriv}} // an old vault: named only
	rep := Build(uses, []Source{{Name: "this device", Projects: local}, {Name: "vault server", Projects: server}, {Name: "backup", Err: os.ErrNotExist}})
	if rep.Lost != 0 || rep.Problems != 1 {
		t.Fatalf("report: %+v", rep)
	}
	for _, k := range rep.Keys {
		if k.Public == oldPub && (k.Places != 1 || !strings.Contains(strings.Join(k.Problems, ";"), "one place only")) {
			t.Fatalf("old key: %+v", k)
		}
		if k.Public == newPub && (k.Places != 2 || len(k.Problems) != 0) {
			t.Fatalf("new key: %+v", k)
		}
	}
	if rep.Sources[2].Checked || rep.Sources[2].Error == "" {
		t.Fatalf("unchecked source: %+v", rep.Sources)
	}

	// The same key in another project's keyring is reuse; no copy is loss.
	local["acme/shop"] = map[string]string{keystore.PubEntry(newPub): newPriv}
	delete(local["acme/store"], keystore.PubEntry(oldPub))
	rep = Build(uses, []Source{{Name: "this device", Projects: local}})
	if rep.Lost != 1 {
		t.Fatalf("lost: %+v", rep)
	}
	var reuse bool
	for _, k := range rep.Keys {
		if k.Public == newPub && strings.Contains(strings.Join(k.Problems, ";"), "several projects: acme/shop, acme/store") {
			reuse = true
		}
	}
	if !reuse {
		t.Fatalf("reuse not found: %+v", rep.Keys)
	}
}

// A monorepo's subprojects each claim only their own files' history; a
// worktree adds no second read of the same history.
func TestHistoryByCheckoutInMonorepoAndWorktrees(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv("ESEC_CONFIG", "")
	repo := t.TempDir()
	gitRun(t, repo, "init", "-q")
	pubs := map[string]string{}
	for _, sub := range []string{"svc/a", "svc/b"} {
		dir := filepath.Join(repo, sub)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := projectfile.WriteProjectFile(dir, "acme/"+filepath.Base(sub)); err != nil {
			t.Fatal(err)
		}
		pub, _, _ := esec.GenerateKeypair()
		pubs[sub] = pub
		if err := os.WriteFile(filepath.Join(dir, ".env.prod"), []byte("ESEC_PUBLIC_KEY="+pub+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A file under no checkout belongs to nobody known here.
	stray, _, _ := esec.GenerateKeypair()
	if err := os.WriteFile(filepath.Join(repo, ".env.ci"), []byte("ESEC_PUBLIC_KEY="+stray+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "-A")
	gitRun(t, repo, "commit", "-q", "-m", "init")
	wt := filepath.Join(t.TempDir(), "wt")
	gitRun(t, repo, "worktree", "add", "-q", wt)

	checkouts := []string{filepath.Join(repo, "svc/a"), filepath.Join(repo, "svc/b"), filepath.Join(wt, "svc/a")}
	if got := repos(context.Background(), checkouts); len(got) != 1 || len(got[0].roots) != 3 {
		t.Fatalf("repos: %+v", got)
	}
	uses, _, err := Collect(context.Background(), checkouts, true)
	if err != nil {
		t.Fatal(err)
	}
	for sub, pub := range pubs {
		for _, u := range uses[pub] {
			if u.Project != "acme/"+filepath.Base(sub) {
				t.Fatalf("%s's key claimed by %s", sub, u.Project)
			}
		}
	}
	if len(uses[stray]) != 0 {
		t.Fatalf("stray file claimed: %+v", uses[stray])
	}
	if _, err := os.Stat(historyFile()); err != nil {
		t.Fatalf("history not cached: %v", err)
	}
	rep := Build(uses, []Source{{Name: "this device", Projects: map[string]map[string]string{}}})
	if rep.Problems != 0 || rep.Lost != 0 || rep.Unheld != 2 {
		t.Fatalf("keys of projects held nowhere are not losses: %+v", rep)
	}
}
