package cli

import (
	"strings"
	"testing"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec/pkg/projectfile"
)

func TestProjectCheckRejectsABadID(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	err := (&ProjectCheckCmd{ID: "not-an-id", JSON: true}).Run(testCtx(t))
	var code *exitCodeError
	if err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatal(err)
	}
	if !asExit(err, &code) || code.code != 80 {
		t.Fatalf("exit: %v", err)
	}
}

func TestProjectCheckNeedsASignIn(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	err := (&ProjectCheckCmd{ID: "acme/store"}).Run(testCtx(t))
	if err == nil || !strings.Contains(err.Error(), "not signed in") {
		t.Fatal(err)
	}
}

func TestReservedNamespaceIsSystem(t *testing.T) {
	if !reservedNamespaceName("vault") || reservedNamespaceName("acme") {
		t.Fatal("reserved list")
	}
	if projectfile.ValidateOrgRepo("vault/x") != nil {
		t.Fatal("vault/x should be a syntactic project id; the check, not the format, refuses it")
	}
}

func TestInitGuardLevels(t *testing.T) {
	levels, err := initGuardLevels([]string{"dev", "production"}, []string{"production=session", "dev"})
	if err != nil {
		t.Fatal(err)
	}
	if levels["production"] != "session" || levels["dev"] != "touch" {
		t.Fatal(levels)
	}
	if _, err := initGuardLevels([]string{"dev"}, []string{"nope=touch"}); err == nil {
		t.Fatal("guard for an unknown environment accepted")
	}
	if _, err := initGuardLevels([]string{"dev"}, []string{"dev=sometimes"}); err == nil {
		t.Fatal("bad guard level accepted")
	}
}

func asExit(err error, dst **exitCodeError) bool {
	e, ok := err.(*exitCodeError)
	if ok {
		*dst = e
	}
	return ok
}

// account is imported so a future check test can build a signed-in state
// without the compiler dropping the dependency if this file is split.
var _ = account.ErrNotLoggedIn
