package cli

import (
	"testing"

	"github.com/mscno/esec-vault/internal/vaultfile"
)

func TestNormalOperationsRequireLogin(t *testing.T) {
	for _, cmd := range []string{"project init <project>", "env list", "env rotate <name>", "backup", "restore", "run <env> -- <command>", "decrypt <env>", "seal recover", "sync", "unlock", "identity init", "identity rotate", "identity show"} {
		if !requiresLogin(cmd) {
			t.Errorf("%q bypasses login", cmd)
		}
	}
	for _, cmd := range []string{"login", "setup", "setup --check", "recover", "status", "daemon stop", "lock", "machine run <env> -- <command>"} {
		if requiresLogin(cmd) {
			t.Errorf("bootstrap or machine authentication blocked: %q", cmd)
		}
	}
}

func TestLegacyBackupIgnoresExternalSyncSettings(t *testing.T) {
	v := &vaultfile.Vault{Projects: map[string]map[string]string{}, Files: map[string][]byte{"remote.toml": []byte("obsolete provider config"), "policy.toml": []byte("rules = []")}}
	if err := validateRestore(v); err != nil {
		t.Fatal(err)
	}
	if _, ok := v.Files["remote.toml"]; ok {
		t.Fatal("obsolete external sync settings would be restored")
	}
	if _, ok := v.Files["policy.toml"]; !ok {
		t.Fatal("supported settings lost")
	}
}
