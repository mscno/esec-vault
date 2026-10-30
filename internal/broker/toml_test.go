package broker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mscno/esec"
	"github.com/mscno/esec-vault/internal/policy"
)

func TestBrokerInjectsTomlScalars(t *testing.T) {
	skipUnlessUnix(t)
	pub, priv, err := esec.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	var enc strings.Builder
	plain := "_ESEC_PUBLIC_KEY='" + pub + "'\n[database]\npassword='broker-secret'\nport=5432\n"
	if _, err := esec.Encrypt(strings.NewReader(plain), &enc, esec.FileFormatEtoml); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "production.etoml")
	if err := os.WriteFile(file, []byte(enc.String()), 0600); err != nil {
		t.Fatal(err)
	}
	client, _, _ := startTestBroker(t,
		map[string]map[string]string{"org/repo": {"ESEC_PRIVATE_KEY_PRODUCTION": priv}},
		&policy.Policy{Default: policy.Deny, Rules: []policy.Rule{{Project: "org/repo", Env: []string{"production"}, Action: policy.Allow}}})
	values, err := client.GetSecrets("org/repo", "production", file, ".etoml")
	if err != nil {
		t.Fatal(err)
	}
	if values["DATABASE__PASSWORD"] != "broker-secret" || values["DATABASE__PORT"] != "5432" || len(values) != 2 {
		t.Fatal("TOML mapping or metadata exclusion failed")
	}
}
