package runcmd

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/projectfile"

	"github.com/mscno/esec-vault/internal/broker"
	"github.com/mscno/esec-vault/internal/policy"
	"github.com/mscno/esec-vault/internal/seal"
)

func TestResolveSecretsFile(t *testing.T) {
	dir := t.TempDir()
	// Only an .env.dev exists.
	if err := os.WriteFile(filepath.Join(dir, ".env.dev"), []byte("A=B\n"), 0600); err != nil {
		t.Fatal(err)
	}

	path, format, err := resolveSecretsFile(dir, "dev", "")
	if err != nil {
		t.Fatal(err)
	}
	if format != ".env" || !strings.HasSuffix(path, ".env.dev") {
		t.Fatalf("got %s %s", path, format)
	}
	if !filepath.IsAbs(path) {
		t.Fatal("path must be absolute")
	}

	// Explicit format that does not exist errors.
	if _, _, err := resolveSecretsFile(dir, "dev", ".ejson"); err == nil {
		t.Fatal("expected error for missing .ejson.dev")
	}
	// Unknown environment errors.
	if _, _, err := resolveSecretsFile(dir, "prod", ""); err == nil {
		t.Fatal("expected error for missing environment")
	}
	// Explicit file path wins.
	p, f, err := resolveSecretsFile(dir, filepath.Join(dir, ".env.dev"), "")
	if err != nil || f != ".env" || p == "" {
		t.Fatalf("explicit path: %s %s %v", p, f, err)
	}
}

func TestRunInjectsSecretsFromBroker(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("broker requires unix sockets")
	}
	dir := t.TempDir()

	// Real encrypted secrets file in the repo.
	pub, priv, err := esec.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	var enc strings.Builder
	if _, err := esec.Encrypt(strings.NewReader(`{"_ESEC_PUBLIC_KEY": "`+pub+`", "GREETING": "hello-vault"}`), &enc, esec.FileFormatEjson); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".ejson.dev"), []byte(enc.String()), 0600); err != nil {
		t.Fatal(err)
	}
	if err := projectfile.WriteProjectFile(dir, "org/repo"); err != nil {
		t.Fatal(err)
	}

	// Live broker holding the project key, policy allowing dev. The socket
	// path must stay short (104-char unix socket limit on darwin), so
	// t.TempDir() is too long for it.
	sockDir, err := os.MkdirTemp("", "ev") //nolint:usetesting // see above
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)
	sock := filepath.Join(sockDir, "b.sock")
	audit, err := broker.NewAuditLogger(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	srv := broker.NewServer(
		map[string]map[string]string{"org/repo": {"ESEC_PRIVATE_KEY_DEV": priv}},
		&policy.Policy{Default: policy.Deny, Rules: []policy.Rule{{Project: "*", Env: []string{"dev"}, Action: policy.Allow}}},
		audit, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, sock) }()
	client := broker.NewClient(sock)
	deadline := time.Now().Add(5 * time.Second)
	for client.Ping() != nil {
		if time.Now().After(deadline) {
			t.Fatal("broker did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Run from the repo dir; child prints the secret.
	t.Chdir(dir)

	marker := filepath.Join(t.TempDir(), "out")
	cmd := []string{"sh", "-c", "printf '%s' \"$GREETING\" > " + marker}
	if err := Run(client, "dev", "", cmd, Options{}); err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(marker) //nolint:gosec // test fixture path
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "hello-vault" {
		t.Fatalf("child did not receive injected secret: %q", out)
	}

	// decrypt fetches the same secrets without a command.
	secrets, err := Fetch(client, "dev", "", Options{})
	if err != nil || secrets["GREETING"] != "hello-vault" {
		t.Fatalf("fetch: %v %v", secrets, err)
	}

	// Denied environment must fail.
	if err := Run(client, "prod", "", []string{"true"}, Options{}); err == nil {
		t.Fatal("prod should be denied")
	}
	if _, err := Fetch(client, "prod", "", Options{}); err == nil {
		t.Fatal("prod should be denied to fetch")
	}
}

// Print shows one value bare, or every secret one per line in key order,
// quoting a value that spans lines; JSON on request.
func TestPrint(t *testing.T) {
	secrets := map[string]string{"B": "two", "A": "one", "PEM": "-----BEGIN-----\nabc\n-----END-----"}
	var out strings.Builder
	if err := Print(&out, secrets, "", false, false); err != nil {
		t.Fatal(err)
	}
	if want := "A=one\nB=two\nPEM=\"-----BEGIN-----\\nabc\\n-----END-----\"\n"; out.String() != want {
		t.Fatalf("all:\n%s\nwant:\n%s", out.String(), want)
	}
	out.Reset()
	if err := Print(&out, secrets, "B", false, false); err != nil || out.String() != "two\n" {
		t.Fatalf("one: %q %v", out.String(), err)
	}
	out.Reset()
	if err := Print(&out, secrets, "A", true, false); err != nil || out.String() != "{\n  \"A\": \"one\"\n}\n" {
		t.Fatalf("json: %q %v", out.String(), err)
	}
	if err := Print(&out, secrets, "MISSING", false, false); err == nil || !strings.Contains(err.Error(), "no secret named MISSING") {
		t.Fatalf("missing: %v", err)
	}
}

// Print refuses a name that would forge a line and shows a value with
// control characters escaped, so a value planted in the secrets file cannot
// fake a line or drive the terminal.
func TestPrintEscapes(t *testing.T) {
	var out strings.Builder
	for _, k := range []string{"A\nB", "A=B", "", "A\x1bB"} {
		if err := Print(&out, map[string]string{k: "v"}, "", false, false); err == nil {
			t.Errorf("printed a secret named %q", k)
		}
	}
	out.Reset()
	esc := "x\x1b]52;c;aGk=\x07"
	if err := Print(&out, map[string]string{"E": esc, "Q": `"q"`, "T": "a\tb"}, "", false, false); err != nil {
		t.Fatal(err)
	}
	if want := "E=" + strconv.Quote(esc) + "\nQ=" + strconv.Quote(`"q"`) + "\nT=" + strconv.Quote("a\tb") + "\n"; out.String() != want {
		t.Fatalf("lines %q, want %q", out.String(), want)
	}
	out.Reset()
	if err := Print(&out, map[string]string{"C1": "a\u009b31mb"}, "", true, false); err != nil || strings.ContainsRune(out.String(), '\u009b') || !strings.Contains(out.String(), `\u009b`) {
		t.Fatalf("json %q %v", out.String(), err)
	}
	out.Reset()
	if err := Print(&out, map[string]string{"E": esc}, "E", false, false); err != nil || out.String() != esc+"\n" {
		t.Fatalf("piped value %q %v", out.String(), err)
	}
	out.Reset()
	if err := Print(&out, map[string]string{"E": esc, "P": "a\nb"}, "E", false, true); err != nil || out.String() != strconv.Quote(esc)+"\n" {
		t.Fatalf("value on a terminal %q %v", out.String(), err)
	}
	out.Reset()
	if err := Print(&out, map[string]string{"P": "a\nb"}, "P", false, true); err != nil || out.String() != "a\nb\n" {
		t.Fatalf("multi-line value on a terminal %q %v", out.String(), err)
	}
	if !Unsafe(esc) || Unsafe("-----BEGIN-----\nabc\n\tdef") {
		t.Fatal("Unsafe")
	}
}

// The touch notice knows an environment guarded by its seal record alone.
func TestGuardedBySealRecord(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "esec.toml"), []byte("project = \"acme/web\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if guarded(dir, "prod") {
		t.Fatal("guarded with no record")
	}
	if err := (seal.Records{"prod": {Guard: "touch"}}).Save(dir); err != nil {
		t.Fatal(err)
	}
	if !guarded(dir, "prod") || guarded(dir, "dev") {
		t.Fatal("the seal record's guard was not seen")
	}
}

func TestResolveSecretsFileEnvironmentNamesAreExact(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv("ESEC_CONFIG", "")
	for _, pair := range [][2]string{{"prod", "production"}, {"dev", "development"}, {"stage", "staging"}} {
		for _, names := range [][2]string{pair, {pair[1], pair[0]}} {
			t.Run(names[0]+"-is-not-"+names[1], func(t *testing.T) {
				dir := t.TempDir()
				other := filepath.Join(dir, ".env."+names[1])
				if err := os.WriteFile(other, nil, 0600); err != nil {
					t.Fatal(err)
				}
				if _, _, err := resolveSecretsFile(dir, names[0], ""); err == nil || !strings.Contains(err.Error(), "no secrets file") {
					t.Fatalf("resolved another environment: %v", err)
				}
				exact := filepath.Join(dir, ".env."+names[0])
				if err := os.WriteFile(exact, nil, 0600); err != nil {
					t.Fatal(err)
				}
				if got, format, err := resolveSecretsFile(dir, names[0], ""); err != nil || got != exact || format != ".env" {
					t.Fatalf("exact environment: %s %s %v", got, format, err)
				}
			})
		}
	}
}
