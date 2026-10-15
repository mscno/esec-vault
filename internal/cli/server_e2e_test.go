package cli_test

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/mscno/esec/pkg/keyringfile"

	"github.com/mscno/esec-vault/internal/server"
	"github.com/mscno/esec-vault/internal/servertest"
)

var (
	buildOnce sync.Once
	binDir    string
	errBuild  error
)

// buildBinaries compiles esec-vault and esec (from the module's esec
// dependency) once per test run.
func buildBinaries(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "esec-e2e-bin-") //nolint:usetesting // shared by every test in the run
		if err != nil {
			errBuild = err
			return
		}
		binDir = dir
		root, err := filepath.Abs("../..")
		if err != nil {
			errBuild = err
			return
		}
		for _, target := range [][2]string{{"esec-vault", "./cmd/esec-vault"}, {"esec", "github.com/mscno/esec/cmd/esec"}} {
			cmd := exec.Command("go", "build", "-o", filepath.Join(dir, target[0]), target[1])
			cmd.Dir = root
			if out, err := cmd.CombinedOutput(); err != nil {
				errBuild = fmt.Errorf("build %s: %v\n%s", target[0], err, out)
				return
			}
		}
	})
	if errBuild != nil {
		t.Fatal(errBuild)
	}
	return binDir
}

// machine is one simulated computer: its own vault home and secret store.
type machine struct {
	t    *testing.T
	name string
	home string
	bin  string
	env  []string
}

func newMachine(t *testing.T, bin, name string) *machine {
	t.Helper()
	home := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	env := []string{
		"PATH=" + bin + string(os.PathListSeparator) + "/usr/bin:/bin",
		"HOME=" + home,
		"ESEC_VAULT_HOME=" + home,
		"ESEC_SECRET_STORE=file",
		"TMPDIR=" + os.TempDir(),
	}
	return &machine{t: t, name: name, home: home, bin: bin, env: env}
}

func (m *machine) with(extra ...string) *machine {
	c := *m
	c.env = append(append([]string(nil), m.env...), extra...)
	return &c
}

// run executes esec-vault (or another tool with tool=true) and returns
// combined output, failing the test on error unless allowFail.
func (m *machine) cmd(dir, stdin string, tool string, args ...string) *exec.Cmd {
	c := exec.Command(filepath.Join(m.bin, tool), args...)
	c.Env = m.env
	c.Dir = dir
	c.Stdin = strings.NewReader(stdin)
	return c
}

func (m *machine) run(stdin string, args ...string) string {
	m.t.Helper()
	out, err := m.cmd(m.home, stdin, "esec-vault", args...).CombinedOutput()
	if err != nil {
		m.t.Fatalf("%s: esec-vault %s: %v\n%s", m.name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

func (m *machine) runFail(stdin string, args ...string) {
	m.t.Helper()
	out, err := m.cmd(m.home, stdin, "esec-vault", args...).CombinedOutput()
	if err == nil {
		m.t.Fatalf("%s: esec-vault %s succeeded unexpectedly:\n%s", m.name, strings.Join(args, " "), out)
	}
}

func (m *machine) tool(dir string, args ...string) string {
	m.t.Helper()
	out, err := m.cmd(dir, "", "esec", args...).CombinedOutput()
	if err != nil {
		m.t.Fatalf("%s: esec %s: %v\n%s", m.name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

// background is a running esec-vault process whose output is scanned.
type background struct {
	t    *testing.T
	cmd  *exec.Cmd
	mu   sync.Mutex
	out  bytes.Buffer
	done chan error
}

func (m *machine) start(stdin string, args ...string) *background {
	m.t.Helper()
	c := m.cmd(m.home, stdin, "esec-vault", args...)
	pr, pw := io.Pipe()
	c.Stdout, c.Stderr = pw, pw
	b := &background{t: m.t, cmd: c, done: make(chan error, 1)}
	if err := c.Start(); err != nil {
		m.t.Fatal(err)
	}
	go func() {
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			b.mu.Lock()
			b.out.WriteString(sc.Text() + "\n")
			b.mu.Unlock()
		}
	}()
	go func() { err := c.Wait(); pw.Close(); b.done <- err }()
	m.t.Cleanup(func() { _ = c.Process.Kill() })
	return b
}

func (b *background) output() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.out.String()
}

func (b *background) waitFor(pattern string) string {
	b.t.Helper()
	re := regexp.MustCompile(pattern)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if m := re.FindStringSubmatch(b.output()); m != nil {
			return m[1]
		}
		time.Sleep(50 * time.Millisecond)
	}
	b.t.Fatalf("timed out waiting for %q in:\n%s", pattern, b.output())
	return ""
}

func (b *background) wait(wantOK bool) string {
	b.t.Helper()
	select {
	case err := <-b.done:
		time.Sleep(50 * time.Millisecond)
		if (err == nil) != wantOK {
			b.t.Fatalf("process ended with %v (want success %t):\n%s", err, wantOK, b.output())
		}
	case <-time.After(60 * time.Second):
		b.t.Fatalf("process did not finish:\n%s", b.output())
	}
	return b.output()
}

var codePattern = `enter ([0-9A-Z]{4}-[0-9A-Z]{4})`

// login signs m in and confirms the code in the browser as login.
func login(t *testing.T, h *servertest.Harness, m *machine, stdin string, args ...string) *background {
	t.Helper()
	p := m.start(stdin, append([]string{"login", h.URL, "--no-browser", "--name", m.name}, args...)...)
	code := p.waitFor(codePattern)
	if err := h.Browser("mscno").Confirm(code, true); err != nil {
		t.Fatal(err)
	}
	return p
}

// testAgent serves an in-memory SSH agent holding one Ed25519 key.
func testAgent(t *testing.T) (string, string) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "esa") //nolint:usetesting // unix socket paths must stay short
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "agent.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	kr := agent.NewKeyring()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if err := kr.Add(agent.AddedKey{PrivateKey: priv, Comment: "test"}); err != nil {
		t.Fatal(err)
	}
	pub, _ := ssh.NewPublicKey(priv.Public())
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { _ = agent.ServeAgent(kr, c); c.Close() }()
		}
	}()
	return sock, ssh.FingerprintSHA256(pub)
}

// decryptsTo checks that m can decrypt the test project's dev file.
func decryptsTo(t *testing.T, m *machine, repo string) {
	t.Helper()
	const want = "postgres://db-dev"
	out := m.tool(repo, "decrypt", ".env.dev")
	if !strings.Contains(out, want) {
		t.Fatalf("%s: decrypt .env.dev = %q, want it to contain %q", m.name, out, want)
	}
}

// TestVaultServerEndToEnd drives the whole device story with real binaries:
// account creation, approval, SSH-agent unlock, recovery phrase, key sync,
// revocation with key rotation, environment rotation, and a rejected
// intruder.
func TestVaultServerEndToEnd(t *testing.T) { //nolint:gocyclo,maintidx // one sequential story with explicit checks
	if testing.Short() {
		t.Skip("builds binaries")
	}
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets")
	}
	bin := buildBinaries(t)
	// Many machines sign in from localhost here, above the real per-address
	// limit; the limits themselves are tested in the server package.
	h := servertest.StartWith(t, []server.Option{server.WithRegistrationLimits(100, 1000)}, 53101343)
	h.GitHub.AddUser(53101343, "mscno")
	h.GitHub.AddUser(4242, "intruder")
	sock, fp := testAgent(t)

	// --- Laptop: identity, project, first login creates the account. ---
	laptop := newMachine(t, bin, "laptop").with("SSH_AUTH_SOCK=" + sock)
	out := laptop.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
	mnemonic := regexp.MustCompile(`(?m)^\s+((?:[a-z]+ ){23}[a-z]+)\s*$`).FindStringSubmatch(out)
	if mnemonic == nil {
		t.Fatalf("no recovery phrase in:\n%s", out)
	}
	repo := t.TempDir()
	laptop.run("", "project", "init", "acme/store", "--dir", repo, "--env", "dev,prod", "--format", "env")
	envDev := filepath.Join(repo, ".env.dev")
	data, err := os.ReadFile(envDev) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(envDev, append(data, []byte("DATABASE_URL=postgres://db-dev\n")...), 0o600); err != nil { //nolint:gosec // test temp dir
		t.Fatal(err)
	}
	laptop.tool(repo, "encrypt", "dev", "-f", "env")

	// Without the operator's bootstrap token no account can be created.
	login(t, h, laptop.with("ESEC_VAULT_BOOTSTRAP_TOKEN=wrong-token-wrong-token"), "").wait(false)
	login(t, h, laptop, "esb_from_the_prompt_but_wrong\n").wait(false)
	p := login(t, h, laptop.with("ESEC_VAULT_BOOTSTRAP_TOKEN="+servertest.BootstrapToken), "")
	out = p.wait(true)
	for _, want := range []string{"Signed in as mscno", "Created the vault account", "Account key:", "Sealed"} {
		if !strings.Contains(out, want) {
			t.Fatalf("laptop login output lacks %q:\n%s", want, out)
		}
	}
	accountKey := regexp.MustCompile(`Account key: (\S+)`).FindStringSubmatch(out)[1]
	raw, err := os.ReadFile(filepath.Join(laptop.home, "keyrings", "acme_store.keyring"))
	if err != nil || !keyringfile.IsSealed(raw) {
		t.Fatalf("laptop keyring not sealed after login: %v", err)
	}
	decryptsTo(t, laptop, repo)

	// --- An intruder's GitHub account cannot get in. ---
	intruder := newMachine(t, bin, "intruder")
	ip := intruder.start("", "login", h.URL, "--no-browser")
	code := ip.waitFor(codePattern)
	if err := h.Browser("intruder").Confirm(code, true); err == nil {
		t.Fatal("a GitHub account that is not allowlisted confirmed a code")
	}
	_ = ip.cmd.Process.Kill()

	// --- VM 1: approval from the laptop. ---
	// A wrong account key aborts before anything is installed.
	vm0 := newMachine(t, bin, "vm0")
	p = login(t, h, vm0, "", "--account-key", "abandon-abandon-abandon-abandon-abandon-abandon-abandon-about")
	vm0Words := p.waitFor(`Check that it shows this fingerprint: (\S+)`)
	// A plain "yes" no longer approves anything: the words must be typed.
	if out := laptop.run("y\n", "devices", "approve"); !strings.Contains(out, "does not match") {
		t.Fatalf("approval without the fingerprint:\n%s", out)
	}
	laptop.run(strings.ReplaceAll(vm0Words, "-", " ")+"\n", "devices", "approve")
	if out := p.wait(false); !strings.Contains(out, "nothing was installed") {
		t.Fatalf("wrong account key:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(vm0.home, "identity.esec")); err == nil {
		t.Fatal("identity installed despite a wrong account key")
	}
	if _, err := os.Stat(filepath.Join(vm0.home, "account.toml")); err == nil {
		t.Fatal("a declined account was kept")
	}
	vm0.runFail("", "sync", "--server")

	vm1 := newMachine(t, bin, "vm1")
	p = login(t, h, vm1, "", "--account-key", accountKey)
	words := p.waitFor(`Check that it shows this fingerprint: (\S+)`)
	approved := laptop.run(words+"\n", "devices", "approve")
	if !strings.Contains(approved, "Approved vm1") || !strings.Contains(approved, accountKey) {
		t.Fatalf("approval with the typed fingerprint %s failed:\n%s", words, approved)
	}
	out = p.wait(true)
	if !strings.Contains(out, "Approved by laptop") || !strings.Contains(out, "Account key: "+accountKey) {
		t.Fatalf("vm1 login output:\n%s", out)
	}
	decryptsTo(t, vm1, repo)

	// --- Laptop: enable SSH-agent unlock; VM 2 uses it. ---
	out = laptop.run("", "agent-unlock", "enable", "--key", fp, "--expires", "30d")
	if !strings.Contains(out, "can unlock new devices") {
		t.Fatalf("agent-unlock enable:\n%s", out)
	}
	vm2 := newMachine(t, bin, "vm2").with("SSH_AUTH_SOCK=" + sock)
	out = login(t, h, vm2, "", "--ssh-agent").wait(true)
	if !strings.Contains(out, "Added this device using ssh_agent") {
		t.Fatalf("vm2 login:\n%s", out)
	}
	decryptsTo(t, vm2, repo)

	// --- VM 3: recovery phrase; a wrong phrase is refused. ---
	vm3 := newMachine(t, bin, "vm3")
	wrong := "legal winner thank year wave sausage worth useful legal winner thank yellow"
	login(t, h, vm3, wrong+"\n", "--recover").wait(false)
	vm3 = newMachine(t, bin, "vm3b")
	out = login(t, h, vm3, mnemonic[1]+"\n", "--recover").wait(true)
	if !strings.Contains(out, "Added this device using recovery") {
		t.Fatalf("vm3 login:\n%s", out)
	}
	decryptsTo(t, vm3, repo)

	// --- A key added on the laptop reaches the VMs. ---
	added := laptop.run("", "env", "add", "qa", "--project", "acme/store")
	qaPub := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(added), "ESEC_PUBLIC_KEY="))
	if len(qaPub) != 64 {
		t.Fatalf("env add output: %q", added)
	}
	out = vm2.run("", "sync", "--server")
	if !strings.Contains(out, "acme/store ESEC_PRIVATE_KEY_QA") {
		t.Fatalf("vm2 did not import the new key:\n%s", out)
	}
	out = vm2.run("", "env", "list", "--project", "acme/store")
	if !strings.Contains(out, "qa "+qaPub) {
		t.Fatalf("vm2 env list:\n%s", out)
	}

	// --- Devices list shows all four, with methods. ---
	out = laptop.run("", "devices")
	for _, want := range []string{"vm1", "vm2", "vm3b", "approval", "ssh_agent", "recovery", "first"} {
		if !strings.Contains(out, want) {
			t.Fatalf("devices list lacks %q:\n%s", want, out)
		}
	}
	vm1ID := regexp.MustCompile(`(d_[a-z0-9]+)\s+vm1\s`).FindStringSubmatch(out)[1]

	// --- Revoke VM 1: user key rotates; VM 2 picks it up, VM 1 is locked out. ---
	out = laptop.run("y\n", "devices", "revoke", vm1ID, "--yes", "--reason", "test")
	if !strings.Contains(out, "user key is now version 2") || !strings.Contains(out, "Re-created SSH-agent unlock slot") {
		t.Fatalf("revoke:\n%s", out)
	}
	out = vm2.run("", "sync", "--server")
	if !strings.Contains(out, "rotated by another device") {
		t.Fatalf("vm2 did not install the rotated key:\n%s", out)
	}
	vm1.runFail("", "sync", "--server")
	// The rotation disabled the old agent slot; the laptop re-created it with
	// the new user key because its agent still held the SSH key.
	vm4 := newMachine(t, bin, "vm4").with("SSH_AUTH_SOCK=" + sock)
	out = login(t, h, vm4, "", "--ssh-agent").wait(true)
	if !strings.Contains(out, "Added this device using ssh_agent") {
		t.Fatalf("vm4 login:\n%s", out)
	}
	// Disabling the slot stops further agent logins.
	slots := laptop.run("", "agent-unlock", "list")
	slotID := regexp.MustCompile(`(s_[a-z0-9]+)\s+\S+\s+expires \S+\s+enabled`).FindStringSubmatch(slots)
	if slotID == nil {
		t.Fatalf("no enabled slot:\n%s", slots)
	}
	laptop.run("", "agent-unlock", "disable", slotID[1])
	vm5 := newMachine(t, bin, "vm5").with("SSH_AUTH_SOCK=" + sock)
	login(t, h, vm5, "", "--ssh-agent").wait(false)

	// --- Environment rotation re-encrypts the file; another device follows. ---
	out = laptop.with().run("", "env", "rotate", "dev", "--project", "acme/store", "--dir", repo, "--yes")
	if !strings.Contains(out, "re-encrypted .env.dev") {
		t.Fatalf("env rotate:\n%s", out)
	}
	decryptsTo(t, laptop, repo)
	vm2.run("", "sync", "--server")
	decryptsTo(t, vm2, repo)

	// --- Status reports the server, device and sealed keyrings. ---
	out = vm2.run("", "status")
	for _, want := range []string{"Vault server: " + h.URL, "status active", "Account key: " + accountKey, "keyrings sealed: 1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("status lacks %q:\n%s", want, out)
		}
	}

	// --- The web UI lists projects and environments, never private keys. ---
	b := h.Browser("mscno")
	status, page, err := b.Get("/projects")
	if err != nil || status != 200 {
		t.Fatalf("projects page: %d %v", status, err)
	}
	for _, want := range []string{"acme/store", "dev", "prod", "qa", qaPub[:16]} {
		if !strings.Contains(page, want) {
			t.Fatalf("projects page lacks %q:\n%s", want, page)
		}
	}
	entries := readKeyring(t, vm2, "acme/store")
	for name, priv := range entries {
		if strings.Contains(page, priv) {
			t.Fatalf("projects page leaks the private key of %s", name)
		}
	}

	// --- Logout ends the session; the server rejects the old token. ---
	vm3.run("", "logout")
	vm3.runFail("", "sync", "--server")
}

// readKeyring decodes a machine's keyring through its own secret store.
func readKeyring(t *testing.T, m *machine, project string) map[string]string {
	t.Helper()
	path := filepath.Join(m.home, "keyrings", strings.ReplaceAll(project, "/", "_")+".keyring")
	raw, err := os.ReadFile(path) //nolint:gosec // test machine home
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ESEC_VAULT_HOME", m.home)
	t.Setenv("ESEC_SECRET_STORE", "file")
	entries, err := keyringfile.Parse(path, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("empty keyring")
	}
	return entries
}
