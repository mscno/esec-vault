// Package runcmd implements `esec-vault run` and `esec-vault decrypt`:
// decrypt secrets via the broker, then run a command with them injected as
// environment variables, or print them. Key material never enters the
// client process — only the decrypted values cross the socket.
package runcmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mscno/esec/pkg/fileutils"
	"github.com/mscno/esec/pkg/projectfile"
	coreseal "github.com/mscno/esec/pkg/seal"
	"golang.org/x/term"

	"github.com/mscno/esec-vault/internal/broker"
)

// ExitError requests process termination with the child's exit code.
type ExitError struct{ Code int }

// Error implements error.
func (e *ExitError) Error() string { return fmt.Sprintf("exit status %d", e.Code) }

// resolveSecretsFile finds the encrypted secrets file for env in dir, trying
// each known format. An explicit file argument wins.
func resolveSecretsFile(dir, fileOrEnv, format string) (path string, fileFormat string, err error) {
	if fileOrEnv == "" {
		return "", "", fmt.Errorf("no environment or file given")
	}
	p, f, err := fileutils.Resolve(dir, fileOrEnv, format)
	if err != nil {
		return "", "", err
	}
	abs, err := filepath.Abs(p)
	return abs, string(f), err
}

// Options are the optional parts of Run.
type Options struct {
	// Mask replaces the secrets' values in the command's output.
	Mask bool
	// Session labels the request in the audit log and the dialog.
	Session string
	// Forwarded sends the file itself, to a broker on another machine.
	Forwarded bool
	// Host names this machine to a forwarded broker.
	Host string
}

// Fetch resolves the project from esec.toml and returns env's secrets,
// decrypted by the broker. Reading a guarded environment waits for the
// person's touch, which Fetch says on a terminal: otherwise the wait looks
// like a hang, and a touch of a YubiKey that nothing waits for types its
// one-time password into the terminal instead.
func Fetch(client *broker.Client, env, format string, opts Options) (map[string]string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	project, marker, err := projectfile.FindProjectFile(cwd)
	if err != nil {
		return nil, fmt.Errorf("no esec.toml found (needed to identify the project): %w", err)
	}
	secretPath, fileFormat, err := resolveSecretsFile(cwd, env, format)
	if err != nil {
		return nil, err
	}
	req := &broker.Request{Op: broker.OpGetSecrets, Project: project, Env: env, Path: secretPath, Format: fileFormat, Session: opts.Session}
	if opts.Forwarded {
		if req.Content, err = os.ReadFile(secretPath); err != nil { //nolint:gosec // the secrets file this command resolved
			return nil, err
		}
		req.Host = opts.Host
		// The key sealed in the repository: the other machine opens it
		// with a touch there, and the key never comes here.
		if req.Seal, err = coreseal.Read(filepath.Dir(marker), env); err != nil {
			return nil, err
		}
	}
	if guarded(cwd, env) && term.IsTerminal(int(os.Stderr.Fd())) {
		fmt.Fprintf(os.Stderr, "esec: %s is guarded: allow the read if a dialog asks, then touch your security key when it blinks\n", env)
	}

	// Approval may take a while; allow the server's approval window plus slack.
	client.Timeout = 6 * time.Minute
	secrets, err := client.GetSecretsRequest(req)
	if err != nil {
		return nil, err
	}
	if len(secrets) == 0 {
		return nil, fmt.Errorf("broker returned no secrets for %s env %q", project, env)
	}
	return secrets, nil
}

// guarded reports whether esec.toml above dir guards env.
func guarded(dir, env string) bool {
	pf, _, err := projectfile.Find(dir)
	if err != nil || pf == nil {
		return false
	}
	e, ok := pf.Env[env]
	return ok && e.GuardLevel() != projectfile.GuardNone
}

// Print writes secrets to w: key's value alone, or else KEY=value lines in
// key order, a value spanning lines quoted so each line holds one secret.
// asJSON writes a JSON object instead (of key alone, when given).
func Print(w io.Writer, secrets map[string]string, key string, asJSON bool) error {
	if key != "" {
		v, ok := secrets[key]
		if !ok {
			return fmt.Errorf("no secret named %s in this environment", key)
		}
		secrets = map[string]string{key: v}
	}
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(secrets)
	}
	if key != "" {
		_, err := fmt.Fprintln(w, secrets[key])
		return err
	}
	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := secrets[k]
		if strings.ContainsAny(v, "\r\n") {
			v = strconv.Quote(v)
		}
		if _, err := fmt.Fprintf(w, "%s=%s\n", k, v); err != nil {
			return err
		}
	}
	return nil
}

// Run resolves the project from esec.toml, fetches decrypted secrets from
// the broker, and runs command with them in the environment.
func Run(client *broker.Client, env, format string, command []string, opts Options) error {
	if len(command) == 0 {
		return errors.New("no command specified to run")
	}
	secrets, err := Fetch(client, env, format, opts)
	if err != nil {
		return err
	}

	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = os.Environ()
	for k, v := range secrets {
		// Never drop a secret silently: the child would run successfully
		// without the variable it was promised.
		if strings.ContainsAny(k, "=;\n") || k == "" {
			return fmt.Errorf("cannot inject secret with unsupported name %q", k)
		}
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var masks []*Masker
	if opts.Mask {
		values := make([]string, 0, len(secrets))
		for _, v := range secrets {
			values = append(values, v)
		}
		out, errOut := NewMasker(os.Stdout, values), NewMasker(os.Stderr, values)
		masks = append(masks, out, errOut)
		cmd.Stdout, cmd.Stderr = out, errOut
	}
	// Best-effort scrub of our own copy once spawned.
	defer func() {
		for k := range secrets {
			secrets[k] = ""
		}
	}()

	err = wait(cmd)
	for _, m := range masks {
		_ = m.Flush()
	}
	return err
}

// Exec runs command with env and the terminal, forwarding signals, and
// returns an *ExitError for a non-zero exit.
func Exec(command, env []string) error {
	if len(command) == 0 {
		return errors.New("no command given")
	}
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = env
	return wait(cmd)
}

func wait(cmd *exec.Cmd) error {
	cmd.Stdin = os.Stdin
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	if cmd.Stderr == nil {
		cmd.Stderr = os.Stderr
	}
	setProcAttr(cmd)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting command: %w", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case sig := <-sigChan:
		signal.Stop(sigChan)
		close(sigChan)
		return &ExitError{Code: forwardSignal(cmd, sig)}
	case err := <-done:
		signal.Stop(sigChan)
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				return &ExitError{Code: exitErr.ExitCode()}
			}
			return fmt.Errorf("running command: %w", err)
		}
		return nil
	}
}
