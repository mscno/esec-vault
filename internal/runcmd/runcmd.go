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
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/fileutils"
	"github.com/mscno/esec/pkg/projectfile"
	coreseal "github.com/mscno/esec/pkg/seal"

	"github.com/mscno/esec-vault/internal/broker"
	"github.com/mscno/esec-vault/internal/seal"
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
	target, err := esec.ResolveRead(".", env, format)
	if err != nil {
		return nil, err
	}
	if !opts.Forwarded {
		data, err := esec.ReadDocument(target, esec.ReadOptions{Socket: client.SockPath, Session: opts.Session})
		if err != nil {
			return nil, err
		}
		return esec.EnvVars(data, target.Format)
	}
	req := &broker.Request{Op: broker.OpGetSecrets, Project: target.Project, Env: target.Environment, Path: target.Path, Format: string(target.Format), Session: opts.Session, Content: target.Content, Host: opts.Host}
	if target.KeyEnvironment != target.Environment {
		return nil, fmt.Errorf("forward the exact environment holding this sealed key: %s", target.KeyEnvironment)
	}
	req.Seal, err = coreseal.Read(target.Root, target.KeyEnvironment)
	if err != nil {
		return nil, err
	}

	// Approval may take a while; allow the server's approval window plus slack.
	client.Timeout = 6 * time.Minute
	secrets, err := client.GetSecretsRequest(req)
	if err != nil {
		return nil, err
	}
	if len(secrets) == 0 {
		return nil, fmt.Errorf("broker returned no secrets for %s env %q", target.Project, env)
	}
	return secrets, nil
}

// guarded reports whether env is guarded in the project above dir: by its
// esec.toml, or by its seal record (.esec/seals.toml), as the background
// service decides.
func guarded(dir, env string) bool {
	pf, path, err := projectfile.Find(dir)
	if err != nil || pf == nil {
		return false
	}
	if e, ok := pf.Env[env]; ok && e.GuardLevel() != projectfile.GuardNone {
		return true
	}
	recs, err := seal.LoadRecords(filepath.Dir(path))
	if err != nil {
		return false
	}
	rec := recs[env]
	return rec != nil && seal.Guarded(rec.Guard)
}

// checkName refuses a secret name that cannot be a variable or a line of
// its own: one that is empty, holds '=' or ';', or holds a character that
// is not printable (a newline would start a forged line).
func checkName(k string) error {
	if k == "" || strings.ContainsAny(k, "=;") || strings.ContainsFunc(k, func(r rune) bool { return !unicode.IsPrint(r) }) || !utf8.ValidString(k) {
		return fmt.Errorf("unsupported secret name %q", k)
	}
	return nil
}

// Unsafe reports whether v, printed as it is on a terminal, could do more
// than show text: it holds a control character other than a newline or a
// tab (an escape sequence can rewrite the screen or the clipboard), an
// invisible formatting character, or bytes that are not UTF-8.
func Unsafe(v string) bool {
	return !utf8.ValidString(v) || strings.ContainsFunc(v, func(r rune) bool {
		return r != '\n' && r != '\t' && r != ' ' && !unicode.IsPrint(r)
	})
}

// Print writes secrets to w: key's value alone, or else KEY=value lines in
// key order. A value is quoted (Go syntax) when it holds anything but
// printable characters and spaces, or begins with a quote, so each line is
// one secret and no value drives the terminal. The lines are not shell
// syntax: give secrets to a command with run, never eval them. key's value
// alone is written as it is, unless terminal is set and it is Unsafe: then
// it is quoted too. asJSON writes a JSON object instead (of key alone, when
// given), with every character that is not printable escaped.
func Print(w io.Writer, secrets map[string]string, key string, asJSON, terminal bool) error {
	if key != "" {
		v, ok := secrets[key]
		if !ok {
			return fmt.Errorf("no secret named %s in this environment", key)
		}
		secrets = map[string]string{key: v}
	}
	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		if err := checkName(k); err != nil {
			return err
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if asJSON {
		data, err := json.MarshalIndent(secrets, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(w, "%s\n", escapeJSON(string(data)))
		return err
	}
	if key != "" {
		v := secrets[key]
		if terminal && Unsafe(v) {
			v = strconv.Quote(v)
		}
		_, err := fmt.Fprintln(w, v)
		return err
	}
	for _, k := range keys {
		v := secrets[k]
		if strings.HasPrefix(v, `"`) || !utf8.ValidString(v) || strings.ContainsFunc(v, func(r rune) bool { return r != ' ' && !unicode.IsPrint(r) }) {
			v = strconv.Quote(v)
		}
		if _, err := fmt.Fprintf(w, "%s=%s\n", k, v); err != nil {
			return err
		}
	}
	return nil
}

// escapeJSON escapes what encoding/json leaves as it is but a terminal may
// act on (DEL, C1 controls, invisible formatting). Outside strings, JSON
// holds only spaces, newlines and printable ASCII, so this changes strings
// only and keeps their values.
func escapeJSON(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '\n' || r == ' ' || unicode.IsPrint(r) {
			b.WriteRune(r)
			continue
		}
		if r > 0xffff {
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(&b, "\\u%04x\\u%04x", hi, lo)
			continue
		}
		fmt.Fprintf(&b, "\\u%04x", r)
	}
	return b.String()
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
		if err := checkName(k); err != nil {
			return fmt.Errorf("cannot inject secret: %w", err)
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
