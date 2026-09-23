// Package runcmd implements `esec-vault run`: decrypt secrets via the broker
// and run a command with them injected as environment variables. Key material
// never enters the client process — only the decrypted values cross the socket.
package runcmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/mscno/esec/pkg/fileutils"
	"github.com/mscno/esec/pkg/projectfile"

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
	// Explicit path containing a separator or a leading format prefix.
	if strings.ContainsAny(fileOrEnv, `/\`) || strings.HasPrefix(fileOrEnv, ".") {
		f, ferr := fileutils.ParseFormat(fileOrEnv)
		if ferr != nil {
			return "", "", ferr
		}
		abs, aerr := filepath.Abs(fileOrEnv)
		return abs, string(f), aerr
	}
	env := fileOrEnv
	if format != "" {
		f, ferr := fileutils.ParseFormat(format)
		if ferr != nil {
			return "", "", ferr
		}
		name := fileutils.GenerateFilename(f, env)
		if _, serr := os.Stat(filepath.Join(dir, name)); serr != nil {
			return "", "", fmt.Errorf("secrets file %s does not exist", name)
		}
		abs, aerr := filepath.Abs(filepath.Join(dir, name))
		return abs, string(f), aerr
	}
	// Auto-detect across formats.
	for _, f := range fileutils.ValidFormats() {
		name := fileutils.GenerateFilename(f, env)
		if _, serr := os.Stat(filepath.Join(dir, name)); serr == nil {
			abs, aerr := filepath.Abs(filepath.Join(dir, name))
			return abs, string(f), aerr
		}
	}
	return "", "", fmt.Errorf("no secrets file found for environment %q in %s", env, dir)
}

// Run resolves the project from .esec-project, fetches decrypted secrets from
// the broker, and runs command with them in the environment.
func Run(client *broker.Client, env, format string, command []string) error {
	if len(command) == 0 {
		return errors.New("no command specified to run")
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	project, _, err := projectfile.FindProjectFile(cwd)
	if err != nil {
		return fmt.Errorf("no .esec-project found (needed to identify the project): %w", err)
	}
	secretPath, fileFormat, err := resolveSecretsFile(cwd, env, format)
	if err != nil {
		return err
	}

	// Approval may take a while; allow the server's approval window plus slack.
	client.Timeout = 6 * time.Minute
	secrets, err := client.GetSecrets(project, env, secretPath, fileFormat)
	if err != nil {
		return err
	}
	if len(secrets) == 0 {
		return fmt.Errorf("broker returned no secrets for %s env %q", project, env)
	}

	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = os.Environ()
	for k, v := range secrets {
		if strings.ContainsAny(k, "=;\n") {
			continue
		}
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	// Best-effort scrub of our own copy once spawned.
	defer func() {
		for k := range secrets {
			secrets[k] = ""
		}
	}()

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
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
