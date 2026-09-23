package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mscno/esec-vault/internal/broker"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/policy"
	"github.com/mscno/esec-vault/internal/runcmd"
	"github.com/mscno/esec-vault/internal/vaultfile"
)

// AgentCmd runs or controls the broker daemon.
type AgentCmd struct {
	Start AgentStartCmd `cmd:"" default:"withargs" help:"Start the broker (holds keys in memory)."`
	Stop  AgentStopCmd  `cmd:"" help:"Stop the running broker."`
}

// AgentStartCmd starts the broker.
type AgentStartCmd struct {
	TTL       time.Duration `help:"How long the broker keeps running (e.g. 4h)" default:"4h"`
	Policy    string        `help:"Policy file" type:"path" default:""`
	FromVault bool          `help:"Load keys from the sealed vault blob instead of keyring files"`
	Sock      string        `help:"Socket path" default:"" env:"ESEC_VAULT_SOCK"`
}

// Run implements agent start.
func (c *AgentStartCmd) Run(ctx *cliCtx) error {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return fmt.Errorf("the broker requires unix sockets with peer credentials; unsupported on %s", runtime.GOOS)
	}
	if err := paths.EnsureHome(); err != nil {
		return err
	}

	// Load key material into memory.
	keys := map[string]map[string]string{}
	if c.FromVault {
		id, err := identity.Load(ctx.Keyring)
		if err != nil {
			return err
		}
		v, err := vaultfile.Read(paths.VaultFile(), &id.Public, &id.Private)
		if err != nil {
			return err
		}
		keys = v.Projects
		ctx.Logger.Info("loaded keys from vault blob", "projects", len(keys))
	} else {
		ks := keystore.New()
		projects, err := ks.List()
		if err != nil {
			return err
		}
		for _, p := range projects {
			entries, err := ks.Read(p)
			if err != nil {
				return err
			}
			keys[p] = entries
		}
		ctx.Logger.Info("loaded keyrings", "projects", len(keys), "dir", ks.Dir)
	}

	polPath := c.Policy
	if polPath == "" {
		polPath = paths.PolicyPath()
	}
	pol, err := policy.Load(polPath)
	if err != nil {
		return err
	}

	audit, err := broker.NewAuditLogger(paths.AuditPath())
	if err != nil {
		return err
	}

	sock := c.Sock
	if sock == "" {
		sock = paths.SocketPath()
	}
	srv := broker.NewServer(keys, pol, audit, ctx.Logger)

	ctxc, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		ctx.Logger.Info("shutting down broker")
		cancel()
	}()
	if c.TTL > 0 {
		time.AfterFunc(c.TTL, func() {
			ctx.Logger.Info("broker TTL expired, shutting down", "ttl", c.TTL)
			cancel()
		})
	}

	// PID file for `agent stop`.
	if err := os.WriteFile(paths.PIDFile(), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		return err
	}
	defer os.Remove(paths.PIDFile())

	fmt.Printf("esec-vault broker running (socket %s, ttl %s, %d projects)\n", sock, c.TTL, len(keys))
	return srv.Serve(ctxc, sock)
}

// AgentStopCmd stops the broker.
type AgentStopCmd struct{}

// Run implements agent stop.
func (c *AgentStopCmd) Run(ctx *cliCtx) error {
	data, err := os.ReadFile(paths.PIDFile())
	if err != nil {
		return fmt.Errorf("no broker pid file (is it running?): %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return fmt.Errorf("invalid pid file: %w", err)
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("failed to stop broker (pid %d): %w", pid, err)
	}
	fmt.Printf("Stopped broker (pid %d)\n", pid)
	return nil
}

// RunCmd injects broker-decrypted secrets into a command.
type RunCmd struct {
	Env     string   `arg:"" help:"Environment to decrypt (e.g. dev)"`
	Format  string   `help:"File format (e.g. .ejson); default: auto-detect" short:"f" env:"ESEC_FORMAT"`
	Sock    string   `help:"Broker socket path" default:"" env:"ESEC_VAULT_SOCK"`
	Command []string `arg:"" optional:"" name:"command" help:"Command to run"`
}

// Run implements run.
func (c *RunCmd) Run(ctx *cliCtx) error {
	sock := c.Sock
	if sock == "" {
		sock = paths.SocketPath()
	}
	err := runcmd.Run(broker.NewClient(sock), c.Env, c.Format, c.Command)
	var ee *runcmd.ExitError
	if errors.As(err, &ee) {
		return &exitCodeError{code: ee.Code}
	}
	return err
}

// ApproveCmd approves a pending broker request.
type ApproveCmd struct {
	ID  string `arg:"" help:"Pending request id"`
	Sock string `help:"Broker socket path" default:"" env:"ESEC_VAULT_SOCK"`
}

// Run implements approve.
func (c *ApproveCmd) Run(ctx *cliCtx) error {
	sock := c.Sock
	if sock == "" {
		sock = paths.SocketPath()
	}
	if err := broker.NewClient(sock).Approve(c.ID); err != nil {
		return err
	}
	fmt.Println("Approved", c.ID)
	return nil
}
