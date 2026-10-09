package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/daemon"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/remote"
	"github.com/mscno/esec-vault/internal/storage"
)

// RemoteCmd configures and operates backup destinations.
type RemoteCmd struct {
	Add        RemoteAddCmd        `cmd:"" help:"Configure a destination with flags or an interactive wizard."`
	List       RemoteListCmd       `cmd:"" help:"List destinations and last verified uploads."`
	SetDefault RemoteSetDefaultCmd `cmd:"" help:"Choose the default destination."`
	Remove     RemoteRemoveCmd     `cmd:"" help:"Remove a destination's configuration."`
	Test       RemoteTestCmd       `cmd:"" help:"Test put/get/list/delete with a random probe."`
	Push       RemotePushCmd       `cmd:"" help:"Snapshot live keys and upload now."`
	Pull       RemotePullCmd       `cmd:"" help:"Download the newest backup for recovery or inspection."`
	Prune      RemotePruneCmd      `cmd:"" help:"Delete older remote generations."`
	Watch      RemoteWatchCmd      `cmd:"" help:"Continuously snapshot and retry pending uploads."`
}

// RemoteAddCmd writes declarative destination configuration.
type RemoteAddCmd struct {
	Name         string   `arg:"" optional:"" help:"Destination name"`
	Type         string   `help:"file, rclone, restic or exec"`
	Dir          string   `type:"path" help:"File backend directory"`
	RcloneRemote string   `help:"Remote name in rclone.conf"`
	Bucket       string   `help:"Rclone bucket"`
	Path         string   `help:"Path inside bucket"`
	Repository   string   `help:"Restic repository (credentials from environment)"`
	Command      string   `help:"Exec adapter executable (no shell)"`
	Args         []string `name:"exec-arg" help:"Fixed arguments for the exec adapter"`
	Description  string   `help:"Human description"`
	Prefix       string   `default:"v2" help:"Destination namespace"`
	SetDefault   bool     `help:"Make this the default"`
}

// Run writes config; specifying --type makes it strictly non-interactive.
func (c *RemoteAddCmd) Run(ctx *cliCtx) error {
	cfg, err := remote.Load()
	if err != nil {
		return err
	}
	if c.Type == "" {
		if err := c.wizard(); err != nil {
			return err
		}
	}
	if err := validateRemoteName(c.Name); err != nil {
		return err
	}
	if _, ok := cfg.Remotes[c.Name]; ok {
		return fmt.Errorf("remote %q exists; edit %s or remove it first", c.Name, remote.ConfigPath())
	}
	if c.Dir != "" {
		c.Dir, err = filepath.Abs(c.Dir)
		if err != nil {
			return err
		}
	}
	e := remote.Entry{Type: c.Type, Dir: c.Dir, RcloneRemote: c.RcloneRemote, Bucket: c.Bucket, Path: c.Path, Repository: c.Repository, Command: c.Command, Args: c.Args, Description: c.Description, Prefix: c.Prefix}
	if err := e.Validate(); err != nil {
		return err
	}
	cfg.Remotes[c.Name] = e
	if c.SetDefault || cfg.Default == "" {
		cfg.Default = c.Name
	}
	if err := remote.Save(cfg); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Saved", remote.ConfigPath())
	args := []string{"esec-vault", "remote", "add", c.Name, "--type", c.Type, "--prefix", c.Prefix}
	for _, pair := range [][2]string{{"--dir", c.Dir}, {"--rclone-remote", c.RcloneRemote}, {"--bucket", c.Bucket}, {"--path", c.Path}, {"--repository", c.Repository}, {"--command", c.Command}, {"--description", c.Description}} {
		if pair[1] != "" {
			args = append(args, pair[:]...)
		}
	}
	for _, arg := range c.Args {
		args = append(args, "--exec-arg", arg)
	}
	if cfg.Default == c.Name {
		args = append(args, "--set-default")
	}
	for i, arg := range args {
		args[i] = shellQuote(arg)
	}
	fmt.Fprintln(os.Stderr, "Equivalent command:", strings.Join(args, " "))
	fmt.Fprintf(os.Stderr, "Next: esec-vault remote test %s\n", c.Name)
	return nil
}

func (c *RemoteAddCmd) wizard() error {
	var err error
	if c.Name == "" {
		c.Name, err = promptLine("Destination name: ")
		if err != nil {
			return err
		}
	}
	c.Type, err = promptLine("Type [rclone]: ")
	if err != nil {
		return err
	}
	if c.Type == "" {
		c.Type = "rclone"
	}
	var fields []struct {
		label string
		value *string
	}
	switch c.Type {
	case "file":
		fields = append(fields, struct {
			label string
			value *string
		}{"Directory: ", &c.Dir})
	case "rclone":
		fields = append(fields, struct {
			label string
			value *string
		}{"Remote name from rclone.conf: ", &c.RcloneRemote}, struct {
			label string
			value *string
		}{"Bucket: ", &c.Bucket})
	case "restic":
		fields = append(fields, struct {
			label string
			value *string
		}{"Repository: ", &c.Repository})
	case "exec":
		fields = append(fields, struct {
			label string
			value *string
		}{"Adapter executable: ", &c.Command})
	default:
		return fmt.Errorf("unknown remote type %q", c.Type)
	}
	for _, f := range fields {
		if *f.value == "" {
			*f.value, err = promptLine(f.label)
			if err != nil {
				return err
			}
		}
	}
	if c.Type == "file" {
		c.Dir, err = filepath.Abs(c.Dir)
	}
	return err
}

// RemoteListCmd prints destination metadata.
type RemoteListCmd struct{}

// Run lists destinations and verified state.
func (c *RemoteListCmd) Run(ctx *cliCtx) error {
	cfg, err := remote.Load()
	if err != nil {
		return err
	}
	state, err := remote.LoadState()
	if err != nil {
		return err
	}
	for _, name := range cfg.Names() {
		marker := " "
		if name == cfg.Default {
			marker = "*"
		}
		s := state.Remote[name]
		last := "never pushed"
		if !s.LastPush.IsZero() {
			last = fmt.Sprintf("generation %d, %s ago", s.Generation, humanAge(time.Since(s.LastPush)))
		}
		fmt.Printf("%s %s (%s): %s\n", marker, name, cfg.Remotes[name].Type, last)
	}
	return nil
}

// RemoteSetDefaultCmd selects a destination.
type RemoteSetDefaultCmd struct {
	Name string `arg:"" help:"Remote name"`
}

// Run changes the default.
func (c *RemoteSetDefaultCmd) Run(ctx *cliCtx) error {
	cfg, err := remote.Load()
	if err != nil {
		return err
	}
	if _, _, err := cfg.Resolve(c.Name); err != nil {
		return err
	}
	cfg.Default = c.Name
	return remote.Save(cfg)
}

// RemoteRemoveCmd removes configuration only.
type RemoteRemoveCmd struct {
	Name  string `arg:"" help:"Remote name"`
	Force bool   `help:"Skip confirmation"`
}

// Run removes a destination without deleting its backups.
func (c *RemoteRemoveCmd) Run(ctx *cliCtx) error {
	cfg, err := remote.Load()
	if err != nil {
		return err
	}
	if _, _, err := cfg.Resolve(c.Name); err != nil {
		return err
	}
	if !c.Force && !confirm("Remove remote "+c.Name+"?") {
		return fmt.Errorf("cancelled")
	}
	delete(cfg.Remotes, c.Name)
	if cfg.Default == c.Name {
		cfg.Default = ""
	}
	return remote.Save(cfg)
}

// RemoteTestCmd performs a real object round trip.
type RemoteTestCmd struct {
	Name string `arg:"" optional:"" help:"Remote name"`
}

// Run verifies all backend operations and cleans up its probe.
func (c *RemoteTestCmd) Run(ctx *cliCtx) error {
	cfg, err := remote.Load()
	if err != nil {
		return err
	}
	name, entry, err := cfg.Resolve(c.Name)
	if err != nil {
		return err
	}
	b, err := remote.New(entry)
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	key := "test/" + rand.Text()
	probe := []byte(rand.Text())
	if err := b.Put(cctx, key, probe); err != nil {
		return fmt.Errorf("%s write: %w", name, err)
	}
	defer b.Delete(cctx, key) //nolint:errcheck // explicit deletion below reports failures
	got, err := b.Get(cctx, key)
	if err != nil {
		return fmt.Errorf("%s read: %w", name, err)
	}
	if !bytes.Equal(got, probe) {
		return fmt.Errorf("%s read-back mismatch", name)
	}
	keys, err := b.List(cctx, "test/")
	if err != nil {
		return fmt.Errorf("%s list: %w", name, err)
	}
	found := false
	for _, k := range keys {
		if k == key {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("%s listing omitted probe", name)
	}
	if err := b.Delete(cctx, key); err != nil {
		return fmt.Errorf("%s delete: %w", name, err)
	}
	fmt.Fprintln(os.Stderr, name, "passed put/get/list/delete verification")
	return nil
}

// RemotePushCmd snapshots and uploads now.
type RemotePushCmd struct {
	Name  string `arg:"" optional:"" help:"Remote name"`
	Prune bool   `help:"Apply retention after verification"`
	Async bool   `help:"Queue in daemon and return a job id"`
}

// Run performs an immediate verified upload.
func (c *RemotePushCmd) Run(ctx *cliCtx) error {
	if resp, err := daemon.Call(context.Background(), daemon.Request{Op: "ping"}); err == nil {
		resp, err = daemon.Call(context.Background(), daemon.Request{Op: "backup", Remote: c.Name, Prune: c.Prune, Async: c.Async})
		if err != nil {
			return err
		}
		return printJSON(resp.Job)
	} else if resp != nil {
		return err
	}
	if c.Async {
		return fmt.Errorf("--async requires the daemon")
	}
	res, err := pushNow(ctx, c.Name, c.Prune)
	if err != nil {
		return err
	}
	if !ctx.Quiet {
		fmt.Fprintf(os.Stderr, "Verified generation %d at %s:%s\n", res.Generation, res.Remote, res.Key)
	}
	return nil
}

// RemotePullCmd downloads ciphertext without changing active identity or keys.
type RemotePullCmd struct {
	Name  string `arg:"" optional:"" help:"Remote name"`
	Out   string `type:"path" help:"Download path (default: vault home/download.esec)"`
	Force bool   `help:"Overwrite download path"`
}

// Run saves the download for restore or cold recovery.
func (c *RemotePullCmd) Run(ctx *cliCtx) error {
	cfg, err := remote.Load()
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	key, blob, err := remote.Latest(cctx, cfg, c.Name)
	if err != nil {
		return err
	}
	out := c.Out
	if out == "" {
		out = filepath.Join(paths.Home(), "download.esec")
	}
	if _, err := os.Lstat(out); err == nil && !c.Force {
		return fmt.Errorf("%s exists; use --force", out)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := storage.Write(out, blob); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Downloaded %s to %s\nRecover with: esec-vault recover --file %s\n", key, out, shellQuote(out))
	return nil
}

// RemotePruneCmd explicitly applies retention.
type RemotePruneCmd struct {
	Name  string `arg:"" optional:"" help:"Remote name"`
	Keep  int    `help:"Number of generations to retain"`
	Force bool   `help:"Skip confirmation"`
}

// Run prunes older objects only after checking a retained copy is readable.
func (c *RemotePruneCmd) Run(ctx *cliCtx) error {
	cfg, err := remote.Load()
	if err != nil {
		return err
	}
	keep := c.Keep
	if keep == 0 {
		keep = cfg.Policy.Retention()
	}
	if !c.Force && !confirm(fmt.Sprintf("Keep newest %d generations and remove older backups?", keep)) {
		return fmt.Errorf("cancelled")
	}
	cctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	removed, err := remote.Prune(cctx, cfg, c.Name, keep)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Removed %d older generations\n", len(removed))
	return nil
}

// RemoteWatchCmd is a foreground worker suitable for launchd or systemd.
type RemoteWatchCmd struct {
	Once bool `help:"Scan once (suitable for a scheduled job)"`
}

// Run detects direct keyring edits, snapshots changes, and retries uploads.
func (c *RemoteWatchCmd) Run(ctx *cliCtx) error {
	cfg, err := remote.Load()
	if err != nil {
		return err
	}
	interval := cfg.Policy.IntervalDuration()
	if interval <= 0 {
		return fmt.Errorf("policy.interval must be positive to watch")
	}
	cctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		id, err := identity.Load(ctx.Keyring)
		if err == nil {
			_, err = remote.BuildSnapshot(id, keystore.New())
			if err == nil {
				_, err = remote.MaybePush(cctx, id, keystore.New(), "")
			}
		}
		if c.Once {
			return err
		}
		if err != nil {
			ctx.Logger.Warn("backup pending; retrying", "error", err)
		}
		select {
		case <-cctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func validateRemoteName(name string) error {
	if name == "" {
		return fmt.Errorf("destination name required")
	}
	for _, r := range name {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-", r) {
			return fmt.Errorf("invalid destination name %q", name)
		}
	}
	return nil
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
