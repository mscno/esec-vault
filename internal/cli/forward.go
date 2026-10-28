package cli

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/runcmd"
)

// ForwardCmd opens an SSH session whose machine can ask this one for
// guarded keys, the way ssh -A forwards an SSH agent. Each read shows a
// dialog here, naming the machine, and waits for a touch of the security
// key plugged in here. The keys never leave this machine; only the values
// of the one run go back, and only for guarded environments.
type ForwardCmd struct {
	Host string   `arg:"" help:"Where to connect, as for ssh: user@host"`
	SSH  []string `name:"ssh-option" short:"o" help:"Extra ssh -o options, such as Port=2222"`
}

// Run implements forward.
func (c *ForwardCmd) Run(_ *cliCtx) error {
	if strings.HasPrefix(c.Host, "-") {
		return errors.New("the host comes first; pass ssh options with -o")
	}
	local := paths.ForwardSocket()
	if info, err := os.Stat(local); err != nil || info.Mode()&os.ModeSocket == 0 {
		return errors.New("the background service is not serving forwarded reads: esec vault daemon install --start (or daemon upgrade)")
	}
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		return err
	}
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	remote := "/tmp/esec-vault-forward-" + hex.EncodeToString(b[:]) + ".sock"
	args := []string{ssh, "-o", "StreamLocalBindUnlink=yes", "-o", "ExitOnForwardFailure=yes", "-R", remote + ":" + local}
	for _, o := range c.SSH {
		args = append(args, "-o", o)
	}
	// The remote path holds only safe characters, so it needs no quoting.
	args = append(args, "-t", c.Host, "ESEC_VAULT_FORWARD="+remote+` exec "${SHELL:-/bin/sh}" -l`)
	fmt.Fprintf(os.Stderr, "Forwarding guarded reads from %s. There, run: esec vault run prod -- ./deploy\nEach read shows a dialog here and waits for your touch. Exit the shell to stop.\n", c.Host)
	err = runcmd.Exec(args, os.Environ())
	var ee *runcmd.ExitError
	if errors.As(err, &ee) {
		return &forwardedExitError{code: ee.Code}
	}
	return err
}
