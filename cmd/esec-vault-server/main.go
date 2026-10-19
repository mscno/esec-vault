// Command esec-vault-server runs the esec vault server: GitHub sign-in, device
// approval, and storage for encrypted vaults and signed device chains.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/mscno/esec-vault/internal/server"
)

var version string

func main() {
	configPath := flag.String("config", os.Getenv("ESEC_SERVER_CONFIG"), "path to the server TOML config")
	showVersion := flag.Bool("version", false, "print the version and exit")
	tokenFor := flag.Int64("bootstrap-token-for", 0, "print the account creation token for this numeric GitHub user id and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(buildVersion())
		return
	}
	if *tokenFor > 0 {
		secret := os.Getenv("ESEC_SERVER_BOOTSTRAP_TOKEN")
		if len(secret) < 16 {
			fmt.Fprintln(os.Stderr, "ESEC_SERVER_BOOTSTRAP_TOKEN must be set (16+ characters)")
			os.Exit(1)
		}
		fmt.Println(server.UserBootstrapToken(secret, *tokenFor))
		return
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(*configPath, log); err != nil {
		log.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run(configPath string, log *slog.Logger) error {
	cfg, err := server.LoadConfig(configPath)
	if err != nil {
		return err
	}
	db, err := server.OpenDB(cfg.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()
	srv, err := server.New(cfg, db, log, server.WithVersion(buildVersion()))
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("starting", "version", buildVersion(), "allowed_users", len(cfg.Access.AllowedGitHubIDs))
	return srv.Run(ctx)
}

func buildVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "dev"
}
