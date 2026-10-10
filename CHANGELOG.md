# v0.3.2

- Resolve the module version for `go install` builds. The hardcoded `dev`
  placeholder made released binaries report an unknown build over the control
  socket, so the daemon staleness check could never fire.
- Remove the mise `install` task, which wrote dev builds into a `PATH` directory
  and shadowed real releases. Local builds are now injected as `dev` plus the
  commit hash instead of a stale hardcoded version.

# v0.3.1

- Add `daemon upgrade` to replace the managed executable after upgrading the
  CLI. The service runs a private copy, so a new binary on `PATH` never reached
  the running daemon.
- Report the daemon's build over the control socket. `daemon status` shows
  `version`, `cli_version` and `up_to_date`, and `status`/`doctor` warn when the
  managed copy is older than the CLI.
- Refuse `daemon restart` against a stale managed copy instead of silently
  restarting the old build, and point at `daemon upgrade`.
- Make `daemon install` idempotent: an identical managed copy and unit file are
  reused without stopping a healthy daemon, so a live broker session survives.
- Update go-keyring to v0.2.8, with wincred v1.2.3 and dbus v5.2.2.
- Depend on esec v0.8.1.
- Add detailed project, environment, subfolder, teammate-sharing, and broker
  guides in simplified technical English.
- Update CI to checkout v7, setup-go v7, and golangci-lint-action v9.
- Preserve Markdown spacing when extracting release notes.

# v0.3.0

- OS-managed user daemon with launchd/systemd installation, manifest-based
  uninstall and explicit local-data/keychain purge.
- Owner-only control socket, separate broker socket, locked startup and bounded
  unlock sessions independent of backup scheduling.
- Guided setup, backup jobs, CLI change notifications and crash-released locks.

- Self-contained format-2 snapshots with identity and recovery-key encryption;
  cold recovery needs only the backup, phrase and optional passphrase.
- Versioned memory-hard identity derivation, confirmed setup, passphrase changes,
  explicit legacy migration and preserved encrypted identity backups.
- Declarative remote config and setup wizard; file, rclone, restic and exec
  transports with round-trip verification, immutable generations and explicit retention.
- Live-key snapshots, deduplicated unchanged backups, durable pending uploads,
  periodic watch/retry worker and broker integration.
- Project/environment setup, status/doctor, safe restore preflight and default/
  monorepo keyring coverage.

# v0.2.0

Monorepo support (pairs with esec v0.7.0):

- Broker key resolution uses esec's shared chain — environment suffix (dotted envs like
  `registry.production`) then the secrets file's embedded public key — so per-component
  keypairs work through the broker without naming discipline
- `keyring migrate` walks monorepos: every repo-local `.esec-keyring` is migrated, keyed by
  its nearest `.esec-project` (nested subprojects included); `.gitignore` is updated at the
  git root
- New `keyring add` command: generates a component keypair, appends the pubkey-keyed entry
  (`ESEC_PRIVATE_KEY_<pubkey>`) to the project's global keyring, and prints the public key
  for embedding in the new secrets file
- Depends on esec v0.7.0

# v0.1.0

Initial release.

- Identity: BIP39 recovery phrase -> HKDF master key -> wrapped identity keypair
  (`identity init` / `recover` / `rotate` / `show`); identity lives in the OS keyring
- Global keyring store management: `keyring migrate` moves repo-local `.esec-keyring` files
  to `~/.config/esec/keyrings/<org>_<repo>.keyring` (verified copy before optional deletion),
  `keyring list` shows projects and environments
- Backup: `backup` / `restore` / `recover` seal and open the vault blob (NaCl sealed box +
  inner SHA-256 integrity)
- Broker: `agent` daemon holds keys in memory and answers policy-checked decryption requests
  over a unix socket with peer-uid authentication (Linux/macOS), TOML policy with
  allow/ask/deny, JSON-lines audit log, TTL, `agent stop`
- `run <env> -- cmd`: inject broker-decrypted secrets into a child process; also reachable as
  `esec vault run` via esec's subcommand passthrough
- Team sharing (git-native, no server): member proofs signed with GitHub-registered SSH keys
  (`members prove` / `verify` / `trust` / `list`), TOFU fingerprint pinning, `share` writes
  committed per-member sealed blobs under `.esec/vault/`, `sync` opens them
