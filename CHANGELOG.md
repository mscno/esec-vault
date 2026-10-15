# Unreleased

Vault server and device sync. Requires esec v0.9.0 or later.

- Add `esec-vault-server`:
  - GitHub sign-in for an allowlist of numeric GitHub user ids, and a device
    authorization grant for the CLI.
  - Ciphertext-only storage for vaults, device boxes, the master-wrapped
    identity and SSH-agent unlock slots.
  - Pages for code confirmation, devices, slots, the audit log and projects.
  - Every API request is signed with the device key, so a stolen session
    token alone is useless.
- Add `login`, `logout`, `devices` (list, approve, revoke, rename, suspend),
  `agent-unlock`, `sync --server` and `index`. A new machine gets your keys
  by approval from another device, by the recovery phrase, or from a
  forwarded SSH agent.
- Add a signed, hash-linked device chain that every client verifies and pins.
  A server cannot add devices, swap keys, or roll back history unnoticed.
- Vault uploads are signed by the user key, and sync merges three ways
  against the last synced version.
- Revoking a device rotates the user key. `env rotate` replaces an environment
  key and re-encrypts its files, keeping the old key for history.
- Seal keyring files under a per-machine cache key (`keyring seal`/`unseal`;
  default on signed-in machines). Device secrets live in a shared secret
  store: the OS keychain, a TPM, a 0600 file, or the Linux kernel keyring.
- `identity.esec` becomes version 3 with an Ed25519 signing key. The upgrade
  needs no recovery phrase. Older esec-vault versions cannot read version 3
  files.
- The daemon syncs with the server, refreshes an unlocked broker, and
  notifies about pending devices and devices added by phrase or SSH agent.
- Add `deploy/` (Dockerfile, Litestream, Fly.io) and a server runbook.
- The account root is signed by a key derived from the recovery phrase, so
  recovering with the phrase cannot be fooled into a forged account. Identities
  from older versions are asked for the phrase once, when the account is
  created.
- A device joining by approval confirms 8-word account key words before
  installing anything (or checks `--account-key`). Machines that already have
  an identity refuse an account created with another recovery phrase.
- Server-supplied text is sanitized before printing. Device boxes are
  write-once. Unlock slots disabled by a revocation are re-created only after
  an explicit yes.
- The recovery passphrase cannot change while signed in to a vault server.
- Creating an account needs the server's bootstrap token
  (`ESEC_SERVER_BOOTSTRAP_TOKEN`, `login --bootstrap-token`), so a taken-over
  GitHub account cannot create the vault account first.

# v0.3.6

- Add `env show-key ENV` to print a named environment's private key after
  confirmation, resolving the nearest project marker or an explicit `--project`.
- Report a clear error when `project init` cannot infer a project because Git
  origin is missing or empty, with a hint to use `--project org/repo`.
- Print the initialized project's absolute directory and whether its ID came
  from the `--project` flag, positional argument, or Git origin.

# v0.3.5

- Never exit on failure without reporting why. `remote test`, `backup --push`,
  `daemon install/start/stop/restart` and `project init` all exited with a
  non-zero status and no output at all when an external tool failed, because the
  error path called `os.Exit` without printing the message. Tool diagnostics that
  embed "exit status" (rclone's 403 AccessDenied, launchctl's load errors) are
  now shown; only `run` stays silent, since the child already wrote its stderr.
- Preserve git's stderr in `project init` errors, so a missing `origin` remote
  explains itself instead of reporting only "exit status 128".
- Fail closed when the audit log cannot be written. A secret is no longer
  decrypted and served if the allow decision could not be recorded.
- Report a failed audit-log `Close` (for example ENOSPC on append) instead of
  returning success for an entry that never reached disk.
- Report plist XML escaping failures instead of writing a malformed unit that
  later surfaces as an opaque launchctl error.
- Reject keyring entries whose names cannot be exported as environment
  variables, rather than silently omitting the secret from the child process.
- Treat an unreadable push marker as pending instead of silently reporting that
  nothing needs uploading.
- Surface `members list` proof-read failures, `doctor` daemon-check failures and
  `daemon logs` errors rather than omitting them silently.

# v0.3.4

- Fix rclone-backed backups failing forever against object stores such as S3,
  R2 and B2. Reading a missing key with `rclone cat` succeeds and prints
  nothing there, because those stores have no directories. The rclone backend
  inferred "absent" from the exit code alone, so every first push reported
  `remote generation already exists with different content` and the daemon
  retried a conflicting generation that never existed. `Get` now probes the key
  with `lsjson` before reading, so a missing object is reported as absent.

# v0.3.3

- Fix the managed-copy comparison so `daemon upgrade` is idempotent and
  `daemon restart` stops rejecting a current daemon. The check rendered the
  unit file before capturing the environment, so it compared a PATH-less plist
  against the installed one and always reported the copy as stale.

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
