# v0.6.0

Security alerts by email and webhook.

- The server alerts on a new device that signed in and waits for approval,
  an approved device (or a new account), a suspended or revoked device, and
  a web sign-in from a browser the account never used.
- **Email** goes through Lettermint's sending API: set `alerts.email_from`
  and `ESEC_SERVER_LETTERMINT_TOKEN`. Each person can enter an address under
  **Alerts** on the overview; it gets alerts only after they open the
  emailed link and press Confirm (mail scanners that open links confirm
  nothing). A changed or removed address is told. `alerts.email_to` sends
  every account's alerts to the operator as well.
- **Webhook**: `ESEC_SERVER_ALERT_WEBHOOK_URL` gets every alert as JSON with
  a Slack-ready `text`, signed with HMAC-SHA256 when
  `ESEC_SERVER_ALERT_WEBHOOK_SECRET` is set (`X-Esec-Vault-Signature`).
- Alerts are queued in the database with the event, so none are lost, and
  are retried for about 11 hours. Email retries reuse an idempotency key.
  Delivery errors never contain the webhook URL or the token.
- The Admin page shows whether each channel is on, the alerts sent, waiting
  and failed in the last 7 days, and the last error.
  `esec-vault-server -test-alert` sends a test alert to the operator's
  channels.
- The database gains an `alert_outbox` table and four `users` columns. Both
  are additive: v0.5.0 still opens the database after a rollback.

# v0.5.0

Web pages for people and for the operator. They still read only metadata:
nothing on them can decrypt anything.

- **Overview** (`/account`) opens with what needs attention, each with the
  command that fixes it: a device waiting for approval (first, since it may
  be a sign-in someone else started), a suspended device to revoke, a device
  unseen for 90 days, an unlock slot about to expire, an account only one
  device can open, an account not yet created. Tiles summarize devices, the
  vault, projects and the last activity. New sections list signed-in
  browsers, with sign-out for one or all other browsers, and the recent
  activity.
- **Device pages** (`/devices/{id}`) show a device's fingerprint, how it was
  added, where it signed in from, its live sessions with when each ends, and
  its activity. A device that was never approved, including one suspended
  while it waited, never shows its words on the web, and is not sent to be
  revoked: it never had access.
- **Activity** (`/activity`) lists the audit log in plain words, with device
  names, filters (sign-ins, devices, vault and keys, slots, or one device)
  and paging.
- **Vault** (`/vault`) lists the stored versions with size, hash and the
  device that pushed each.
- **Projects** has a search, including by public key, to find which project
  and environment an encrypted file belongs to.
- **Admin** (`/admin`), for the new `access.admin_github_ids`
  (`ESEC_SERVER_ADMIN_GITHUB_IDS`): the server's version and settings, totals,
  every allowed GitHub id with its state, and server-wide security events,
  plus a page per account. Read-only, and a 404 for everyone else. It never
  shows keys, fingerprint words or account creation tokens. The design
  document's threat table covers a taken-over admin GitHub account.
- A small first-party script adds copy buttons for commands and keys,
  confirmations before suspending or disabling, times in the viewer's time
  zone, table filters, and code formatting on the code page. The CSP allows
  only this script; every page works without it.
- Session counts now leave out sessions that went idle past
  `sessions.idle`.
- After GitHub sign-in, the browser returns to the page it asked for
  (activity, vault, a device page, admin) instead of always the overview.
- The database gains two columns for the browser list (`user_agent`, `ip` in
  `web_sessions`). They are added on start and have defaults, so v0.4.x
  servers can still open the database after a rollback.

# v0.4.4

- Build with esec v0.10.1, which adds `esec export` (the decrypted
  variables as `NAME=value` lines, without the public key) and keeps the
  public key out of `esec run`.
- Update dependencies (`golang.org/x/crypto` v0.58.0, `x/sys` v0.49.0,
  `x/term` v0.47.0). `modernc.org/libc` stays at v1.77.1, the version
  `modernc.org/sqlite` v1.60.1 requires.
- Update GitHub Actions (checkout v7, setup-go v7, cosign-installer v4,
  goreleaser-action v7.3.0, attest-build-provenance v4.2.2) and pin
  golangci-lint v2.15.0 in CI and `mise.toml`.

# v0.4.3

- Fix every web form failing with "The form expired" in real browsers. The
  pages used `Referrer-Policy: no-referrer`, under which browsers send
  `Origin: null` with same-origin form posts, and the CSRF origin check
  refused them. Pages now use `same-origin`, which still sends no referrer
  to other sites. The test browser now sends `Origin` the way browsers do.

# v0.4.2

Security fixes from an independent review.

- `login --recover` and `login --ssh-agent` now always require the phrase or
  SSH key, even when the server says the device is already trusted. Before,
  a malicious server could skip that check and reduce it to the account-key
  prompt. A machine that holds an identity also refuses an account made with
  a different recovery phrase on this path.
- Requests now declare their body hash in a signed header, and the server
  checks the signature before reading the body. A copied session token could
  otherwise make the server buffer many 16 MiB uploads. Bodies held in memory
  are also capped per account and in total. Devices waiting for approval use
  separate pools, capped per device, and may send only small requests. Clients before v0.4.2
  can still read, but must upgrade to write.
- `client_ip_header` now reads every line of the header, so a proxy that adds
  its own line cannot be bypassed by a client-sent one.
- A pending device learns only whether the account exists, not its chain
  length, from either `/v1/me` or commit errors. Commits with null links are rejected cleanly.

# v0.4.1

- While the server is closed to new devices (`new_devices = "closed"`), no
  new device is created for any account, including through a registration
  that reuses another account's trusted device key.

# v0.4.0

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
- Creating an account needs a per-user token derived from the server's
  bootstrap secret (`ESEC_SERVER_BOOTSTRAP_TOKEN`; print one with
  `esec-vault-server -bootstrap-token-for <id>`; the CLI asks for it or reads
  `ESEC_VAULT_BOOTSTRAP_TOKEN`), so a taken-over GitHub account cannot create
  the vault account first.
- `devices approve` requires typing the new device's fingerprint words, which
  are shown only on the new device.
- Devices waiting for approval see nothing of the account until approved or
  until they prove the recovery phrase or an SSH key.
- Device codes are always typed; links never carry them.
- `new_devices = "closed"` (`ESEC_SERVER_NEW_DEVICES`) is an emergency switch
  that refuses brand-new devices and browsers during an attack.
- Trusted devices and browsers that signed in before bypass the server-wide
  sign-in caps, so a flood only delays new ones.

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
