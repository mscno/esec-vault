# esec-vault

Identity, encrypted backups, project setup and key sharing for
[esec](https://github.com/mscno/esec). Every command is also available as
`esec vault …` when both executables are on PATH.

```sh
go install github.com/mscno/esec-vault/cmd/esec-vault@latest
```

## First setup

For a guided setup including remote configuration and a managed background
service, run `esec-vault setup`. It preserves an existing identity and offers
only explicit configuration/installation steps. No desktop UI is required.

```sh
esec-vault init
# Confirm your generated 24-word phrase; optionally add a recovery passphrase.

cd your/project
esec-vault project init myorg/myapp --env dev,staging,prod
esec-vault env add registry.prod
esec-vault env list
```

`project init` writes a non-secret `.esec-project`, creates independent random
keys for each environment, and scaffolds `.env.dev`, `.env.staging`, etc.
Use `--format ejson|eyaml|eyml|etoml` or `--no-template` as needed. Without an
explicit id, it infers `org/repo` from Git origin. Repeating setup preserves
existing keys and matching templates; conflicting files stop setup.

Private keys live in the global keyring store, never in generated project
templates. Files name their public keys; keys are also indexed by public key.
Nested `.esec-project` markers support monorepo subprojects.

For existing projects:

```sh
esec-vault keyring migrate --dir /path/to/repos
esec-vault keyring list
esec-vault doctor --dir /path/to/repos
# Add --delete-local to migrate only when you want verified local copies removed.
```

Add a project marker before importing a repo without one. Import scope is
explicit: backups include global project keyrings and `default.keyring`; keys
existing only in repositories, environment variables, SSH stores or other tools
must first be imported. This is an esec key manager, not a general SSH-key scanner.

## Remote configuration: file + wizard

`remote add` asks for a destination and writes `~/.config/esec/remote.toml`.
Supplying `--type` makes it non-interactive: missing required flags are errors.
The wizard prints the equivalent command for repeatable bootstrapping.

```sh
esec-vault remote add

# Or use explicit flags. Configure rclone credentials separately first.
esec-vault remote add r2 --type rclone --rclone-remote r2-account \
  --bucket esec-vault --prefix personal/v2 --set-default
esec-vault remote test r2
esec-vault backup --verify --push
```

Use a dedicated private bucket, with versioning/retention where your provider
supports it. Objects are encrypted locally before upload. The CLI does not
provision buckets or change cloud permissions. Rclone supports R2, S3, B2 and
many other destinations; esec-vault needs no provider SDK.

```toml
default = "r2"

[policy]
push = "on-change"     # or "manual"
debounce = "15m"       # maximum delay from first pending change; 0s = immediate
interval = "1m"        # worker scans for changes and retries offline uploads
keep = 30             # applied only by explicit prune commands/flags

[remotes.r2]
type = "rclone"
rclone_remote = "r2-account"
bucket = "esec-vault"
prefix = "personal/v2"
description = "Personal recovery backups"
```

Selection: explicit remote argument / `backup --remote` → `ESEC_VAULT_REMOTE`
→ config default. Settings are global, outside project repositories.

```sh
esec-vault remote list
esec-vault remote set-default r2
esec-vault remote remove r2             # configuration only
esec-vault remote test r2               # random PUT → GET → LIST → DELETE probe
esec-vault remote push r2               # snapshots live keys before uploading
esec-vault remote pull r2 --out backup.esec
esec-vault remote prune r2 --keep 30     # explicitly delete older generations
esec-vault status --json
```

**Credentials stay with the transport.** Rclone reads its own credential config;
restic uses its normal environment/credential chain. Remote TOML rejects inline
credential-named fields and unknown settings. Do not put credentials in adapter
arguments or repository URLs. Keep transport access independently recoverable:
cloud login or restic repository passwords cannot exist only inside the vault
they are needed to download.

### Other backends

```sh
esec-vault remote add usb --type file --dir /Volumes/Backup/esec --prefix personal

# Initialize the restic repository yourself first; password stays external.
export RESTIC_PASSWORD_FILE=/path/to/restic-password
esec-vault remote add archive --type restic --repository /path/to/restic-repo
```

The file backend is also suitable for a synced folder. Only encrypted snapshots
are placed there: do not sync the entire live vault home, which contains
plaintext working keyrings.

Restic stores one tagged snapshot per object. Get uses `dump`; delete uses
`forget`. Run restic's own `prune` separately to reclaim repository space.

For custom transports:

```toml
[remotes.custom]
type = "exec"
command = "/usr/local/bin/my-vault-adapter"
args = ["--profile", "personal"]
prefix = "personal/v2"
```

No shell is used. The adapter receives fixed arguments followed by
`<operation> <namespaced-key>`:

| Operation | Contract |
|---|---|
| `put` | Read encrypted bytes from stdin; store at key |
| `get` | Write exact encrypted bytes to stdout |
| `list` | Write a JSON array of full namespaced keys matching the prefix |
| `delete` | Delete exactly the named object |

Exit 44 means object not found; other nonzero codes mean failure. Credentials
belong in the adapter's own credential mechanism. All four operations are
required, so verification, recovery and retention work with every backend.

## Automatic backups

Successful key-mutating CLI commands create a local encrypted snapshot when an
identity is configured. Unchanged content reuses the exact snapshot; changes
create a new immutable generation. Identity changes, default keyrings and nested
project keyrings are included. Policy, trust pins and remote configuration are
also included inside the encryption; sockets, audit logs and transport secrets
are excluded.

```sh
esec-vault daemon install --start
esec-vault daemon status
esec-vault daemon logs
```

The OS owns the process: a macOS LaunchAgent or Linux systemd user service starts
at login and restarts after a crash. Installation copies the current executable
to a stable, private path and records an ownership manifest. Re-run installation
after upgrading the CLI to update that copy. No root service or terminal session
is needed. `daemon run` and `remote watch` remain foreground debugging tools.

The daemon starts **locked**. Its broker session is independent of process lifetime:

```sh
esec-vault unlock --ttl 4h
esec-vault lock
```

Expiration discards the broker key cache; snapshots and uploads continue. Backup
operations use the OS keyring transiently and do not unlock or extend the broker
session. Locking does not encrypt the existing plaintext working keyring files.
The user's OS keyring must be available to the service. Unavailable keyring or
network access leaves work pending for retry.

Two local sockets keep interfaces distinct: `run/control.sock` accepts owner-only
administration, while `run/agent.sock` serves policy-controlled secret requests.
The broker socket cannot approve requests or control the daemon. Unix peer
credentials authenticate the caller; this is not isolation between arbitrary
processes running under the same unrestricted OS account.

CLI writes persist first, then notify the control socket. Filesystem notifications
also catch external edits and atomic file replacements. The worker coalesces
notifications and scans periodically/startup to recover missed events. It
serializes uploads; normal backups wait for verification.
Explicit asynchronous uploads return inspectable job ids:

```sh
esec-vault backup --push --async
esec-vault daemon job JOB_ID
esec-vault daemon reload              # reload broker policy
```

Job history is bounded and in-memory; durable snapshot/pending/upload records
survive daemon restarts. Manual backup and recovery still work without the
daemon. `remote watch --once` remains available for external schedulers.

Installation captures only transport paths/profile references and PATH, including
`RCLONE_CONFIG`, `RESTIC_PASSWORD_FILE`, `AWS_PROFILE`, and the keyring directory.
Credential values are never copied into the manifest or service definition.
Configure those references in the shell before installation.

### Stop, disable, uninstall and purge

```sh
esec-vault daemon stop                # stop now; preserve login startup
esec-vault daemon disable             # stop and disable automatic startup
esec-vault daemon start               # enable/start the installed service
esec-vault daemon restart             # restart locked
esec-vault daemon uninstall           # remove service, copied binary, sockets, logs
esec-vault uninstall --purge --dry-run # preview destructive local cleanup
esec-vault uninstall --purge          # confirm and delete local vault data/identity
```

Uninstall first disables restart, waits for the OS to confirm process exit,
unregisters the service, then removes only manifest-owned artifacts. It works
when the daemon is stopped/broken and is repeatable. A failed stop prevents
artifact deletion. `daemon uninstall` preserves keys, snapshots and settings.

Purge explicitly previews and removes known local keyrings, snapshots, settings,
coordination locks and both `esec-vault` OS-keyring identity entries. It preserves
unknown files and rejects changed purge previews. Stop foreground agents before
purging, and do not run concurrent key-management commands during destruction.
`--yes` is available for scripted, explicitly requested purges. External CLI
installations, rclone/restic credentials and remote backups are not deleted;
systemd journal history remains subject to OS retention.

Uploads are read back and SHA-256 compared before recording success. Offline
failures preserve local snapshots and pending state. `status` reports stale local
snapshots and last uploaded generations. Explicit `backup --push` bypasses the
debounce. Local history is kept under `snapshots/`; remote pruning is opt-in.

Use one namespace per personal vault. This is backup, not automatic multi-device
merge: a second device should explicitly restore before adding keys. Generation
numbers and local receipts detect ordinary staleness; they do not prove freshness
against a malicious server on a completely fresh device.

## Recovery

**A new machine needs one backup file, its recovery phrase and the optional
passphrase used for that generation. It does not need `identity.esec` or the old
OS keychain.**

```sh
# Configure transport access independently, then:
esec-vault remote pull r2 --out backup.esec
esec-vault recover --file backup.esec
esec-vault backup --verify
```

`recover` prompts without echoing the phrase/passphrase. It opens the recovery
copy, reconstructs the identity, then restores keyrings. Restore conflicts are
checked before keys are written. `restore --dry-run` lists projects, `--force`
replaces conflicts, and `--settings` explicitly restores backed-up policy, trust
pins and remote config. Downloads never overwrite the active vault implicitly.

Cloud backups and local snapshots are encrypted. The working `keyrings/*.keyring`
files are still plaintext with mode 0600 for compatibility with core esec.
The broker can load ciphertext directly using `agent --from-vault`.

### Encryption and identity

```
24-word BIP39 phrase [+ optional passphrase]
  → BIP39 seed → Argon2id → HKDF-SHA256 "esec-master-v2"
  → recovery X25519 keypair
       wraps a random daily identity keypair (stored in the OS keyring)
       seals a recovery copy of each vault snapshot
```

The derivation version fixes Argon2id at 64 MiB, three passes, two lanes, and a
32-byte output. Passphrases are exact UTF-8 strings (including spaces); this is
an esec-specific derivation, not a cryptocurrency wallet derivation. The identity
header records the derivation, protection flag and public keys, with a matching
authenticated copy inside its sealed payload. Only public recovery material is
cached, allowing unattended encrypted backups without storing the phrase.

Vault format 2 is `ESECVLT | version | flags | identity-box-length (BE uint32) |
identity-sealed box | optional recovery-sealed box`. Both NaCl sealed boxes carry
the same payload: identity recovery material, keyrings, settings, generation and
timestamp. The identity copy also authenticates a hash of the recovery ciphertext,
so ordinary verification catches a damaged or removed recovery copy; recovery
cross-checks both payloads before installing the identity. Sealed boxes provide
ciphertext integrity/confidentiality, not sender
authentication. The internal digest is a consistency check, not an independent
signature. Cold recovery selects the recovery box directly.

```sh
esec-vault identity passphrase          # re-wrap same identity, then re-backup
esec-vault identity passphrase --remove
esec-vault identity rotate              # new daily identity; teammates must re-share
```

Changing the passphrase preserves project keys and the identity public key.
Older backup generations still require their old phrase/passphrase for cold
recovery. Rotation does not retroactively revoke copies of keys or secrets that
someone already obtained.

### Upgrading existing installations

Version 1 vaults are not read by normal backup/restore commands. The one-shot
`identity migrate` command reads the old wrapped identity, preserves it, re-wraps
the same daily identity using the new derivation, archives the old local vault,
and creates a verified format-2 backup from current keyrings. Preserve old
backups and their matching wrapped identities until recovery has been verified.
Migration is explicit; installing the binary does not alter live keys.

## Broker and team sharing

```sh
esec-vault agent --from-vault --ttl 4h
esec-vault run dev -- npm run dev
esec-vault approve REQUEST_ID
esec-vault agent stop
```

The broker uses peer credentials, deny-by-default TOML policy and audit logs.
It returns decrypted secret values, not project private keys. Existing sharing
commands remain available: `members prove`, `members verify`, `members trust`,
`share --to alice --env dev` and `sync`. Member proofs use GitHub-registered SSH
keys with local trust pins; sharing writes encrypted files for you to commit.

## Layout

```
~/.config/esec/                 # XDG_CONFIG_HOME/esec or ESEC_VAULT_HOME
  identity.esec                 # wrapped daily identity + recovery public data
  keyrings/*.keyring            # working project keys (0600); ESEC_KEYRING_DIR override
  vault.esec                    # current self-contained encrypted snapshot
  snapshots/*.esec              # local encrypted generation history
  remote.toml                   # declarative destinations and upload policy
  remote-state.json             # last verified upload per destination
  push-dirty.json               # first pending-change timestamp
  policy.toml, trusted.toml     # broker policy and member pins
  daemon-install.json           # exact ownership manifest for uninstall
  daemon/esec-vault             # stable managed executable copy
  daemon/daemon.log             # launchd service logs (Linux uses user journal)
  run/control.sock             # owner-only daemon control
  run/agent.sock               # policy-controlled broker endpoint
  agent.pid, audit.log          # legacy foreground agent / broker audit
```

Writers use private atomic file replacements and kernel-managed cross-process
locks. The kernel releases locks on process exit/crash; reusable `.mutation-lock`
files persist with vault data and are removed by purge. Do not unlink lock files
while writers are running.
