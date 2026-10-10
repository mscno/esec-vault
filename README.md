# esec-vault

Use esec-vault to store, share, and back up the private keys used by
[esec](https://github.com/mscno/esec). Use esec to encrypt project secrets files.

You can write every vault command as `esec vault ...` or `esec-vault ...`.
Both forms run the same program.

## Find a guide

- [Set up your personal vault](#first-setup).
- [Set up a project and its marker](#set-up-a-project).
- [Add environments and keys](#add-environments-and-keys).
- [Use keys in subfolders](#use-keys-in-subfolders).
- [Import existing project keys](#import-existing-project-keys).
- [Share keys with a teammate](#share-project-keys-with-a-teammate).
- [Run an application through the broker](#run-applications-through-the-broker).
- [Set up a remote backup](#remote-configuration-file--wizard).
- [Operate the daemon](#automatic-backups).
- [Recover your keys](#recovery).
- [Find and fix common problems](#find-and-fix-common-problems).

The examples use esec v0.8.0 or later and esec-vault v0.3.0 or later.
Replace `acme`, project names, paths, and GitHub logins with your own values.
Replace `npm run dev` with your application's start command. Set `$EDITOR` to
your editor, or replace `$EDITOR` in the examples with an editor command.

## Install both tools

```sh
GOBIN="$HOME/go/bin" go install github.com/mscno/esec/cmd/esec@latest
GOBIN="$HOME/go/bin" go install github.com/mscno/esec-vault/cmd/esec-vault@latest
export PATH="$HOME/go/bin:$PATH"

esec --version
esec-vault --version
```

The explicit `GOBIN` value gives both tools the same install location.
It also keeps the binaries outside a Go version manager's toolchain directory.

## First setup

Set up your personal identity once. Use it for all your projects.
Your personal identity opens vault backups and shares sent to you.
Project environment keys encrypt and decrypt the files in your projects.

For a new vault, run guided setup:

```sh
esec vault setup
```

Setup can create an identity, configure a remote, and install the daemon.
Write down the generated 24-word recovery phrase. Confirm the phrase when asked.
You can also set a recovery passphrase.

For an existing vault, check its state first:

```sh
esec vault status
```

If the identity uses the format from before v0.3.0, migrate it once:

```sh
esec vault identity migrate
```

Use `project init` for a new project. Do not create a new personal identity for
each project. See [upgrading existing installations](#upgrading-existing-installations)
for details about the older backup format.

## Set up a project

### Step 1: Choose a stable project ID

Use an ID such as `acme/store`. The ID selects a keyring on your computer.
It does not require a GitHub login or a matching local folder name.

Two clones with the same ID use the same global keyring on this computer.
Two different IDs use different project keyrings.

### Step 2: Create the marker, keys, and files

Run this command from your application directory:

```sh
cd ~/projects/store
esec vault project init acme/store --env dev,staging,prod --format env
```

The command creates:

```text
store/
  .esec-project
  .env.dev
  .env.staging
  .env.prod
```

The marker contains:

```dotenv
ESEC_PROJECT=acme/store
```

Commit this marker to Git. It contains no private key.
It selects the project only. It does not select an active environment, file
format, remote, or access policy.

The default global keyring path is:

```text
~/.config/esec/keyrings/acme_store.keyring
```

`project init` creates a different key pair for each environment. Each template
contains its public key. The matching private key goes into the global keyring.

You can select another directory without changing your shell directory:

```sh
esec vault project init acme/billing \
  --dir ~/projects/billing --env dev,prod --format env
```

Use `--format ejson`, `--format eyaml`, `--format eyml`, or `--format etoml`
for other file formats. Use `--no-template` to create keys without secrets files.
If you omit the project ID, `project init` tries to infer it from Git origin.
Use an explicit ID when adding environments to a project with a custom ID.

### Step 3: Add values and encrypt them

Edit the generated file. Keep its `ESEC_PUBLIC_KEY` line.

```sh
$EDITOR .env.dev
esec encrypt dev -f env
```

Example values to add below the public key:

```dotenv
DATABASE_URL=postgres://localhost/store_dev
API_TOKEN=replace-with-your-token
```

Use `-f env` for environment-name commands with dotenv files.
Core esec defaults to `.ejson`.

Read a value or start your application:

```sh
esec get dev DATABASE_URL -f env
esec run dev -f env -- npm run dev
```

`esec run` reads the local keyring directly. It does not require the daemon.
Use [the broker](#run-applications-through-the-broker) when you want policy-controlled
access through `esec vault run`.

### Step 4: Save the encrypted files and back up the keys

Encrypt each file after you add its values. Then commit the marker and encrypted
files to Git. Keep private keyring files out of Git.

```sh
esec encrypt staging -f env
esec encrypt prod -f env
git add .esec-project .gitignore .env.dev .env.staging .env.prod
```

If your repository ignores `.env.*`, add exceptions for the specific encrypted
files you want to track. Your Git repository stores the encrypted data.
Your vault backup stores the private keys.

After you configure a backup remote, run:

```sh
esec vault backup --verify --push
```

Without a remote, `esec vault backup --verify` creates a local backup.

### Work in several projects

Change directory to select the project:

```sh
cd ~/projects/store
esec vault env list
esec run dev -f env -- npm run dev

cd ~/projects/billing
esec vault env list
esec run dev -f env -- npm run dev
```

Both projects can use the environment name `dev`. Their private keys are separate.
Use an explicit project ID to list or create keys from another directory:

```sh
esec vault env list --project acme/store
esec vault env add qa --project acme/billing
esec vault keyring list
```

One backup includes all project keyrings in the configured global store.
Run `status`, `backup`, or daemon commands from any directory.

### Open an existing project after cloning it

```sh
git clone git@github.com:acme/store.git
cd store
```

The clone contains the project marker and encrypted files. It does not contain
your private keys. If your global keyring already has `acme/store`, use esec
immediately. Otherwise, restore your own backup or import a teammate's share
with `esec vault sync`.

Keep the public keys that are already in the files. Generating new keys does
not recover the keys used by existing encrypted files.

## Add environments and keys

### Add an environment with a file template

From the project root:

```sh
esec vault project init acme/store --env qa --format env
$EDITOR .env.qa
esec encrypt qa -f env
esec vault env list
```

This adds `qa`. It keeps the other environments.
Running the same command again keeps matching keys and files.
If an existing file uses a different public key, the command stops.
Import that file's original private key before trying to reuse it.

### Add a named key without a template

```sh
esec vault env add preview
```

This stores a private key and prints its `ESEC_PUBLIC_KEY=...` line.
Create `.env.preview` in your editor and put that line at the top.
Then add values and encrypt the file:

```sh
$EDITOR .env.preview
esec encrypt preview -f env
```

Do not redirect `env add` into an existing secrets file. Shell redirection can
truncate the file before the command checks whether the environment exists.

Core esec provides another key-only command:

```sh
esec keygen --save --env preview2 --project acme/store
```

Both commands refuse to replace an existing named environment key.
Neither command creates a secrets file. In contrast, plain `esec keygen` prints
both keys and does not save them.

### Give each component its own key

Use dotted environment names:

```sh
esec vault project init acme/store \
  --env api.dev,api.prod,worker.dev,worker.prod --format env
```

These are four separate keys. Use the full environment name in commands:

```sh
esec encrypt api.dev -f env
esec run api.dev -f env -- npm run dev
```

Use lowercase letters and digits. Separate name parts with dots.
For example, `api.dev` is valid. `api-dev`, `api_dev`, and `API.DEV` are not
valid names for these environment helpers.

### Add an unnamed key

```sh
esec vault keyring add --project acme/store
```

This stores a key under its public-key entry. It prints the public key for a new
file. It does not create a named environment or a secrets file.

Use named environments for normal project work and selective team sharing.
`share --env dev` selects a named key. It does not discover unnamed keys by
looking at your files.

### Refresh the broker after changing keys

The daemon backs up changes, but an unlocked broker keeps its current key cache.
Reload that cache after you add, import, or sync keys:

```sh
esec vault unlock --ttl 4h
```

Changing secret values without changing the key does not require a new key pair.
See the core [file-editing example](https://github.com/mscno/esec#edit-an-encrypted-file).

`identity rotate` changes your personal identity. It does not rotate project
environment keys. Changing the public-key line alone does not re-encrypt a file.

## Use keys in subfolders

Choose one layout for each repository:

| Layout | Marker files | Key arrangement | Example environment |
|---|---|---|---|
| Shared key | One at the root | Components use the same project environment key | `dev` |
| Separate component keys | One at the root | Components have different keys in one keyring | `api.dev` |
| Separate projects | One in each component | Each component has its own keyring | `dev` in each project |

The [core subfolder guide](https://github.com/mscno/esec#subfolder-guide) has full
file trees and commands for all three layouts. The following rules are important.

### Project lookup and file lookup are separate

- Commands inside a folder use its nearest `.esec-project` marker.
- Marker lookup searches parent folders, but stops at the Git root.
- Environment-name commands read a secrets file in the current directory.
- Secrets file lookup does not search parent folders or combine several files.
- A folder name does not become part of an environment name automatically.

### Share a key between folders in one project

From a new repository root:

```sh
esec vault project init acme/sharedapp --env dev --format env
mkdir -p services/api services/worker
cp .env.dev services/api/.env.dev
cp .env.dev services/worker/.env.dev
```

These commands copy the new empty template. Both files use the same public key.
Keep only the root marker. Edit and encrypt each file from its own directory:

```sh
cd services/api
$EDITOR .env.dev
esec encrypt dev -f env
esec run dev -f env -- npm run dev
```

Both folders use `acme/sharedapp` and its `dev` key.
A person who receives this key can decrypt both files.
The private key does not need to be copied into either folder.

### Store separate component keys in one project

From a new repository root:

```sh
esec vault project init acme/platform --env api.dev,worker.dev --format env
mkdir -p services/api services/worker
mv .env.api.dev services/api/
mv .env.worker.dev services/worker/
```

Keep the root marker. Do not shorten `.env.api.dev` to `.env.dev` in this layout.
From `services/api`, use:

```sh
esec encrypt api.dev -f env
esec vault env list
```

The API key is named `api.dev`, even though the file is in the API directory.
To add its production template, create it at the root and move it:

```sh
# Run from the repository root.
esec vault project init acme/platform --env api.prod --format env
mv .env.api.prod services/api/
```

This keeps one root marker. `project init --dir` also writes a marker in the
target directory. Use that behavior for the separate projects in the next example.

### Give each component a separate project

From a new repository root:

```sh
esec vault project init acme/mono/services/api \
  --dir services/api --env dev,prod --format env
esec vault project init acme/mono/services/worker \
  --dir services/worker --env dev,prod --format env
```

Each folder now has its own marker and its own `.env.dev` and `.env.prod` files.
The nested marker selects that component's keyring. It does not merge the parent
project's keys into it.

Use a subshell to run from a component without changing your current directory:

```sh
(cd services/api && esec run dev -f env -- npm run dev)
(cd services/worker && esec vault env list)
```

For a core esec command from the repository root, select the child key directory:

```sh
esec decrypt services/api/.env.dev --key-dir services/api
```

A file path alone does not change the project lookup directory.
For `esec vault run`, change into the component and use its environment name.

### Read a root file from a child folder

```sh
# Run from services/api. Use the repository root's file and keyring.
project_root=$(git rev-parse --show-toplevel)
esec run "$project_root/.env.dev" --key-dir "$project_root" -- npm run dev
```

This requires a root `.env.dev` and a root project marker for that file's key.
The command reads one file. It does not merge it with the component's file.
Use an absolute path for this key-directory override. The current CLI rejects
`..` in `--key-dir`.

## Import existing project keys

### Step 1: Add the project marker

In the repository that contains the existing `.esec-keyring`, create
`.esec-project` with this content:

```dotenv
ESEC_PROJECT=acme/legacyapp
```

Use your editor if a marker already exists. Keep the project ID that owns the
existing keys. Adding a marker does not generate or import a private key.

### Step 2: Copy the keys into the global store

```sh
esec vault keyring migrate --dir .
esec vault keyring list
```

Migration keeps the local file by default. It refuses an existing destination
keyring; it does not merge several local keyrings into the same project.
To remove the local file as part of the initial import, add `--delete-local` to
that first migration command. The command checks the copied data and asks before
it deletes the local file.

### Step 3: Test the imported key explicitly

With the default vault directory, this command selects the global keyring file
instead of the repo-local file:

```sh
ESEC_KEYRING_PATH="$HOME/.config/esec/keyrings/acme_legacyapp.keyring" \
  esec decrypt dev -f env
```

Adjust the path if you use a custom vault or keyring directory.
Private-key environment variables still take priority over this file selection.
Then back up the imported keys:

```sh
esec vault backup --verify --push
esec vault unlock --ttl 4h
```

You can scan several repositories with `keyring migrate --dir /path/to/repos`.
Each local keyring needs a project marker. Local keyrings with the same project
ID target the same global file; resolve that conflict before removing any copy.

Backups include the global project keyrings and `default.keyring`. A key that
exists only in an environment variable or an external secret store must first
be saved or imported into the global store. esec-vault does not scan SSH keys
or other tools' credential stores for project keys.

## Share project keys with a teammate

Sharing is different from cloud backup. A backup protects your copy of the keys.
A share gives another person's vault identity a copy of selected project keys.

In this example, Alice receives `dev` and `staging` for `acme/store`.
Each person needs their own personal vault identity.
Run the commands in the directory that contains this project's `.esec-project`.

### Step 1: Alice publishes her identity proof

Alice needs an SSH key whose public key is registered on her GitHub account.
The proof command uses OpenSSH to sign her vault public key.

On Alice's computer, in her clone:

```sh
esec vault identity show
esec vault members prove --login alice --ssh-key "$HOME/.ssh/id_ed25519"
git add .esec/members/alice.proof
git commit -m "Add Alice vault identity proof"
git push
```

If needed, load the SSH key into Alice's SSH agent with
`ssh-add "$HOME/.ssh/id_ed25519"` before creating the proof.
The committed proof contains public identity data and a signature.
It does not contain either private key.

### Step 2: The key owner verifies and trusts Alice

On the computer that already has the project keys:

```sh
git pull
esec vault members verify alice
esec vault members trust alice
```

Compare the displayed fingerprint with Alice's `identity show` output through
a separate trusted channel. Confirm the trust prompt after the fingerprints match.

### Step 3: The key owner creates the share

```sh
esec vault share --to alice --env dev,staging
git add .esec/vault/alice.esec
git commit -m "Share development and staging keys with Alice"
git push
```

The share file is encrypted to Alice's vault identity. It can be committed.
For dotted environments, use the full name:

```sh
esec vault share --to alice --env api.dev,worker.dev
```

Use `--to alice,bob` to send the same selection to two verified, trusted members.
Omitting `--env` shares every entry in the current project's keyring, including
unnamed keys. It does not share all projects in your personal vault.

Each `share` command replaces that member's share file in the current directory.
List the complete set of environments the member should receive each time.
For example, use `--env dev,staging,qa` when you add `qa` to an existing share.

An environment-limited share contains the named key entries. Keep matching
environment and file names on the receiving side. For example, use `api.dev`
with `.env.api.dev`. Such a share does not include every public-key alias.

### Step 4: Alice imports the share

On Alice's computer:

```sh
git pull
esec vault sync
esec vault env list
esec get dev DATABASE_URL -f env
esec vault backup --verify --push
```

`sync` imports shares addressed to Alice's current identity. It keeps existing
entries and asks before replacing conflicting values. Alice can now use core
esec directly, or [configure broker access](#run-applications-through-the-broker).
If her broker is already unlocked, she must run `unlock` again to load the keys.

### Share keys for a nested project

For separate component projects, run the complete workflow from each component
directory. Its proof and share files are local to that directory:

```text
services/api/
  .esec-project
  .esec/members/alice.proof
  .esec/vault/alice.esec
```

The key owner runs:

```sh
cd services/api
esec vault members verify alice
esec vault members trust alice
esec vault share --to alice --env dev
```

Alice runs `esec vault sync` from `services/api` in her clone.
Repeat for `services/worker` if Alice should also receive its keys.

An identity proof can be reused in several projects. Place it in each project's
`.esec/members` directory. `members`, `share`, and `sync` use the current directory;
they do not search parents or recursively process nested projects.

### Change or remove access

Create and commit a new share when you add keys or when a teammate changes their
personal identity. Verify a changed identity fingerprint before trusting it.

Deleting a committed share file does not remove keys already imported by a
recipient. To remove access, replace the affected project keys, re-encrypt the
affected files, and share the new keys with the remaining members. Replace any
credentials that the removed member already received.

## Run applications through the broker

Core `esec run` reads keys directly. `esec vault run` asks the daemon's broker.
The broker needs an unlocked session and a matching policy rule.

### Step 1: Add policy rules

Edit `~/.config/esec/policy.toml`. These example rules allow selected development
environments and require approval for the store's production environment:

```toml
default = "deny"

[[rule]]
project = "acme/store"
env = ["dev", "staging", "qa"]
action = "allow"

[[rule]]
project = "acme/store"
env = ["prod"]
action = "ask"

[[rule]]
project = "acme/platform"
env = ["api.dev", "worker.dev"]
action = "allow"

[[rule]]
project = "acme/mono/services/api"
env = ["dev"]
action = "allow"
```

The first matching rule wins. Environment names match exactly.
An `env = ["dev"]` rule does not match `api.dev`.
Use the nested project's full ID when it has its own marker.

### Step 2: Start, reload, and unlock

```sh
esec vault daemon install --start
esec vault daemon reload
esec vault unlock --ttl 4h
```

Use `daemon reload` after editing policy. Use `unlock` again after adding or
importing keys. Restarting the daemon starts a locked session.

### Step 3: Run from the correct directory

```sh
# From the store project root.
esec vault run dev -f env -- npm run dev

# From a repository root with separate component projects.
(cd services/api && esec vault run dev -f env -- npm run dev)
```

For one project with dotted component environments, run from the file's directory:

```sh
(cd services/api && esec vault run api.dev -f env -- npm run dev)
```

Use an environment name for broker commands. The current broker checks the
environment argument as supplied. An explicit file path is not converted to
`dev` for policy matching. The broker supports dotenv and EJSON injection.

### Approve a request

An `ask` rule makes the requesting command wait for approval.
In another terminal, inspect `~/.config/esec/audit.log`. The entry with
`"decision":"ask"` contains the request ID in its `detail` field.

```sh
tail -n 20 ~/.config/esec/audit.log
esec vault approve REQUEST_ID
```

Replace `REQUEST_ID` with the ID you inspected. The request expires after five
minutes if it is not approved. `lock` also cancels pending requests.

```sh
esec vault lock
```

Locking ends broker access. It does not stop backups or revoke direct access
to plaintext working keyring files on your computer.

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
debounce = "15m"       # wait from first pending change; 0s = immediate
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

## Daily command reference

| Task | Command |
|---|---|
| Check identity, backup, and daemon state | `esec vault status` |
| Check setup and repository coverage | `esec vault doctor --dir ~/projects` |
| List stored projects | `esec vault keyring list` |
| List this project's named keys and public keys | `esec vault env list` |
| List another project's named keys | `esec vault env list --project acme/store` |
| List proofs in the current project | `esec vault members list` |
| Import a share after `git pull` | `esec vault sync` |
| Reload policy after editing it | `esec vault daemon reload` |
| Load current keys and unlock for four hours | `esec vault unlock --ttl 4h` |
| Lock broker access | `esec vault lock` |
| Create a local backup | `esec vault backup --verify` |
| Back up and upload now | `esec vault backup --verify --push` |
| Check remote upload state | `esec vault remote list` |
| Read recent daemon logs | `esec vault daemon logs` |

Use the managed daemon for normal work. `agent --from-vault --ttl 4h` is an
alternative foreground broker for manual use. Do not start that broker on the
same socket as an active managed daemon.

## Find and fix common problems

| Problem | Check or action |
|---|---|
| `dev` cannot find a file | Check the current directory. Use `-f env` for `.env.dev`. Secrets files are not searched for in parent folders. |
| No project marker is found | Add `.esec-project` with `ESEC_PROJECT=org/repo`. Use no quotes. The search stops at the Git root. |
| A child file uses the wrong project | For core esec, pass `--key-dir services/api` from the root. For broker commands, change into the component directory. |
| `--key-dir ../..` is rejected | Set `project_root=$(git rev-parse --show-toplevel)` and use `--key-dir "$project_root"`. |
| A correct public key still fails to decrypt | Check named key entries and `ESEC_*` overrides. Named environment entries have priority over public-key entries. |
| An environment already exists | Use `env list`. Use `project init PROJECT --env NAME --format env` to create a missing template with the existing named key. |
| An existing file has a different public key | Import its original private key. A new key cannot decrypt its old values. |
| Migration says the target keyring exists | Migration does not overwrite or merge that target. Keep both copies until you reconcile their keys. |
| The broker reports a missing key after an import | Run `esec vault unlock --ttl 4h` again to reload its key cache. |
| The broker reports `denied by policy` | Check the exact project ID and environment name. Run `daemon reload` after a policy edit. |
| `share` or `members` cannot find files | Run the command in the directory that contains this project's marker and `.esec` directory. Sharing commands do not search parents. |
| A filtered share omits an unnamed key | `share --env` selects named entries. Use named environment keys for selective sharing. |
| `sync` cannot open a share | Pull the latest share and check the current directory. If your identity changed, ask the owner to verify the new proof and share again. |
| A backup does not contain a repo-local key | Import the `.esec-keyring` first. Backups collect keys from the global store. |
| An upload is pending | Check `remote list` and `daemon logs`. Use `backup --push` to request an immediate upload. |
| A new clone has encrypted files but cannot decrypt | Restore your personal backup or use `sync` to import a share. The marker alone does not provide private keys. |

### Check key lookup without changing the shell

The core [key lookup guide](https://github.com/mscno/esec#private-key-lookup)
lists all overrides and their order.
For example, you can remove one stale environment override for a single command:

```sh
env -u ESEC_PRIVATE_KEY_DEV esec decrypt dev -f env
```

This does not change the variable in your current shell.
Other overrides can still apply. `ESEC_KEYRING_PATH`, for example, selects one
exact file and disables other keyring-file lookups.

For `.env.api.prod`, each key source checks `ESEC_PRIVATE_KEY_API_PROD`, then
`ESEC_PRIVATE_KEY_PROD`, then the entry for the file's public key. If an earlier
named key is wrong, esec does not retry every other key after decryption fails.
Keep component names in both the environment and the filename to avoid this
ambiguity.

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
