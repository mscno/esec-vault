# esec-vault

Use esec-vault to store, share, and back up the private keys used by
[esec](https://github.com/mscno/esec). Use esec to encrypt project secrets files.

You can write every vault command as `esec vault ...` or `esec-vault ...`.
Both forms run the same program.

## Find a guide

- [Runbook: new projects, people, keyless Fly.io apps with a cloud KMS, key rotation](docs/runbook.md).
- [Quick recipes: people, CI, servers, Fly.io apps, fleets](#quick-recipes).
- [Set up your personal vault](#first-setup).
- [Sync keys between machines with a vault server](#sync-keys-with-a-vault-server).
- [Set up a project and its marker](#set-up-a-project).
- [Add environments and keys](#add-environments-and-keys).
- [Use keys in subfolders](#use-keys-in-subfolders).
- [Import existing project keys](#import-existing-project-keys).
- [Share a project with your team through the server](#share-a-project-with-your-team).
- [Give CI jobs and apps their own key](#give-ci-jobs-and-apps-their-own-key).
- [Run a fleet of machines in groups](#run-a-fleet-of-machines-in-groups).
- [Share keys with a teammate without a server](#share-project-keys-with-a-teammate).
- [Run an application through the broker](#run-applications-through-the-broker).
- [Set up a remote backup](#remote-configuration-file--wizard).
- [Operate the daemon](#automatic-backups).
- [Recover your keys](#recovery).
- [Find and fix common problems](#find-and-fix-common-problems).

The examples use esec v0.8.0 or later and esec-vault v0.3.0 or later.
Replace `acme`, project names, paths, and GitHub logins with your own values.
Replace `npm run dev` with your application's start command. Set `$EDITOR` to
your editor, or replace `$EDITOR` in the examples with an editor command.

## Quick recipes

Copy-paste versions of the common tasks. Each assumes you signed in to your
vault server (`esec vault login https://vault.example.com`) and run the
command in the project's repository, or pass `--project org/repo`. Replace
`acme/store`, `acme/production` and the logins with your own.

### Share a project with a teammate

```sh
esec vault access create                    # once per project: you become its admin
# the teammate, once: sign in, then prove their account with their GitHub SSH key
esec vault login https://vault.example.com && esec vault access prove
esec vault access grant alice --env dev     # you: add them; their devices get the dev key
esec vault access grant alice --env staging # later: now dev and staging
```

On the web: the project's page › **Add a member**, then sign it with a
passkey or `esec vault changes`. (`esec vault team ...` still works: `team`
is the old name of `access`.)

### Give a whole team access with a group

```sh
esec vault group create acme/backend                     # you become its admin
esec vault group add acme/backend alice                  # people read what the group reads
esec vault group add acme/backend bob
esec vault access grant acme/backend --env dev,staging   # in each project's repository
```

Everyone in the group gets the keys on their next sync (their device asks
once per project). A new hire is one `group add` instead of one `access
grant` per project. On the web: the group's page › **Add a person**.

### Offboard someone

```sh
esec vault access offboard alice --dry-run   # every project and group alice reads
esec vault access offboard alice             # take it all away; lists what to rotate
esec vault env rotate prod --project acme/store
```

On the web: **Access** › the person › **Offboard**.

### Give access for a while

```sh
esec vault access grant alice --env prod --for 8h   # prod ends again in 8 hours
```

When the time comes, the server signs the removal for you if you let it
(`esec vault delegate server`); otherwise it waits in `esec vault changes`
(and `changes --yes` signs it, since it only takes access away).

### Rename, archive or delete a project, hand over admin

```sh
esec vault access move acme/shop          # rename: same keys and people; members follow
esec vault access archive                 # no keys are sent for it; --undo to restart
esec vault access delete --yes            # an archived project, from the server
esec vault access handover alice --step-down
esec vault access leave
```

After a move, set `ESEC_PROJECT` in the repository's `.esec-project` to the
new id and commit it; machines bound to the old project are listed to create
again. On the web, the project's page › **Settings** proposes each of these
for a passkey or device to sign (moving and handing over admin need a
device), and a member leaves there.

### Manage devices from the web

A device's page (Overview › the device) asks your devices to approve a new
device, rename one or retire (revoke) one. Your user key signs these, so one
of your devices does it, in `esec vault changes` or its dialog. To approve, you
type the words the new device shows into the approving device; the web page
never takes them.

### Review who reads a project

```sh
esec vault access review                       # asks about each reader; admins stay
esec vault access review --remove bob,machine:old-ci --yes
```

It records the review on the server. An organisation's policy can ask for
one every so many days; the overview and the project's page then remind its
admins. On the web: the project's page › **Review who reads it**.

### Set up an organisation

An organisation (the acme of acme/store) can have its own signed chain: its
people, the KMS keys its workloads may use, and its rules, all signed on its
admins' devices.

```sh
esec vault org create acme                      # you are its first admin
esec vault org add acme alice                   # --admin for an admin
esec vault org set acme --members-only --require-github-proof --max-token-days 30
esec vault org remove acme alice --yes          # out of every project and group of acme
esec vault org acme                             # people, keys, rules, projects, groups
```

Once it has a chain, only its people create projects and groups named
`acme/...`; with `--members-only`, only they can be added to them. Removing
someone takes them out of everything of acme: your device does it at once
for what you administer, the devices of the other admins at their next
sync. Devices wrap the group keys of acme's workloads only with KMS keys it
approved (`esec vault org kms add`), so a server cannot slip in a key of its
own, and a member's device tells them whether the creator of a project they
are added to belongs to acme.

All of it is on the organisation's web page too (`/orgs/acme`: Overview,
People, Workloads, Settings): each form proposes a change that a device
signs (a dialog of the background service, or `esec vault changes`), or a
passkey where its scope allows. The server's admins can add a policy of
their own there; the stricter of both applies.

### Ask for access, and answer

```sh
esec vault access request --env staging --reason "release week"   # anyone signed in
esec vault access requests                                       # admins: what waits
esec vault access requests --grant 12                            # or --deny 12
```

On the web: a project's page › **Ask for more access** (members), or
**Access** › **Ask for access** (anyone); admins answer on the project's
page.

### Give a GitHub Actions workflow its secrets

```sh
esec vault group create acme/ci
esec vault group grant acme/ci --env prod                 # in the repository
esec vault group token acme/ci deploy --expires never \
  --github-repo acme/store --github-ref refs/heads/main --out - | gh secret set ESEC_VAULT_MACHINE_KEY
```

```yaml
permissions:
  id-token: write          # the token works only from this repository's main branch
  contents: read
steps:
  - uses: actions/checkout@v5
  - name: Install esec and esec-vault
    run: |
      curl -fsSL https://github.com/mscno/esec-vault/releases/download/v0.17.0/esec-vault_0.17.0_linux_amd64.tar.gz | sudo tar -xz -C /usr/local/bin esec-vault
      curl -fsSL https://github.com/mscno/esec/releases/download/v0.11.0/esec_0.11.0_linux_amd64.tar.gz | sudo tar -xz -C /usr/local/bin esec
  - run: esec-vault machine run -- esec run prod -- ./deploy.sh
    env:
      ESEC_VAULT_MACHINE_KEY: ${{ secrets.ESEC_VAULT_MACHINE_KEY }}
```

One token can serve every workflow of the repository; make one token per
repository, so each works only from its own.

### Run a Fly.io app with its secrets

With no secret stored anywhere: approve a cloud KMS key (or a self-hosted
OpenBao one) for the organisation once, then set up each app in one step,
here or on the organisation's **Workloads** page:

```sh
esec vault kms setup gcp --project acme-vault --fly-org acme --fly-app store --apply --approve   # a key for the app, approved
esec vault org fly-app acme store --read acme/store:prod   # prints ESEC_VAULT_WORKLOAD for fly.toml
```

The [runbook](docs/runbook.md) has the details. Or give the app's machines a
token of a group, bound to the Fly.io app, and start the app through
`esec-vault`, which hands it the keys of its project:

```sh
esec vault group create acme/production
esec vault access grant acme/production --env prod
fly secrets set -a store ESEC_VAULT_MACHINE_KEY="$(esec vault group token acme/production fly-store \
  --expires 90d --fly-org acme --fly-app store --out -)"
```

With `--fly-org` (the organisation's slug, from `fly orgs list`) and
`--fly-app`, the server hands the sealed keys only to Machines of that app:
`esec-vault` proves it with the Machine's own OIDC token from `/.fly/api`,
signed by Fly.io (`https://oidc.fly.io/ORG`). A leaked token is useless
anywhere else. `esec vault machine create` takes the same flags.

```dockerfile
FROM alpine:3.21 AS esec
RUN apk add --no-cache curl \
 && curl -fsSL https://github.com/mscno/esec-vault/releases/download/v0.17.0/esec-vault_0.17.0_linux_amd64.tar.gz | tar -xz -C /usr/local/bin esec-vault \
 && curl -fsSL https://github.com/mscno/esec/releases/download/v0.11.0/esec_0.11.0_linux_amd64.tar.gz | tar -xz -C /usr/local/bin esec

FROM your-app-image
COPY --from=esec /usr/local/bin/esec /usr/local/bin/esec-vault /usr/local/bin/
# The image holds the repository's .esec-project and encrypted .env.prod.
CMD ["esec-vault", "machine", "run", "--", "esec", "run", "prod", "--", "/app/server"]
```

Every machine of the app uses the same token, and the group's page shows
when each fetched its keys. Remove the token there to cut them all off.

### Add a server or VM

On the server (once), with esec and esec-vault installed:

```sh
sudo esec-vault machine join acme/production --server https://vault.example.com \
  --fingerprint WORD-WORD-WORD-WORD-WORD-WORD-WORD-WORD   # from: esec vault group show acme/production
```

It shows six words and waits. On your laptop, check the words and let it in:

```sh
esec vault group approve acme/production
```

The server keeps its key in `/etc/esec-vault/machine.key`; services start
with `esec-vault machine run -- esec run prod -- ./server`.

### Add many machines at once (autoscaling, images)

```sh
esec vault group token acme/production autoscale --expires 90d
```

Put the token in the image or the machines' start-up script; each machine
joins by itself, with its own key, and no laptop needs to be on:

```sh
ESEC_VAULT_ENROLL_TOKEN=esecg1_... esec-vault machine join
```

### Remove a person or a machine

```sh
esec vault access revoke alice                    # then rotate what it lists
esec vault env rotate dev
esec vault access revoke alice --env prod         # only prod
esec vault group remove acme/backend alice        # out of a group: the group gets a new key
esec vault group remove acme/production web-3     # a machine: the group gets a new key
esec vault group remove acme/production web-4 --destroyed   # deleted with its disk: nothing to rotate
```

On the web, **Remove** blocks a person's or machine's keys at once; with
`esec vault delegate server`, the server also signs the removal for you.

### Approve web changes without a terminal

Under **Overview › Signing**, open the signer page and make a passkey
(YubiKey, Touch ID, phone); approve it once with `esec vault changes` after
comparing the fingerprint. From then on, **Sign with passkey** on the Changes
page opens the signer, which shows what you sign; one touch signs it. Your computer also shows a dialog for each change
while the background service runs.

### Run many projects and apps

```sh
esec vault todo                                            # what waits for you, everywhere
esec vault access list --needs rotate --org acme           # every key to rotate
esec vault access grant acme/backend --env dev,staging --project 'acme/*' --skip-missing-env
esec vault org fly-app acme api web worker --read acme/shared:prod --json
esec vault org workloads acme --idle 30d                   # apps that stopped starting
esec vault org rekey acme --from gcp-prod --to gcp-prod-2  # move every app to a new key
```

Setup commands are safe to run again. The runbook has a table of these.

### See what needs doing

```sh
esec vault access                # shared projects and their to-dos
esec vault group                 # groups, machines waiting to join
esec vault changes               # changes made on the web, waiting for you
```

The web overview lists the same, with the command for each. **Access** on
the web shows everyone who reads something of your projects, directly or
through a group, with what needs rotating first.

### Use it from scripts and agents

```sh
esec vault                         # the commands, in sections; same as esec vault --help
esec vault help group token        # one command, with examples
esec vault access show --json      # list and show commands print JSON with --json
esec vault access grant acme/backend --env dev --json
esec vault access offboard alice --dry-run --json
esec vault changes --list          # look at web changes without signing them
esec vault access revoke alice --yes   # commands that ask take --yes (or --force)
```

`--json` works on `status`, `access list`, `access show`, `access grant`,
`access revoke`, `access offboard`, `group list`,
`group show`, `machine list`, `machine whoami`, `devices list`, `env list`,
`keyring list`, `delegate list` and `changes`. It shows names, public keys
and fingerprints, never a private key.

A command that would ask a question with no terminal attached, and no
answer on stdin, stops and names the flag that answers it. `changes` never
signs anything that gives access unasked: with no answer it signs nothing
and fails, saying so. Errors end with a `hint:` line when there is a next
step, such as a missing `.esec-project`.

Exit codes: `0` done, `1` failed, `80` bad usage (unknown command or flag).
`run` and `machine run` return their command's code. Data goes to stdout,
messages to stderr.

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

## Sync keys with a vault server

A vault server moves your keys to a new machine without rclone, cloud
credentials or a config file. You sign in with GitHub, and an existing device
approves the new one. The server stores only ciphertext: signing in never
decrypts anything.

To run your own server, follow the [server runbook](docs/operations/server.md).
The [design document](docs/design/vault-server.md) explains the security model.

### Connect your first machine

Use the machine that already has your identity and keyrings. The first
login creates your account and asks for your account creation token, which
the server operator gives you:

```sh
esec vault login https://vault.example.com
```

1. Open the printed address and type the code your terminal shows.
2. Sign in with GitHub, check that the code matches, and confirm.
3. The first login creates your account and uploads your vault.

Write down the **Account key** words it prints. Every device of your account
shows the same words.

If your identity was created before this version, account creation asks for
your recovery phrase once. The phrase signs your identity as the account's
root, so a machine that later recovers with the phrase can tell your real
account from one a server made up.

On this machine, login also seals the keyring files under a per-machine
cache key, if the `esec` on your PATH is v0.9.0 or later. Use `--no-seal` to
keep them plain.

### Add a machine

On the new machine:

```sh
esec vault login https://vault.example.com
```

After you confirm the code in the browser, the machine waits for approval and
prints its fingerprint words. On a trusted machine, run:

```sh
esec vault devices approve
```

`approve` asks you to type the fingerprint words that the new machine shows.
It does not print them itself, so typing them proves you can see the new
machine's terminal. The new machine then shows the account key and asks you to confirm it matches your other
devices (`esec vault status` shows it). Nothing is installed until you
confirm. In scripts, pass the words instead: `--account-key word-word-…`.

There are two other ways to unlock a new machine:

| Method | Command | Needs |
|---|---|---|
| Recovery phrase | `esec vault login --recover` | Your 24 words (and passphrase, if set) |
| SSH-agent unlock | `esec vault login --ssh-agent --ssh-key ~/.ssh/id_ed25519.pub` | A forwarded SSH agent holding an enabled key (without `--ssh-key`, every agent key is tried) |

To enable SSH-agent unlock, run this on a trusted machine:

```sh
esec vault agent-unlock enable --key ~/.ssh/id_ed25519.pub --expires 90d
```

Only `ssh-ed25519` and `ssh-rsa` keys work. Use a dedicated key with
per-use confirmation (`ssh-add -c`, or your agent's prompt). Every use is
recorded, and your other devices show a notification.

A signed-in machine stays signed in across restarts. On headless Linux, keys
are kept in a TPM-sealed store when a TPM is available, otherwise in a 0600
file. `esec vault status` shows which one is used.

### Keep machines in sync

The daemon syncs automatically: it pushes key changes and pulls changes from
other devices. Without the daemon, commands that change keys push right away.
To sync by hand and answer any conflict questions:

```sh
esec vault sync --server
```

A key changed on one machine replaces the old value on the others. A key
changed differently on two machines is a conflict, and sync asks which value
to keep.

### Manage devices

```sh
esec vault devices                      # list devices with fingerprints and methods
esec vault devices rename d_abc… laptop
esec vault devices revoke d_abc…        # remove a device and rotate your user key
esec vault devices suspend d_abc…       # block it on the server at once
```

Revoking rotates your user key, so the revoked device cannot open anything
stored afterwards. It already saw the keys that existed before, so `revoke`
lists those projects. Rotate their environment keys:

```sh
cd ~/projects/store
esec vault env rotate prod
```

`env rotate` creates a new key, re-encrypts every file that used the old one,
and keeps the old key so git history still decrypts. Commit the re-encrypted
files. If the old key may have leaked, also change the secret values
themselves.

### Use the web pages

Sign in at your server with GitHub. The pages never decrypt anything.

- **Overview**: your devices, SSH-agent unlock slots and signed-in browsers,
  and what needs your attention, with the command to fix each: a device
  waiting for approval, a suspended device to revoke, a device unseen for 90
  days, a slot about to expire. Suspend a device or end its sessions here,
  or sign out other browsers. Each device has a page with its sessions and
  activity.
- **Activity**: everything the server recorded for your account, filtered by
  sign-ins, devices, vault or slots, or by one device.
- **Projects**: your shared projects, then your own project ids, environment
  names and public keys, never private keys or values. Search by a public
  key to find which project and environment an encrypted file belongs to.
  Each shared project has a page with its members, invites, access
  requests, access that ends by itself, what each reads and
  whether their devices have the keys yet, its machines and groups
  and when they were last used, keys to rotate, and its history. Admins add
  members, change what they read and remove them there.
- **Access**: everyone who reads something of your shared projects, directly
  or through a group, and what needs doing (keys to rotate, requests to
  answer). Each person has a page listing what they read, with an
  **Offboard** button. Ask for access to any project here too.
- **Orgs** (`/orgs`, and `/orgs/acme`): an organisation's people (add and
  remove them; who left and is still in a project), its workloads (set up a
  Fly.io app with one form, copy its descriptor, move it to another KMS
  key), and its settings (approved KMS keys, rules and defaults). Set an
  organisation up from its page.
- **Groups**: your groups of people and machines. Each group's page shows
  its people (add and remove them there), its machines
  (when and from where each last fetched its keys), its tokens, which
  projects and environments it reads, machines waiting to join, its history
  and log. Tick environments to change what it reads, remove a machine (it
  is blocked at once) or turn a joining machine away.
- **Changes**: changes made on these pages that wait for your device to sign
  them (see below).
- **Vault**: the stored versions of your vault, with who pushed each.
- **Enter a code**: confirm a device sign-in.
- **Alerts** (on the overview, when the server sends email): get an email
  when a device signs in to your account, is approved, suspended or
  revoked, or when someone signs in on the web from a new browser.

Pages update in place and refresh on their own while open. Changes to who
reads what are signed with your user key, which only your devices hold, so
a change made on a page waits until one of your devices signs it:

```sh
esec vault changes
```

It shows each change and asks before signing it; for a new member, it also
checks their GitHub SSH proof first. Removing a machine on a page blocks it at
once, before you sign. There are faster ways, set up under **Overview ›
Signing**:

- **A dialog on your computer.** The background service shows each change as
  soon as it waits, in a dialog it writes itself from the change it will
  sign, with **Sign**, **Later** and **Dismiss**. (`ESEC_VAULT_DIALOGS=off`
  turns it off; without a desktop it notifies instead.)
- **A passkey** (a YubiKey, Touch ID, your phone). Passkeys live on the
  *signer page*, `https://sign.` and your server's host: a static page hosted
  apart from the vault server, so the server can neither make a passkey nor
  have one sign anything. Make one there, add it from a device with
  `esec vault changes` after checking the device shows the same fingerprint
  as the signer page, then sign changes there with one touch: the signer
  decodes and shows the exact change each signature signs. A passkey
  signs adding members, changing what members and already-granted machine
  groups read, and removals; never making anyone an admin, never keys, never
  a new group for a project. A member a passkey adds
  gets keys only once an admin's device has checked their GitHub SSH proof.
- **Removals by the server.** Let the server sign changes that only take
  access away (from members who are not admins, and machines), so they take
  effect at once: `esec vault delegate server`, or on the Signing page. It can
  never add anyone or grant anything.

`esec vault delegate` lists them; `esec vault delegate remove NAME` and
`esec vault delegate server --off` take them back. A new user key (after you
revoke a device) drops them all.

Each device publishes the project index with its vault pushes. Turn it off on
a device with:

```sh
esec vault index off
```

### Sign out

```sh
esec vault logout                  # end the session, keep keys on this machine
esec vault logout --forget-device  # also delete this device's keys
```

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
If origin is missing or empty, it reports an error; pass `--project acme/store`
to initialize without a remote. On success, it prints the project ID, absolute
directory path, and whether the ID came from `--project`, the positional
argument, or Git origin.
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

### Print an environment's private key

From the project directory or one of its subfolders:

```sh
esec vault env show-key dev
```

The command finds the nearest `.esec-project` marker and asks for confirmation.
Enter `y` to print the private key as a plain hex string on stdout. Any other
answer, or no input, cancels without printing the key. Confirmation is always
required, including with `--quiet`.

Use `esec vault env show-key api.prod --project acme/store` to select a project
explicitly. This exposes the private key in your console; only run it when you
need the key itself.

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

## Share a project with your team

With a vault server, a project can have members: who may read which
environment is kept in a list signed by the project's admins, and each
member's devices receive the keys they may read, sealed to that member's
own key. The server passes them on but cannot read them, and cannot add
anyone. Everyone who shares a project needs an account on the same server.

### Step 1: Members prove their account

Each new member signs in to the server, then proves with an SSH key
registered on their GitHub account that the vault account is theirs:

```sh
esec vault login https://vault.example.com
esec vault access prove                     # uses your SSH agent
esec vault access prove --ssh-key ~/.ssh/id_ed25519
```

Without a GitHub SSH key, the member reads out the account key words that
`esec vault status` shows instead, and the admin types them in step 3.

### Step 2: Share the project

On a device that holds the project's keys, in its repository:

```sh
esec vault access create                    # you become its first admin
```

### Step 3: Add people

```sh
esec vault access grant alice --env dev,staging
esec vault access grant bob --admin         # reads everything, manages the project
esec vault access grant carol --env dev --account-key "word word word …"
```

`grant` checks a new person's GitHub proof against `github.com/LOGIN.keys`, and
sends them the keys of the environments they may read. The first time, the
member's device asks before it takes in a project's keys:

```sh
esec vault access sync                      # on Alice's machine
```

After that, the background service takes in new keys on its own, and
Alice's other devices get them through her vault.

### Teams: give a group of people access

A group (such as `acme/backend`) holds people who read the same
environments. Its admins add and remove people; each project's admins
decide what the group reads. The projects' keys are sealed once, to the
group's key, and the group's key to each person in it, so someone who joins
reads everything the group reads, and someone who leaves gives the group a
new key.

```sh
esec vault group create acme/backend
esec vault group add acme/backend alice     # checked like a new project member
esec vault access grant acme/backend --env dev,staging
esec vault access grant acme/backend --env prod --project acme/payments
esec vault group show acme/backend          # its people, machines and projects
esec vault group remove acme/backend alice  # the group gets a new key
esec vault group leave acme/backend         # a member leaving by themselves
```

A member's devices take in the keys like a member of the project's would,
asking once per project. Group admins manage the group without reading
through it; give an admin access to a project directly when they need it.
A group can hold machines as well (see below).

### Invite someone who has no account yet

On a project's page (Add a member) or a group's page (Add a person), name
someone who has not signed in to the server yet: the invite waits, and once
they create their vault account it becomes a change for you to sign. Cancel
it on the same page.

### Change access, remove people, rotate keys

```sh
esec vault access                           # your shared projects
esec vault access show                      # people, groups, machines, keys, what needs doing
esec vault access grant alice --env prod    # adds prod to what alice reads
esec vault access revoke alice --env prod   # takes prod away
esec vault access set alice --env dev,staging   # replaces what alice reads
esec vault access revoke alice              # alice leaves the project
esec vault access leave
esec vault access offboard alice            # every project and group alice reads
```

Someone who loses access may still hold the keys they had. `revoke`,
`set` and `offboard` list the environments that need a new key, the project page shows
them, and the other members get an alert. In the repository, an admin runs:

```sh
esec vault env rotate prod
```

It re-encrypts the files, and sends the new key to everyone who still
reads `prod`. Commit the re-encrypted files, and change the secret values
themselves where they may have been seen. Only admins rotate or add keys of
a shared project; `env add` and `env rotate` send them to the team.

Admins' devices send keys that members are missing on their own, for
example after a member's user key changed. `esec vault access sync` does the
same by hand.

## Give CI jobs and apps their own key

A machine is a key for one CI job or app, instead of a copy of an
environment key: it reads only the environments you give it, every use
is recorded, and removing it stops it at once. An admin creates it:

```sh
esec vault machine create deploy --env prod
esec vault machine create deploy --env prod --out - | gh secret set ESEC_VAULT_MACHINE_KEY
```

Store the key it prints as the secret `ESEC_VAULT_MACHINE_KEY`. In the job,
`esec-vault` fetches the machine's keys and runs your command with them:

```sh
esec-vault machine run -- esec run prod -- ./deploy.sh
esec-vault machine env --format github    # GitHub Actions: masked, into $GITHUB_ENV
```

For GitHub Actions, bind the machine to a repository, so the server hands
its keys only to that repository's jobs. A leaked secret is then useless
anywhere else:

```sh
esec vault machine create deploy --env prod \
  --github-repo acme/store --github-ref refs/heads/main --github-environment production
```

```yaml
permissions:
  id-token: write   # lets the job prove where it runs
steps:
  - run: esec-vault machine run -- esec run prod -- ./deploy.sh
    env:
      ESEC_VAULT_MACHINE_KEY: ${{ secrets.ESEC_VAULT_MACHINE_KEY }}
```

On Fly.io or another host, set the secret the same way
(`fly secrets set ESEC_VAULT_MACHINE_KEY=…`) and start the app with
`esec-vault machine run -- ./app`. List and remove machines with
`esec vault machine list` and `esec vault machine remove deploy`; removing
one lists the environments to rotate.

## Run a fleet of machines in groups

A machine group is a set of machines, such as your production servers,
that read the same environments of one or more shared projects. Each
machine has its own key, so you can add and remove machines one at a time;
the projects' keys are sealed once, to the group's key, so a new machine
reads them the moment it is in the group, whether or not your laptop is on.

### Step 1: Create a group and say what it reads

On a device that holds the projects' keys (an admin of the projects):

```sh
esec vault group create acme/production
esec vault group grant acme/production --project acme/store --env prod
esec vault group grant acme/production --project acme/api --env prod
```

`group create` with a bare name (`production`) creates `LOGIN/production`.
`group grant` again with other environments changes what the group reads;
`group revoke` stops it reading a project. When the project's admins and the
group's admins are different people, each side runs `group grant` to agree:
the group's admins first, since they choose which projects it reads.

### Step 2: Bring machines in

Pick whatever suits the machine:

- **An enrollment token**, for CI jobs, containers and autoscaled machines.
  A job uses it directly as its secret `ESEC_VAULT_MACHINE_KEY`; a
  long-lived machine joins with it once and keeps a key of its own:

  ```sh
  esec vault group token acme/production autoscale --expires 90d
  # on each new machine, from its image or start-up script:
  ESEC_VAULT_ENROLL_TOKEN=esecg1_... esec-vault machine join
  ```

  Bind a token to GitHub Actions with `--github-repo`, as for single
  machines below: it then works, and enrolls machines, only from that
  repository's jobs.

- **On the machine itself**: it asks to join and shows six words; you let it
  in from your device after checking the words match.

  ```sh
  # on the machine (group show prints the fingerprint):
  esec-vault machine join acme/production --server https://vault.example.com \
    --fingerprint WORD-WORD-WORD-WORD-WORD-WORD-WORD-WORD
  # on your device:
  esec vault group approve acme/production
  ```

  With `--fingerprint`, the machine refuses a server that names a different
  group; without it, the machine trusts the server's word for the group
  the first time, and only your word check protects it.

- **A key you make yourself**, for a machine you set up by hand:
  `esec vault group add-machine acme/production db-1`, then save the key it
  prints as `/etc/esec-vault/machine.key` (mode 0600) on the machine.

A joined machine keeps its key in `/etc/esec-vault/machine.key` (as root on
Linux) or in the esec configuration directory; `ESEC_VAULT_MACHINE_FILE`
points elsewhere.

### Step 3: Run commands with the keys

```sh
esec-vault machine run -- esec run prod -- ./server
esec-vault machine whoami      # which machine, which group, what it reads
```

Every key is set by public key, so esec finds the right one for any
project's file. The keys of the project in the current directory (its
`.esec-project`, or `--project`) are also set by environment name.

### Watch and change the fleet

```sh
esec vault group show acme/production     # machines, last use, tokens, what it reads
esec vault group remove acme/production web-3
esec vault group remove acme/production web-4 --destroyed   # deleted with its disk
```

Removing a machine stops the server handing it keys at once, gives the
group a new key sealed to the machines left, and lists the environments to
rotate. With `--destroyed` (a VM or container deleted with its disk),
nothing needs rotating.

The group's web page (**Machines** in the menu) lists its machines with
when and from where each last fetched its keys, its tokens, and a table of
projects and environments. Ticking environments there, or removing a
machine, proposes the change; removing blocks the machine on the server at
once. Your device signs proposed changes with `esec vault group approve`,
because the server holds no key it could sign them with. The background
service tells you when machines wait to join or changes wait to be signed.

## Share project keys with a teammate

This section shares keys without a vault server, through files committed to
the repository. With a server, [share the project with your team](#share-a-project-with-your-team)
instead.

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
esec-vault daemon upgrade               # after upgrading the CLI
```

The OS owns the process: a macOS LaunchAgent or Linux systemd user service starts
at login and restarts after a crash. Installation copies the current executable
to a stable, private path and records an ownership manifest. No root service or
terminal session is needed. `daemon run` and `remote watch` remain foreground
debugging tools.

### Upgrading the CLI and the daemon

The service runs its **own copy** of the executable, not the one on your `PATH`.
Installing a newer `esec-vault` therefore does not change the running daemon,
which keeps executing the copy it was installed with. Refresh it explicitly:

```sh
esec-vault daemon upgrade
esec-vault unlock --ttl 4h              # the daemon restarts locked
```

`daemon upgrade` stops the old process, replaces the managed copy, and starts the
new one. `daemon install` does the same and is a no-op when the copy already
matches, so repeating it never drops a live broker session.

The daemon reports its build over the control socket. `daemon status` shows
`version`, `cli_version` and `up_to_date`, and `status`/`doctor` warn when the
two differ. `daemon restart` refuses to run against a stale copy instead of
silently restarting the old build, pointing you at `daemon upgrade`.

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
esec-vault daemon restart             # restart locked; refuses a stale copy
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
| List shared projects | `esec vault access` |
| See who reads what, and what needs doing | `esec vault access show` |
| Give a person or a group more access | `esec vault access grant acme/backend --env dev` |
| Take access away | `esec vault access revoke alice --env prod` |
| Take everything away from someone leaving | `esec vault access offboard alice` |
| Give access for a while | `esec vault access grant alice --env prod --for 8h` |
| Ask for access, or answer requests | `esec vault access request --env staging`, `esec vault access requests` |
| Review who reads a project | `esec vault access review` |
| Rename, archive or delete a project | `esec vault access move NEW`, `esec vault access archive`, `esec vault access delete` |
| Make someone else an admin | `esec vault access handover alice --step-down` |
| See an organisation and its policy | `esec vault org acme` |
| Receive and send team keys now | `esec vault access sync` |
| List a project's machines | `esec vault machine list` |
| List groups | `esec vault group` |
| Add a person to a group | `esec vault group add acme/backend alice` |
| See a group's people, machines and what it reads | `esec vault group show acme/production` |
| Let machines waiting to join in | `esec vault group approve acme/production` |
| Sign changes made on the web pages | `esec vault changes` |
| Passkeys and server removals | `esec vault delegate` |
| On a machine: what am I, what do I read | `esec-vault machine whoami` |
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
| A machine says the group key or a project's keys were not sent yet | An admin's device seals them on its next sync: `esec vault group sync`. `esec vault group show` says what is missing. |
| A machine says it reads nothing of a project | The group and the project both have to agree: `esec vault group grant GROUP --project ORG/REPO --env ENV`, by an admin of each. |
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

