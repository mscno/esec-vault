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
- [Set up a project and its project file](#set-up-a-project).
- [Add environments and keys](#add-environments-and-keys).
- [Use keys in subfolders](#use-keys-in-subfolders).
- [Import existing project keys](#import-existing-project-keys).
- [Share environments: sealed in the repository, by GitHub username](#keys-live-with-the-code-sealed-in-the-repository).
- [Share a project on a vault server: members, groups, offboarding](#share-a-project-with-your-team).
- [Give CI jobs and apps their own key](#give-ci-jobs-and-apps-their-own-key).
- [Run a fleet of machines in groups](#run-a-fleet-of-machines-in-groups).
- [Run an application through the broker](#run-applications-through-the-broker).
- [Guard prod behind your YubiKey](#guard-prod-with-your-yubikeys).
- [Work with agents and many machines safely](#work-with-agents-and-many-machines).
- [Keep track of every project, and make sure no key is lost](#every-project-on-this-machine).
- [The Mac app](#the-mac-app).
- [Set up a remote backup](#remote-configuration-file--wizard).
- [Operate the daemon](#automatic-backups).
- [Recover your keys](#recovery).
- [Find and fix common problems](#find-and-fix-common-problems).

The examples use esec v0.12.0 or later and esec-vault v0.25.0 or later.
Replace `acme`, project names, paths, and GitHub logins with your own values.
Replace `npm run dev` with your application's start command. Set `$EDITOR` to
your editor, or replace `$EDITOR` in the examples with an editor command.

## Quick recipes

Copy-paste versions of the common tasks. Run each in the project's
repository, or pass `--project org/repo`. Recipes with a vault server
(membership, groups, organisations, offboarding, machines) assume you signed
in to it (`esec vault login https://vault.example.com`). Replace
`acme/store`, `acme/production` and the logins with your own.

### Share environments with a teammate

```sh
esec vault share dev,staging --with alice          # a GitHub login, pinned by id
esec vault share dev --with "group acme/backend"   # everyone in a group
git add esec.toml .esec && git commit -m "share dev and staging with alice"
esec vault unshare staging --with alice --rotate   # take it away, with a new key
```

Each key is sealed to its readers in `.esec/<env>.age`. Alice opens it with
her own keys after `git pull`; nothing else is sent. A GitHub login needs a
sign-in to a vault server, which holds her public keys. Without a server,
share to an age key: `--with alice=age1…`. Details in
[Keys live with the code](#keys-live-with-the-code-sealed-in-the-repository).

### Make a teammate a member of a project on the server

```sh
esec vault access create                    # once per project: you become its admin
# the teammate, once: sign in, then prove their account with their GitHub SSH key
esec vault login https://vault.example.com && esec vault access prove
esec vault access grant alice --env dev     # you: add them; their devices get the dev key
esec vault access grant alice --env staging # later: now dev and staging
```

On the web: the project's page › **Add a member**, then sign it with a
passkey or `esec vault changes`.

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

After a move, set `project` in the repository's `esec.toml` to the
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

### Rename an environment

From a project checkout:

```sh
esec vault env rename prod production
esec vault env rename eu.prod eu.production --dir /path/to/checkout --yes
```

This renames the **vault environment**, not just its file: the key, exposure
history, readers, machine/group access and guard level stay unchanged. Matching
filenames such as `.env.prod` become `.env.production`, recursively, according
to the project's configured patterns. No matching files is fine; their encrypted
contents do not change. Aliases are not used to guess filenames. Nested projects,
symlinks and dependency directories are not traversed; occupied destinations
are refused rather than overwritten. Shared environments require a project admin.

The checkout's `esec.toml`, named keyring entries and `.esec/` seals are updated.
Seals are rebuilt for the **same exact recipients**, including recovery keys;
guarded environments may require a security-key touch and never gain a plaintext
cache. Comments and unknown marker fields are preserved; unusual inline-table
layouts must be converted to separate `[env.NAME]` tables first.

Upgrade the server and all clients before renaming a shared environment. Existing
encrypted grants follow its signed rename; old shared names remain retired to
prevent identity confusion. Update external CI/deployment references and other
checkouts separately. This command is not a key rotation.

If interrupted or the server response is lost, **rerun the same command**.
Keep `.esec/env-rename.json` until it finishes; it holds the checked local plan
and encrypted seals, never private keys. Do not edit files involved in a pending
rename. Local file changes follow the server's atomic rename, so an interruption
can leave local work pending, but does not roll back the vault or lose its keys.

### Set up an organisation

#### Personal and work tenants (guarded server)

The first part of a project ID is its **tenant namespace**, not necessarily
its GitHub repository owner. Keep personal projects under `mscno/...` and
work projects under `geoman/...` or `paraplyventures/...`. There are no plans
or billing tiers. Each tenant has its own ownership and signed policy.

* **Personal:** reserved after verified GitHub sign-in and bound permanently
  to the numeric account ID. Renaming a GitHub login does not rename or
  release it, and a recycled login cannot inherit it. The tenant has one
  permanent owner; individual projects can still have collaborators.
* **Organisation:** any fully onboarded, whitelisted account can claim an
  available namespace by creating a signed tenant. The creator becomes its
  first **owner**. Daily administrators and members are separate roles;
  membership does not automatically grant project keys.

Authentication succeeds even when your GitHub username is unavailable as a
personal namespace. Choose another in the browser, at the login prompt, with
`login --personal-namespace NAME`, or later with `personal choose NAME`.
There is one personal tenant per account, not a new identity per project.

On your trusted device:

```sh
esec vault org create mscno             # personal, one permanent owner
esec vault org create geoman            # self-service organisation; you own it
esec vault org create paraplyventures   # separate team
esec vault org                         # personal/team labels
esec vault org geoman --json
```

Personal and organisation tenants share one case-insensitive namespace pool.
Creating the first project or group does not claim it: creating the tenant
commits its namespace and signed initialization in one transaction, so a
failed signature or concurrent claim cannot leave a squatted organisation.
System names are reserved. Organisation creation defaults to 10 per account;
the operator can adjust `max_orgs_per_account` (no billing or plans).

A vault namespace is **not** a verified claim to the same GitHub organisation.
The signed tenant and its opaque `tenant_id`, not a reusable GitHub login or
handle, identify the workspace. Owners can change its display name or rename
its handle without rewriting history:

```sh
esec vault org add geoman alice --admin
esec vault org owner geoman alice              # second owner, strongly recommended
esec vault org owner geoman alice --remove     # retain daily admin rights
esec vault org rename geoman geoman-work --display-name "Geoman Work"
esec vault personal rename mads-personal
```

Only owners change ownership or the tenant's handle, and the last owner
cannot be demoted or removed. Personal ownership is permanent. Previous
names stay reserved as historical aliases of the same tenant; projects and
groups keep their existing IDs and policy. Create new resources under the
current handle, or use `access move` to rename an existing resource. A rename
between aliases of one tenant retains its people; it is not a cross-tenant
transfer. Namespace deletion/recycling is deliberately not automatic.

Operators can optionally protect known users' personal handles before their
first login with `access.reserved_github_handles = { mscno = 53101343 }`.
IDs must also be allowlisted. Existing reservations are durable; removing
configuration or recycling a GitHub login never transfers ownership.

**Upgrading an existing server:** back up the database first. Existing
unreserved resource prefixes become `legacy`, not somebody's property by
creation order. Their existing projects and signed histories keep working,
but new resources and claims need explicit operator approval. Add reservations
for the actual owners before starting the upgraded server. For an existing
personal prefix, approve it explicitly:

```toml
[[namespaces]]
name = "mscno"
kind = "personal"
owner_github_id = 53101343
```

An existing signed tenant must already recognize the nominated owner;
a personal one must have exactly one person. Historical signed links are not
rewritten. Update clients as well as the server: older clients cannot verify
the new signed tenant-kind and project-transfer fields. Do not roll the
server back to a release without namespace enforcement. Legacy organisation
admins retain their historical owner authority until an owner explicitly
establishes the ownership roster; new organisations separate roles immediately.

#### Transfer a project between tenants

```sh
esec vault project transfer mscno/my-project --to geoman/my-project
```

You must administer the source project and own both tenants for an immediate
cross-tenant move. The destination ID must be unused. The
server creates its new signed chain and archives the source **in one
transaction**, with reciprocal signed chain-root references. Old history and
audit records stay at the source. A name collision, bad signature, stale
source or authorization failure leaves both server resources unchanged.

Across tenants, only the receiving account initially has access; source
people, groups, and machines are **not copied**. Grant access deliberately in
the destination. Within one tenant, renaming retains the existing people and
can reconnect groups you administer. Machines must be recreated.

If a different person owns the destination, create an acceptance request:

```sh
# Source project admin and source tenant owner:
esec vault project transfer mscno/api --to geoman/api --recipient alice
# Receiving tenant owner, on their trusted device:
esec vault transfers
esec vault transfers show tr_...
esec vault transfers accept tr_...
# Either party can withdraw or reject:
esec vault transfers cancel tr_...
esec vault transfers reject tr_...
```

Both accounts are checked using their GitHub SSH proofs, or explicit
`--account-key WORD-WORD-...` verification. An offer binds the source head,
both immutable tenant identities, the recipient's account key, and the exact
new init/source archive. The recipient countersigns that init; signatures do
not change its hash. The server checks both owners again and commits both
projects and acceptance atomically. The source remains active until then.
Offers expire after 24 hours; cancellation, expired offers, stale project
heads, changed user keys, lost ownership, and destination collisions cannot
complete a transfer. Ciphertext records are cleaned up seven days after expiry.
Transfers require a trusted device holding every current environment key.
Guarded-only keys are not silently unguarded or copied into a plain cache;
when those keys are unavailable the transfer fails before changing the server.

The environment keys in an offer are encrypted **only to the chosen account**,
never in plaintext on the server. Offering a transfer authorizes that trusted
person to receive them: someone who downloads the ciphertext can decrypt it
before accepting. Expiry or cancellation prevents the ownership change; it
cannot revoke keys already delivered. Rotate to revoke them.

Environment keys are preserved so encrypted files continue to work. **Former
readers may still possess those keys:** rotate destination environment keys
and re-encrypt files to revoke them; a transfer cannot erase old secrets or
git history. Update `project` in the repository's `esec.toml`, commit it, and
update CI/deploy references to the new ID. The source stays archived, pointing
to its successor; do not unarchive it as a parallel active copy.

#### Signed tenant administration

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
esec vault ci add actions --env prod --github acme/store   # the secret ESEC_AGE_IDENTITY, set with gh
git add esec.toml .esec && git commit -m "CI reads prod"
```

```yaml
steps:
  - uses: actions/checkout@v5
  - name: Install esec
    run: curl -fsSL https://github.com/mscno/esec/releases/download/v0.13.0/esec_0.13.0_linux_amd64.tar.gz | sudo tar -xz -C /usr/local/bin esec
  - run: esec run prod -- ./deploy.sh
    env:
      ESEC_AGE_IDENTITY: ${{ secrets.ESEC_AGE_IDENTITY }}
```

The job's own age key opens `.esec/prod.age`: it needs esec only, and no
vault server. `esec vault ci remove actions` takes it out. Most CI needs
only this. For a project shared on a vault server, a machine key bound to
the repository is the advanced route (see
[Give CI jobs and apps their own key](#give-ci-jobs-and-apps-their-own-key)).

### Run a Fly.io app with its secrets

```sh
esec vault ci add deploy --env prod --fly store   # the secret ESEC_AGE_IDENTITY, set with fly
```

The image holds `esec`, `esec.toml`, `.esec/` and the encrypted
`.env.prod`, and starts with `esec run prod -- /app/server`.

With no secret stored anywhere: approve a cloud KMS key (or a self-hosted
OpenBao one) for the organisation once, then set up each app in one step,
here or on the organisation's **Workloads** page:

```sh
esec vault kms setup gcp --project acme-vault --fly-org acme --fly-app store --apply --approve   # a key for the app, approved
esec vault org fly-app acme store --read acme/store:prod   # prints ESEC_VAULT_WORKLOAD for fly.toml
```

The [runbook](docs/runbook.md) has the details. On a vault server you can
also give the app's machines a token of a group, bound to the Fly.io app,
and start the app through `esec-vault`, which hands it the keys of its
project:

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
 && curl -fsSL https://github.com/mscno/esec-vault/releases/download/v0.22.1/esec-vault_0.22.1_linux_amd64.tar.gz | tar -xz -C /usr/local/bin esec-vault \
 && curl -fsSL https://github.com/mscno/esec/releases/download/v0.13.0/esec_0.13.0_linux_amd64.tar.gz | tar -xz -C /usr/local/bin esec

FROM your-app-image
COPY --from=esec /usr/local/bin/esec /usr/local/bin/esec-vault /usr/local/bin/
# The image holds the repository's esec.toml and encrypted .env.prod.
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

### Rotate a database password, or any credential

```sh
esec vault secrets where DATABASE_URL --root ~/src           # every repository that uses it
esec vault secrets rotate DATABASE_URL --env prod --root ~/src   # one new value, asked for unseen
# commit and deploy each, then:
esec vault env status prod --since 15m                       # which deployments still run the old one
```

Revoke the old value only when every deployment shows ✓. `esec vault hook
install` adds a pre-commit hook that stops values committed in the clear.

### Add a new app, safely

In the app's repository, beside fly.toml:

```sh
esec vault app init --env prod    # checks the repository, sets up the app, writes fly.toml
esec vault app check              # before each deploy, in CI too
```

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
esec vault                         # the everyday commands; same as esec vault --help
esec vault help all                # every command, in sections
esec vault help group token        # one command, with examples
esec vault access show --json      # list and show commands print JSON with --json
esec vault access grant acme/backend --env dev --json
esec vault access offboard alice --dry-run --json
esec vault changes --list          # look at web changes without signing them
esec vault access revoke alice --yes   # commands that ask take --yes (or --force)
```

`--json` works on `setup --check`, `project init`, `status`, `access list`, `access show`, `access grant`,
`access revoke`, `access offboard`, `group list`,
`group show`, `machine list`, `machine whoami`, `devices list`, `env list`,
`keyring list`, `delegate list`, `changes`, `projects`, `projects show`,
`projects scan`, `guard`, `seal`, `seal check`, `security-keys list`, `verify`,
`verify --last` and `activity`. It shows names, public keys
and fingerprints, never a private key.

A command that would ask a question with no terminal attached, and no
answer on stdin, stops and names the flag that answers it. `changes` never
signs anything that gives access unasked: with no answer it signs nothing
and fails, saying so. Errors end with a `hint:` line when there is a next
step, such as a missing `esec.toml`.

Exit codes: `0` done, `1` failed, `80` bad usage (unknown command or flag).
`run` and `machine run` return their command's code. Data goes to stdout,
messages to stderr.

### Start a project whose prod key is guarded from day one

```sh
esec vault security-keys add              # once: plug in your YubiKeys
esec vault project init acme/api --env dev,staging,prod --guard prod
esec vault secrets set STRIPE_KEY --env prod --create   # writing needs no touch
esec vault run prod -- ./deploy           # a dialog, then a touch of the YubiKey
```

The prod key exists in the clear on no disk, only sealed to your YubiKeys
(and your recovery key) in `.esec/prod.age`: an agent running as you can
read every file and still not get it. Details in
[Keys live with the code](#keys-live-with-the-code-sealed-in-the-repository).

### Let an agent work in a repository

```sh
export ESEC_VAULT_SESSION=claude-api ESEC_VAULT_MASK=1   # in the agent's shell
esec vault run dev -- npm test                           # values injected, masked in output
esec vault secrets set SESSION_SECRET --env dev --generate 32
esec vault secrets request STRIPE_KEY --env prod --reason "new integration"   # you paste it in a dialog
```

The agent never sees a value: generated ones go straight into the file,
requested ones are pasted by you into a desktop dialog, and run output is
masked. Guarded environments need your touch. See
[Work with agents and many machines](#work-with-agents-and-many-machines).

### Keep track of every project, and check no key can be lost

```sh
esec vault projects scan ~/src      # remember every checkout, like a git client
esec vault projects                 # every project: checkouts, environments, keys here
esec vault verify                   # every key in two places, none shared between projects
esec vault activity                 # which programs and agents asked for keys
esec vault drill                    # the newest backup opens with your phrase alone
```

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

On every machine, your first or your fifth, run:

```sh
esec vault setup                                      # does what it can, says what is left
esec vault setup --server https://vault.example.com   # a machine joining your account
esec vault setup --check                              # only report; --json for scripts and agents
```

It goes through each step and skips what is done, so run it again any time:

| Step | What it does |
|---|---|
| identity | signs in to your vault server (a machine joining your account), recovers from a backup and your phrase, or creates your first; never a second one unasked, which would split your keys |
| vault server | syncs your keys |
| second place | offers a backup destination when keys would be on this machine only |
| background service | installs it, or upgrades an old one |
| checkouts | finds your projects in `~/src`, `~/code`, `~/projects`, `~/dev`, `~/Developer`, `~/work`, `~/repos` (or `--root`) |
| keys here | lists environments of your checkouts whose key is not here |
| guard | guards here the keys you guard elsewhere (a touch each); suggests a spare YubiKey |
| keys safe | runs `verify`, and reminds you of a recovery drill |

On your first machine, write down the 24-word recovery phrase and confirm it
when asked. You can also set a recovery passphrase.

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

On this machine, login also protects the keyring files with a per-machine
cache key (as `esec vault keyring protect --all` does), if the `esec` on your
PATH is v0.9.0 or later. Use `--no-seal` to keep them plain.

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
To sync by hand (your keys and your shared projects) and answer any questions:

```sh
esec vault sync
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

### Step 2: Create the project file, keys, and files

Run this command from your application directory:

```sh
cd ~/projects/store
esec vault project init acme/store --env dev,staging,prod --format env
```

The command creates:

```text
store/
  esec.toml
  .env.dev
  .env.staging
  .env.prod
```

The project file `esec.toml` contains:

```toml
# esec project file: commit it. It holds no secret.
project = "acme/store"

[files]
format = "env"

[env.dev]
key = "1f0c…"        # the environment's current public key
readers = ["mads (gh:583231)", "alice (gh:91022)"]

[env.prod]
key = "9a2e…"
guard = "touch"
readers = ["mads (gh:583231)", "deploy (age1…)"]
```

Commit it to Git with `.esec/`. It contains no private key. It names the
project, how its secrets files are named, and each environment with its
current public key, guard and readers (see [Keys live with the code](#keys-live-with-the-code-sealed-in-the-repository)).
`env add`, `env rotate` and `guard enable` keep it up to date, changing only
the lines they must, so your comments stay. `secrets lint` fails a file
encrypted to another key than the one it names. Keys it does not know (from
a newer esec) are ignored with a warning. Optional settings:

```toml
[files]
format = "etoml"
name = "secrets/{env}.etoml"   # every machine names and finds files this way

[env.prod]
guard = "touch"                # none, session or touch
```

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

Read a value or start your application:

```sh
esec get dev DATABASE_URL -f env
esec run dev -f env -- npm run dev
```

Commands that take an environment name search every supported format and
naming pattern, and fail when more than one file matches; `-f env` narrows
the search to dotenv files.

`esec run` reads the local keyring directly. It does not require the daemon.
Use [the broker](#run-applications-through-the-broker) when you want policy-controlled
access through `esec vault run`.

### Step 4: Save the encrypted files and back up the keys

Encrypt each file after you add its values. Then commit the project file and encrypted
files to Git. Keep private keyring files out of Git.

```sh
esec encrypt staging -f env
esec encrypt prod -f env
git add esec.toml .esec .gitignore .env.dev .env.staging .env.prod
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

The clone contains the project file and encrypted files. It does not contain
your private keys. If your global keyring already has `acme/store`, use esec
immediately. If you read an environment, its key is sealed to you in
`.esec/`: `esec vault seal sync` opens it on this machine. Otherwise, restore
your own backup, or ask a reader to share it with you
(`esec vault share ENV --with LOGIN`).

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

The command finds the nearest `esec.toml` and asks for confirmation.
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
`share dev --with alice` shares a named environment. It does not discover
unnamed keys by looking at your files.

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

- Commands inside a folder use its nearest `esec.toml`.
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
Keep only the root esec.toml. Edit and encrypt each file from its own directory:

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

Keep the root esec.toml. Do not shorten `.env.api.dev` to `.env.dev` in this layout.
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

This keeps one root esec.toml. `project init --dir` also writes an esec.toml in the
target directory. Use that behavior for the separate projects in the next example.

### Give each component a separate project

From a new repository root:

```sh
esec vault project init acme/mono/services/api \
  --dir services/api --env dev,prod --format env
esec vault project init acme/mono/services/worker \
  --dir services/worker --env dev,prod --format env
```

Each folder now has its own esec.toml and its own `.env.dev` and `.env.prod` files.
The nested esec.toml selects that component's keyring. It does not merge the parent
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

This requires a root `.env.dev` and a root project file for that file's key.
The command reads one file. It does not merge it with the component's file.
Use an absolute path for this key-directory override. The current CLI rejects
`..` in `--key-dir`.

## Import existing project keys

### Step 1: Add the project file

In the repository that contains the existing `.esec-keyring`, create
`esec.toml` with this content:

```toml
project = "acme/legacyapp"
```

Use your editor if an esec.toml already exists. Keep the project ID that owns the
existing keys. Adding the project file does not generate or import a private key.

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
Each local keyring needs a project file. Local keyrings with the same project
ID target the same global file; resolve that conflict before removing any copy.

Backups include the global project keyrings and `default.keyring`. A key that
exists only in an environment variable or an external secret store must first
be saved or imported into the global store. esec-vault does not scan SSH keys
or other tools' credential stores for project keys.

## Share a project with your team

To share environments, `esec vault share ENVS --with WHO` seals their keys
into the repository (see [Keys live with the code](#keys-live-with-the-code-sealed-in-the-repository)).
This section is about a project shared on a vault server: membership,
groups, organisations, offboarding and machines.

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
esec vault sync                             # on Alice's machine
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
example after a member's user key changed. `esec vault sync` does the
same by hand.

## Give CI jobs and apps their own key

Most CI needs only `ci add`. It makes an age key for the job, seals the
environments to it, and stores it as the secret `ESEC_AGE_IDENTITY` with
`gh` or `fly` (or prints it once). The job then reads them with esec alone,
with no vault server:

```sh
esec vault ci add actions --env prod --github acme/store   # stored with gh
esec vault ci add deploy --env prod --fly store            # stored with fly
esec vault ci add build --env dev                          # prints the key once
esec vault ci remove build
```

Commit `esec.toml` and `.esec/`. The job runs `esec run prod -- ./deploy.sh`.

### Machines of a project shared on the server

Machines, groups, workloads and KMS keys are the advanced route: for a
project shared on a vault server, and for workloads that hold no secret
(OIDC and a cloud KMS, in the [runbook](docs/runbook.md)). A machine is a
key for one CI job or app, instead of a copy of an environment key. It reads
only the environments you give it, every use is recorded, and removing it
stops it at once. An admin creates it:

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
esec vault group set acme/production --project acme/store --env prod
esec vault group set acme/production --project acme/api --env prod
```

`group create` with a bare name (`production`) creates `LOGIN/production`.
`group set` replaces what the group reads of a project; `access grant GROUP`
adds to it; `group revoke` stops it reading a project. When the project's
admins and the group's admins are different people, each side runs
`group set` to agree: the group's admins first, since they choose which
projects it reads.

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
  machines above: it then works, and enrolls machines, only from that
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
`esec.toml`, or `--project`) are also set by environment name.

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

## Run applications through the broker

Use the same read commands for ordinary and guarded environments:

```sh
esec inspect production
esec inspect .env.production --json
esec decrypt .env.production
esec run production -- ./deploy
```

With esec v0.18.0 and esec-vault v0.28.0, both clients share the resolver and
read planner. Filenames and exact environment names resolve to the same file,
project, public key and guard; a filename is not used as a policy environment.
Explicit files use their own project rather than the caller's working directory.

An ordinary cached key reads directly. Your personal identity can also open
an unguarded reader seal locally, without the cloud. A guarded key uses the
daemon before any ordinary keyring entry, including an older software copy.
An explicit authorized CI/deploy age identity opens its seal directly. Fresh
public-key-addressed credentials from `machine run` also stay direct. Ordinary
named variables and keyring entries alone never choose that workload route.
`esec decrypt` returns the same document format on either route.

### Local approval without policy setup

Run `esec vault setup` once for your identity and background service. After
updating an existing installation, run `esec vault daemon upgrade`.
Ordinary interactive onboarding needs no manually authored `policy.toml`.

When a broker read needs local consent, the daemon's desktop dialog shows
who requested it, the project, exact environment, file and public key. Choose
**Allow once**, **Allow session** (one hour), or **Cancel**. The scope includes
the checkout, project, environment and key; another key or environment needs
its own approval. Locking the vault or restarting the daemon revokes session
consent. Cancellation, timeout and unavailable desktop approval serve no data.
Only the requested environment is opened: consent does not unlock every key.

Hardware guards retain their own approval and presence checks. A session guard
can reuse its open session; a touch guard asks for hardware approval on each
read. A stronger touch setting never consumes a previously cached session key.
A repository cannot grant itself local consent or remove an explicit local deny.

### Inspect before opening keys

`esec inspect ENV --json` is metadata-only: no secret-store entries are read,
no key or seal opens, no cloud sync runs, and no approval or hardware action
is requested. It reports the file, project, reader metadata, public key, seal
integrity, key availability, guard, read route, broker state, consent and blockers.
Availability that has not been tested stays **unverified**. Reader names in
project metadata are not proof that this device can decrypt the seal.

Blocker codes include `environment_missing`, `environment_ambiguous`,
`key_mismatch`, `consent_required`, `policy_denied`, `daemon_unavailable`,
`daemon_upgrade_required` and `hardware_approval_required`. A read that races
with a changed ciphertext or a vault lock fails explicitly.

### Advanced broker policy and compatibility commands

`~/.config/esec/policy.toml` remains an optional administrative override.
Existing deny rules and configured default denies remain effective for broker
reads. Reload an edited policy with `esec vault daemon reload`. A deliberately
configured allow rule plus an unlocked broker session retains its unattended
behavior. Direct ordinary reads use their local credentials rather than broker
policy; use hardware guard when hardware approval is required.

`esec vault run` and `esec vault decrypt` are compatibility wrappers around the
same reader. Existing masking, JSON and single-value output options remain.
`vault decrypt` retains its historical NAME=value presentation; ordinary
`esec decrypt` always prints the decrypted document. The low-level foreground
broker and forwarded guarded-reader protocol remain available for advanced use.


## Keys live with the code: sealed in the repository

Every environment's private key is committed next to its secrets files, in
`.esec/<env>.age`: a standard [age](https://age-encryption.org) file
encrypted to the environment's **readers** and always to a **recovery
key** your 24 words derive. Whoever can open it has the key; nothing needs
to be synced, copied or remembered.

```
esec.toml            readers of each environment, by GitHub id
.esec/dev.age        dev's key, sealed to its readers + recovery keys
.esec/prod.age       prod's key, sealed to readers' YubiKeys + recovery keys
.esec/seals.toml     signed record: who each seal was made for
```

- **No key is ever lost.** The repository and your phrase open every key,
  in every commit, offline, with no server (`esec vault drill` proves it).
  The pre-commit hook refuses a commit whose seal lacks a recovery key.
- **Nobody handles a key string.** Readers are people by GitHub username,
  pinned to their numeric id (`alice (gh:91022)`): a renamed or re-registered
  login never inherits access. Their keys come from their signed chains on
  the vault server, which the server cannot forge.
- **Changes are reviewed like code.** Sharing is a diff in `esec.toml` and
  `.esec/`; `.esec/seals.toml` is signed, so `secrets lint`, the hook and CI
  catch a swapped key or a reader nobody sealed in.
- **No lock-in.** `age -d -i IDENTITY .esec/dev.age` opens a key with no
  esec at all.

```sh
esec vault project init acme/store --env dev,prod --guard prod
esec vault share dev,staging --with alice          # GitHub login: pinned by id
esec vault share prod --with alice                 # guarded: sealed to her YubiKeys
esec vault unshare prod --with alice --rotate
esec vault seal                                    # who reads what, what to seal again
esec vault seal sync --all                         # reseal what changed; open what you can
```

Someone without an account yet is pinned by GitHub id and sealed in once
they sign up (the Mac app, `setup` and `seal sync` do it). A new machine of
yours needs only your identity (`esec vault setup`): every checkout opens
at once, with no key sync.

### Guard prod with your YubiKeys

A guarded environment is sealed to its readers' **security keys** only, so
no software key on any machine opens it: every read needs a dialog and a
touch no agent can make. One touch opens one environment.

```sh
brew install age-plugin-yubikey
esec vault security-keys setup        # a YubiKey with no age key yet: touch policy always
esec vault security-keys add          # every plugged-in YubiKey: you name it, it goes in your chain
esec vault guard enable --env prod    # or project init --guard prod
esec vault run prod -- ./deploy       # dialog: what, which file, which programs asked; then the touch
esec vault decrypt prod STRIPE_KEY    # one value, after the same dialog and touch (no KEY: all of them)
```

Use `esec decrypt` or `esec run` for guarded reads too: the shared planner
selects the local daemon and its hardware approval flow. Explicit filenames
work the same as exact environment names. CI and deploys use their separate
authorized age identities for unattended reads.
`esec vault unlock` needs no touch; touching a
YubiKey that nothing waits for types its one-time password into the terminal
(`ykman config usb --disable OTP` turns that off if you do not use it).

`esec vault decrypt` prints `KEY=value` lines, quoting a value that holds
anything but printable characters, so a value planted in the file cannot
forge a line or drive your terminal. The lines are not shell syntax: give
secrets to a command with `esec vault run`, never `eval` them. The dialog
shows the asking command's line (`esec vault decrypt prod` or
`esec vault run prod -- ./deploy`): allow a read only if you ran it.

A YubiKey slot with touch policy `never` is not used for guarded reads. One
with `cached` keeps a touch for 15 seconds, so a second read soon after needs
no touch; the dialog says so. `esec vault security-keys setup` makes a slot
that asks every time.

You never copy a recipient: plug a YubiKey in and the background service
asks to add it. Your keys are in your signed chain, so everyone who seals for
you uses them. After adding or removing one, guarded seals are made again:
one touch each, or your phrase once (`esec vault seal recover --all`), which
is also the way back when every security key is lost.

**A blinking key with no esec dialog on screen is one not to touch.** A
`session` key stays open in the service until `esec vault lock`; a `touch`
key is opened for one read. Every read is in `esec vault activity`. Writing
values needs only the public key: no touch.

### CI and deploys: esec alone

```sh
esec vault ci add deploy --env prod --fly acme-store          # secret stored with fly, never shown
esec vault ci add actions --env staging --github acme/store   # with gh
```

The CI gets its own age key, sealed into those environments, as the secret
`ESEC_AGE_IDENTITY`; `esec run prod -- …` then needs nothing else. `esec vault
ci remove deploy` takes it out.

## Work with agents and many machines

The rule: **only your devices hold keys; agents and other machines get
values for one run, or keys of their own that read dev.**

| Where | Identity | Reads |
|---|---|---|
| Your Macs | a device: your user key, signs changes | everything you are granted; guarded envs after a touch |
| A dev VM or box where agents run | a machine in a group, such as `acme/agents-dev` | the dev environments the group reads |
| A cloud agent sandbox | a short-lived group token (`--expires 24h`) | dev |
| CI | its own age key (`esec vault ci add`) | what the workflow needs |
| Fly.io apps | a KMS workload, no secret | its environment |

Never `esec vault login` on a box agents use: a device reads everything
you do. Give it a machine key instead:

```sh
esec vault group create acme/agents-dev
esec vault access grant acme/agents-dev --env dev --project 'acme/*' --skip-missing-env
esec vault group token acme/agents-dev devbox --expires 90d --out -   # ESEC_VAULT_MACHINE_KEY there
```

For the odd staging or prod need on a remote box, forward your Mac's
security key over SSH, like `ssh -A` forwards an SSH agent:

```sh
esec vault forward devbox.example.com
# on devbox:
esec vault run prod -- ./migrate
```

Each read sends the environment's seal to your Mac, shows a dialog there
naming the machine, and waits for your touch. Only the values of that run
cross; the key never leaves the Mac. A forwarded connection reads guarded
keys only.

In an agent's shell:

- `ESEC_VAULT_SESSION=name` labels its reads in the audit log and dialogs.
- `ESEC_VAULT_MASK=1` (or `run --mask`) replaces values with `***` in the
  output of what it runs.
- `secrets set --generate 32` makes a value no one sees; `secrets request
  KEY --env prod` asks you for one in a dialog, and the agent learns only
  that it was set.
- Changes to access an agent makes on the web wait for your device to
  sign them (`esec vault changes`).
- `esec vault hook install` refuses commits with a value in the clear, a
  plain `.env.prod` for a declared environment, or a file encrypted to
  another key than esec.toml names; it checks what is staged and needs no
  network (`secrets lint --staged --offline`). CI should still run `esec
  vault secrets lint`, since a hook can be skipped.
- `esec vault project init --json` says what it set up (environments, keys,
  files created, next steps) and is safe to run again.

## Every project on this machine

esec-vault remembers where each project is checked out, the way a git client
keeps its list of repositories: the project's global id (`acme/store`) and
its directories on this machine, several for clones and worktrees. Commands
that find an `esec.toml` add its checkout by themselves.

```sh
esec vault projects                       # checkouts, environments, keys here, what to fix
esec vault projects show acme/store       # with its secrets files
esec vault projects scan ~/src            # find and remember every checkout
esec vault projects add .  |  remove DIR  |  prune
```

The list is this machine's own, in `~/.config/esec/projects.toml`, and
holds no secret.

### Make sure no key is ever lost

Every key is sealed in its repository, with your recovery key, before any
file is encrypted to it: `project init`, `env add` and `env rotate` seal
first, and stop before writing files when sealing fails. The keyring on each
device is a cache of what you open; sync and backups keep working as a
second copy.

```sh
esec vault verify            # checkouts, git history, this device, the server, the newest backup
esec vault verify --last     # what the background service found (it checks daily)
esec vault drill             # the phrase alone opens every seal (and the newest backup)
esec vault keyring repair    # file keys from older keyrings under their public key
```

`verify` reads every secrets file in every checkout and every one in their
git history, and reports each key that is not on this device, held in only
one place, held nowhere (lost), or used by two projects. History is read once
per repository (worktrees share it), each file counted for the checkout whose
directory holds it (so a monorepo's subprojects stay apart), and cached until
a ref changes. A key of a project you hold no key of anywhere (someone else's
repository, an environment you cannot read) is listed apart, not as lost.
The background service runs it daily and notifies only when something is
wrong; `doctor` reports it, and suggests a drill when the last is older than
six months. Only a full check (no `--no-…` flags) is kept for them.

## The Mac app

`macos/EsecVault` is a menu bar app with a window. It reads metadata only and
never asks for a value; every action is an `esec-vault` command you could
type, and it shows which.

- **Overview**: a setup checklist (recovery phrase, background service, a
  second place for keys, the YubiKey guard and a spare, a recovery drill),
  each step with a button that does it, or opens Terminal for steps that ask
  for a phrase, a PIN or a touch; then key health from `verify`.
- **Activity**: every request for keys, newest first: allowed, asked or
  refused, by which programs (`zsh ▸ claude ▸ esec-vault`) and which agent
  session. The menu bar lists the last day's reads of guarded keys.
- **Projects** by namespace: checkouts (Finder, Terminal), environments with
  their guard, whether this Mac holds the key and the command that fixes it;
  secrets files with values left in the clear; recent requests. Add an
  environment, rotate a key or guard one from there.
- **New Project** (⌘N): pick a folder, name the environments, guard prod;
  it runs `project init`.

It updates when `esec-vault` changes its files (an agent running a command
shows up at once), and can open at login (menu bar › Open at Login).

```sh
cd macos/EsecVault && ./bundle.sh install   # ~/Applications/esec Vault.app
```

It finds `esec-vault` in `~/go/bin`, Homebrew or `PATH` (or
`ESEC_VAULT_BIN`).

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
esec-vault backup --push --remote r2    # snapshots live keys before uploading
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
working keyrings.

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
terminal session is needed. `daemon run` remains a foreground debugging tool.

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
session. Locking does not encrypt working keyring files; `keyring protect` does.
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
daemon; an external scheduler can run `esec-vault backup --push`.

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
files (mode 0600) are plain text unless protected: then they are encrypted
with this machine's cache key, kept in the OS keyring. `esec vault login`
protects them when the `esec` on your PATH is v0.9.0 or later; `esec vault
keyring protect --all` does it by hand, and `keyring unprotect` reverses it.
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
| Every project on this machine | `esec vault projects` |
| Check no key can be lost | `esec vault verify` |
| Share an environment with someone | `esec vault share dev --with LOGIN` |
| Stop sharing it, with a new key | `esec vault unshare dev --with LOGIN --rotate` |
| See who reads what, and what to seal again | `esec vault seal` |
| Register your YubiKeys | `esec vault security-keys add` |
| Guard an environment with your YubiKey | `esec vault guard enable --env prod` |
| Give CI its own key | `esec vault ci add NAME --env prod --github OWNER/REPO` |
| Every security key lost | `esec vault seal recover --all` |
| See which programs and agents asked for keys | `esec vault activity` |
| Prove the backup restores with the phrase | `esec vault drill` |
| Use guarded keys from another machine | `esec vault forward HOST` |
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
| Bring this machine up to date with the server | `esec vault sync` |
| List a project's machines | `esec vault machine list` |
| List groups | `esec vault group` |
| Add a person to a group | `esec vault group add acme/backend alice` |
| See a group's people, machines and what it reads | `esec vault group show acme/production` |
| Let machines waiting to join in | `esec vault group approve acme/production` |
| Sign changes made on the web pages | `esec vault changes` |
| Passkeys and server removals | `esec vault delegate` |
| On a machine: what am I, what do I read | `esec-vault machine whoami` |
| Open the keys sealed to you after `git pull` | `esec vault seal sync` |
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
| A machine says the group key or a project's keys were not sent yet | An admin's device seals them on its next sync: `esec vault sync`. `esec vault group show` says what is missing. |
| A machine says it reads nothing of a project | The group and the project both have to agree: `esec vault group set GROUP --project ORG/REPO --env ENV`, by an admin of each. |
| `dev` cannot find a file | Check the current directory. Use `-f env` for `.env.dev`. Secrets files are not searched for in parent folders. |
| No project file is found | Add `esec.toml` with `project = "org/repo"`, or run `esec vault project init org/repo`. The search stops at the Git root. |
| A child file uses the wrong project | For core esec, pass `--key-dir services/api` from the root. For broker commands, change into the component directory. |
| `--key-dir ../..` is rejected | Set `project_root=$(git rev-parse --show-toplevel)` and use `--key-dir "$project_root"`. |
| A correct public key still fails to decrypt | Check named key entries and `ESEC_*` overrides. Named environment entries have priority over public-key entries. |
| An environment already exists | Use `env list`. Use `project init PROJECT --env NAME --format env` to create a missing template with the existing named key. |
| An existing file has a different public key | Import its original private key. A new key cannot decrypt its old values. |
| Migration says the target keyring exists | Migration does not overwrite or merge that target. Keep both copies until you reconcile their keys. |
| The broker reports a missing key after an import | Run `esec vault unlock --ttl 4h` again to reload its key cache. |
| The broker reports `denied by policy` | Check the exact project ID and environment name. Run `daemon reload` after a policy edit. |
| `share` cannot share an unnamed key | `share` takes environment names. Use named environment keys for selective sharing. |
| A backup does not contain a repo-local key | Import the `.esec-keyring` first. Backups collect keys from the global store. |
| An upload is pending | Check `remote list` and `daemon logs`. Use `backup --push` to request an immediate upload. |
| A new clone has encrypted files but cannot decrypt | If you read the environment, `esec vault seal sync` opens its seal. Otherwise restore your personal backup, or ask a reader to run `esec vault share ENV --with LOGIN`. |

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


## Shared file preferences and encrypted example templates

esec and esec-vault share `~/.config/esec/config.toml` (honoring
`XDG_CONFIG_HOME`, `ESEC_VAULT_HOME`, or an explicit `ESEC_CONFIG` file).
For example:

```toml
default_format = "etoml"
[files]
patterns = [".{format}.{env}", "{env}.{format}"]
create = "{env}.{format}"
templates = ["example.{format}", ".{format}.example"]
```

Put public defaults and dummy placeholders in `example.etoml`, `example.ejson`
or `.env.example`. Omit the public key. `esec vault project init` and
`esec vault env add prod` insert the new public key and encrypt defaults in
memory before creating the file. The configured `default_format` applies to
both commands; `-f` or `ESEC_FORMAT` overrides it. Filenames use the literal
environment argument: the config above creates `prod.etoml`. Templates are
parsed and re-serialized, so comments and formatting are not preserved.
Ambiguous templates and existing mismatched files fail without overwriting.

```sh
esec vault env add prod -f etoml
esec run prod -- ./server
esec vault run prod -- ./server
```

Both core `run` and broker-based `vault run` support TOML scalar values and
nested tables, using `DATABASE__HOST` for `database.host`. Environment names
match exactly: `prod` and `production`, `dev` and
`development`, and `stage` and `staging` are different environments.
Remove any existing `[aliases]` section from the shared config; aliases
are no longer supported. Discovery fails on zero or multiple matches;
use a filename or `--format` to narrow it. Files are not searched recursively except through explicitly configured relative paths.
Use `--no-template` for key-only environment creation. If `env add --project`
runs outside that project's repository without `--dir`, it creates only the
key and explains how to specify a destination.

Development note: the local, ignored `go.work` links this checkout to the
sibling `../esec` module for the new shared config/discovery API. Release that
core API and update the required esec version in `go.mod` before publishing
vault; standalone builds need the released dependency.

Inside an `esec vault forward` session, the same guarded `esec decrypt` and
`esec run` commands use the forwarded broker. Only ciphertext and the sealed
key are sent to it; inspection reports local metadata and remote approval
requirements without asking the remote machine to open a key.
