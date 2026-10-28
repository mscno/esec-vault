# Sealed keys: keys live with the data, people never handle them

Status: built. It replaces the shared guard identity of [guard.md](guard.md);
the dialog, presence and forwarding described there remain.

## What this is for

1. **No key in anyone's head or clipboard.** Nobody types, pastes or
   remembers a private key, a public key or a YubiKey recipient. People are
   GitHub users; security keys are things you plug in and name.
2. **Share with a GitHub username**, pinned by its numeric id, so a renamed
   or re-registered login never inherits access.
3. **No key is ever lost.** A repository and your recovery phrase decrypt
   every secret in it, in every commit, with no server, offline.
4. **Prod needs a person.** Guarded environments open only with a touch of
   one of the reader's security keys; agents cannot touch.
5. **The server and the Mac app do the work.** Sync, invitations, sealing,
   reminders and approvals happen in the background or with one click; the
   command line can do everything too, for agents and scripts.
6. **Nothing breaks without the server.** Reading needs only the repository
   and an identity; the server makes sharing and new machines effortless.

## The idea in one paragraph

Each environment keeps its key pair. Values are encrypted to the public key,
so anyone (an agent too) can write one without being able to read the file,
and unchanged values keep their ciphertext, as today. New: the environment's
private key is committed next to the files, in `.esec/<env>.age`, a plain
age file encrypted to the environment's readers: people (by GitHub id),
their security keys for guarded environments, groups, machines, and always a
recovery key. The server is a directory that says, with signatures it cannot
forge, which public keys belong to which person, group or machine; the tools
seal to those. Whoever can open the file has the key; nobody needs a copy
synced from anywhere.

## What it looks like in a repository

```toml
# esec.toml
project = "acme/store"

[env.dev]
key = "age1qz…"                          # values are encrypted to this
readers = ["mads (gh:583231)", "group acme/backend"]

[env.prod]
key = "age1x7…"
guard = "touch"                          # people read it with a security key
readers = ["mads (gh:583231)", "alice (gh:91022)", "machine deploy"]
```

```
.esec/dev.age        age file: the dev private key, sealed to its readers + recovery
.esec/prod.age       the same for prod
.esec/seals.toml     signed record of each seal: readers resolved to which
                     public keys, by whom, when (machine-written, for review)
```

- `readers` is written by tools and read by people. The login is display
  only; the id in parentheses is what counts. If `gh:91022` is now called
  `alice2`, every view says so; if someone else takes the name `alice`,
  nothing changes.
- `.esec/*.age` are standard age files: `age -d -i …` opens them with no
  esec at all (the escape hatch, and the cold-recovery path).
- `.esec/seals.toml` is signed by a reader of that environment (their user
  key from their chain). `secrets lint`, the pre-commit hook and CI check it,
  so a pull request that swaps prod's public key or adds a reader is caught
  unless one of prod's readers signed it.

## Who a seal is made for

Each reader resolves, through signed chains the server serves but cannot
forge, to age recipients:

| Reader | Unguarded environment | Guarded (`touch`, `session`) |
|---|---|---|
| A person (`gh:<id>`) | their user key (U), on all their devices | each of their registered security keys (YubiKey, Secure Enclave) |
| A group | the group key, which members get from the server | the members' security keys |
| A machine / workload | its machine key, or its KMS-wrapped key | the same: machines have no fingers |
| Recovery (always) | the project owner's recovery key (`MasterPub`), or each org admin's | the same |

The recovery key is derived from the 24 words and never stored, so it opens
seals only in a cold recovery. Every seal includes one; the hook refuses a
commit whose seal lacks it, which turns "no key is ever lost" into something
checked before every commit instead of something hoped for.

A person who has no security key registered cannot be a reader of a guarded
environment; tools say so ("alice has no security key yet: she gets prod
once she adds one") and seal her in when she does.

## What already exists, and what is new

Already there, reused as is:

- Accounts are `gh:<numeric id>`; the login is refreshed on each sign-in;
  lookups by login check the id (`GET /v1/users?login=`).
- Each person has a signed chain: user key U (X25519 + Ed25519), recovery
  key (`MasterPub`), devices, delegates (passkeys). Clients verify it.
- Groups with their own X25519 key, distributed to members; machines,
  OIDC-bound CI, KMS workloads.
- Device approval (from another device, the phrase, or an SSH key), web
  changes signed by devices or phone passkeys, daemon dialogs.

New:

- **Security keys in the chain**: a `hwkey_add` / `hwkey_remove` link with
  the age recipient, the YubiKey serial and a nickname, signed by a device.
  Everyone who shares with you learns your keys from your chain; you never
  copy a recipient.
- **Sealing** (`internal/seal`): resolve readers, seal, sign `seals.toml`,
  open (with U, a security key, a group key, a machine key or the recovery
  key).
- **A reseal queue** in the daemon: when a chain changes (a new security
  key, a group member, a reader added from the web), it works out which
  environments in which checkouts need sealing again and does it, or asks.
- **Invitations**: share with a GitHub user who has no account yet; they are
  sealed in when they sign up.

## How each task feels

**A new machine.** `esec vault setup` → sign in with GitHub → approve on
another device or your phone (or type the phrase). Done: every checkout
opens, dev without a prompt, prod with a touch. No key sync, nothing to wait
for, nothing to conflict.

**A new project.** `esec vault project init` or the app's New Project: dev
sealed to you, prod sealed to your security keys, both to your recovery key,
hook installed. Commit.

**A new YubiKey.** Plug it in. The app: "New YubiKey (serial 2234…). Use it
for esec?" If it has no age key yet it walks you through making one (PIN,
touch always) in Terminal. You name it ("spare, in the safe"); it goes into
your chain. Then: "Reseal 14 guarded environments in 9 repositories: touch
14 times, or enter your recovery phrase once." The reseal runs in the
background; each repository gets the change in its working tree, with a
one-click commit.

**A lost YubiKey.** App › Security keys › Remove. Reseal as above, then the
app lists the guarded environments whose old seals in git history the lost
key (with its PIN) still opens, with Rotate next to each.

**Share.** `esec vault share prod --with alice`, or in the app: type a GitHub
username, pick from the server's lookup (avatar, name, id). If alice has an
account and a security key, she is sealed in now; if not, she gets an
invitation and is sealed in when ready (automatically for unguarded
environments; for guarded ones the app asks you for the touch). The change is
a diff in `esec.toml` and `.esec/`, reviewed like code.

**Unshare.** Removing a reader reseals and offers to rotate (she had the key;
removal alone does not take it back): new key, values re-encrypted, deploys
listed with what still runs the old key.

**CI and deploys.** `esec vault machine add deploy --github-actions
acme/store` (or Fly, or a KMS workload): the machine becomes a reader; the
job runs `esec run prod -- …` with only its machine identity. No per-project
secret to paste into CI.

**Deploys and prod agents: three ways to give a running thing its key.**
Seals do not replace the network; they sit beside it. None of them involves
a touch: a guard is a property of reading on a person's own machine, so
`guard = "touch"` asks the developer's YubiKey, never a deployed service or
a prod agent, which read with what they hold.

| Where it runs holds | It gets the key | After a rotation |
|---|---|---|
| The environment's key, `ESEC_PRIVATE_KEY_PROD` (a root secret) | directly; the file is on disk or embedded | the secret must be replaced |
| An age identity, `ESEC_AGE_IDENTITY` (`ci add`) | opens `.esec/prod.age`, in the checkout or embedded in the binary beside the file (`//go:embed esec.toml .env.prod .esec/prod.age`) | nothing changes: the next build carries the new seal |
| A machine key (`ESEC_VAULT_MACHINE_KEY`), an OIDC token (GitHub Actions, Fly.io), or both; a KMS-bound workload | `esec-vault machine run` asks the vault server, which returns the key sealed to that machine or group; the client checks it against the project chain | nothing changes: `env rotate` sends the new key |

The server's copies are sent by a project admin's device. A key the
keyring does not keep (every guarded key) is opened from the checkout for
that, on the admin's machine: one touch per command when a machine or
group is first given a guarded key (that is a read of prod on a dev
machine), none on rotation, which sends the key it just made. The
background service sends what it can without a touch and notifies about the
rest (`esec vault access sync`). The machines themselves never wait for
anyone.

**An agent.** Unchanged: it writes values with the public key, runs with dev,
asks the background service for prod (dialog, touch). New: it can run
`esec vault seal sync` and `setup --check --json`, and never sees a key
string.

## The server's and the app's part

| | Server | Mac app |
|---|---|---|
| Directory | people by GitHub id, their keys, groups, machines; GitHub lookups for invitations | people picker with avatars; your security keys with nicknames, last used |
| Changes | pushes chain changes to daemons; holds invitations | reseal queue with Apply / Commit; notifications |
| Approvals | phone passkey signer for web changes | dialogs for touches and signing |
| Health | which seals of a project are stale; who has not opened prod in months | per-repo seal state; "keys safe" from the repos, not from backups |
| Activity | across your machines and teammates (opt-in) | per machine, as today |

Without the server: reading works from repository plus identity; sharing
needs public keys typed by hand (`--recipient age1…`), the fallback for air
gaps.

## What happens to the code

- **esec (core):** keeps the file format and `run`. Gains opening
  `.esec/<env>.age` with an age identity (U from the vault, a machine
  identity, a plugin), so CI needs only `esec`.
- **esec-vault:** keeps identity, devices, the broker and guard dialogs, the
  checkout list, setup, hooks, the app, teams. Loses: environment-key sync
  as the source of truth (the keyring becomes a cache of opened keys), the
  shared guard identity (each guarded environment is sealed straight to
  security keys), most of `verify` (seals are checked at commit time; a drill
  opens seals with the phrase).
- **Server:** keeps everything; grants for projects in git are replaced by
  seals in the repository, and stay for groups and machines that do not read
  a repository.

## Decisions

1. **One touch per environment** (seal guarded environments straight to
   security keys) rather than one guard identity per person. A stolen touch
   then opens one environment, not all; the price is a touch per environment
   when adding or removing a security key (or the phrase, once).
2. **`.esec/<env>.age` files**, not a blob inside `esec.toml`: clean diffs,
   standard age files, `esec.toml` stays readable.
3. **Readers are signed in `.esec/seals.toml`**, so lint, hooks and CI catch
   a swapped key or an unsigned new reader.
4. **No backwards compatibility**: a migration command seals every
   environment of every known checkout from today's keyrings.

## Order of work

1. `internal/seal` and `.esec/` files; the recovery key in every seal; the
   hook enforcing it; `project init`, `env add`, `env rotate` seal; core esec
   opens seals; migration from keyrings. Keys are never lost from here on.
2. Security keys in the chain; YubiKey detection, provisioning and naming in
   the daemon and app; guarded environments sealed to them; the guard
   identity removed.
3. Readers by GitHub id, `share` / `unshare`, invitations, the reseal queue,
   the app's People and Security keys views, signed `seals.toml` checks.
4. Machines and groups as readers; CI with `esec` alone; SOPS export if a
   deploy target needs it.
