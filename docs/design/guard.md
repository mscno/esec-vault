# The guard, the project file, and keys that cannot be lost

This note records why esec-vault manages many independent projects the way
it does: a committed `esec.toml` per project, private keys that are only
ever added and always stored twice, a hardware guard for the keys agents
must never read, and a registry of checkouts per machine. The security model
of the vault server is in [vault-server.md](vault-server.md).

## Goals

1. Many independent projects, each with its own key per environment. No
   key serves two projects.
2. Secrets live in git, encrypted. Private keys never do.
3. No key is ever lost, with no manual key handling across machines and
   backups.
4. Prod keys live on the owner's machines, but every read needs the owner
   present: a physical touch. Agents running as the owner cannot read them.
5. Agents on many machines can work on the projects: run them, add values,
   rotate keys, without seeing values or holding keys above dev.

## Threat model for agents

An agent runs as the person. It can read every file the person can, run
every program, talk to every socket the person's processes can, edit the
repository (including `esec.toml`) and the person's configuration. It cannot
touch a YubiKey and cannot see the screen unless given that.

So nothing that must stay from an agent can rest on files, sockets or
software checks alone. It rests on the touch. Everything else is defence in
depth or attribution.

## The project file: esec.toml

`esec.toml` replaced `.esec-project` (no compatibility: there was no
release with many users of it). It names the project, how its files are
named, and each environment with its current public key and guard:

```toml
project = "acme/store"

[files]
format = "env"
name = ".env.{env}"

[env.prod]
key = "9a2e…"
guard = "touch"
```

`[files]` is applied on top of the per-machine `~/.config/esec/config.toml`
(`config.LoadDir`), so every machine and every agent names and finds a
project's files the same way.

`key` and `guard` are claims, not trust: an agent can edit them. The keyring
and the guarded payload are the authority. `lint` and `verify` compare files
with `esec.toml` and with the keyring; the guard level that decides caching
is inside the encryption (below), and wrapping always uses the guard identity
as opened, never a recipient string from a file.

## Keys are only ever added

A private key is filed under its public key, `ESEC_PRIVATE_KEY_<PUB>`. Names
(`ESEC_PRIVATE_KEY_PROD`) only point at keys and may change. The keystore
enforces it on every write:

- a named key without its public-key entry gets one (`fileKeys`);
- a write that would change or remove a public-key or guarded entry fails
  (`checkKept`), except `WriteGuarded`, where a clear key may give way to its
  guarded form.

Sync's three-way merge already never deleted; with this, a conflict on a
name can no longer lose a key either, and sync never pulls back the clear
copy of a key this device keeps guarded.

## Stored twice before use

`project init`, `env add` and `env rotate` store a new key on the vault
server (or the default backup destination) and wait, before any file is
encrypted to it. If that fails, nothing is encrypted to the new key:
`project init` and `env add` stop and can be run again; `env rotate` points
the environment back at its old key and leaves files as they were (the new
key stays filed, unused). With no second place configured at all, they warn
(`doctor` reports it); `--offline` skips the wait on purpose.

## verify and drill

`verify` collects every public key used by a secrets file in every known
checkout and in every revision of their git history (`git rev-list --all
--objects`, then `git cat-file --batch` on secrets files only). For each key
it checks where the private key is held: this device, the vault server's
vault (downloaded and opened, signature checked, not applied), the newest
backup. Problems: held nowhere (lost), not here, held in one place only,
used by two projects. The daemon runs it daily and notifies only on
problems; the result is kept in `verify.json` for `doctor` and the Mac app.

`drill` downloads the newest backup and opens it with the recovery phrase
alone, as a cold recovery would, then checks it holds every key the
checkouts use, and that the recovery key opens the guard and every guarded
key.

## The guard

Built on age, so it is standard and works with the YubiKeys people already
use with rage:

```
YubiKey A (touch=always) ─┐
YubiKey B (spare)        ─┼─ age recipients ─► guard identity (age X25519)
recovery key (phrase)    ─┘                        │
                                                   ▼
                     ESEC_GUARD_<PUB> = age(guard identity, {project, env, level, private})
```

- **Two levels.** Holders wrap one guard identity; keys are wrapped to the
  guard identity. Changing holders is one touch, not one per key.
- **The recovery holder** is the X25519 key the 24-word phrase already
  derives (`DeriveMaster`), written as an age recipient. Its private half is
  stored nowhere, so it opens the guard only in a cold recovery.
- **Storage.** The guard is in the default keyring (`ESEC_GUARD_IDENTITY`,
  `_RECIPIENT`, `_HOLDERS`); guarded keys are `ESEC_GUARD_<PUB>` with
  `ESEC_GUARD_ENV_<ENV>` naming an environment's. All ciphertext, so they
  sync and back up through the existing paths unchanged.
- **The payload** carries project, environment and level inside the
  encryption, and opening checks the key belongs to its public key. A keyring
  edit cannot move a key to another project, or turn `touch` into `session`.
- **Creating** a guarded key opens the guard (one touch) and wraps to the
  identity as opened, so a planted recipient cannot capture new keys.

### Reading

`esec vault run` asks the broker in the background service. For a guarded
key the broker skips the policy file's default (a rule that denies still
denies), records `ask` in the audit log, and the daemon's guarder:

1. shows a dialog with the project, environment, file, the asking programs
   (`zsh ▸ claude ▸ esec-vault`, from the peer pid), the agent session label
   and, when forwarded, the machine;
2. only after **Allow** asks the plugin, and the YubiKey blinks for a touch;
3. opens the key, and for `session` keeps it in memory until the broker locks
   or its session ends; a `touch` key is dropped after the read.

One dialog and one touch at a time. The dialog is the defence against a
confused deputy: a YubiKey blinking with no esec dialog is not to be touched.
It is not the boundary; the touch is.

With only software identities (`ESEC_VAULT_GUARD_IDENTITIES` naming
`AGE-SECRET-KEY-1` lines, used in tests) there is no dialog: whoever can read
that file opens the guard without esec anyway.

### Forwarding

`esec vault forward HOST` runs ssh with `-R` from a random socket on the
remote machine to `run/forward.sock`, a second broker that:

- serves guarded keys only (each read is then one the person sees and
  touches), refusing unguarded ones: a machine should have its own key;
- takes the encrypted file in the request (the path is the remote's) and the
  host name, shown in the dialog.

### What it does not protect

- Values of a run the person allowed: the command gets them.
- Keys guarded after the fact are as safe as the oldest backup holding them
  in software form. Rotate once for full protection.
- A `session` key while open: a same-user process can ask the broker.
- A stolen YubiKey with its PIN opens old copies of the guard in backups;
  remove the holder and rotate the guarded keys.

## Agents on many machines

Devices (the person's Macs) hold the user key and sign. Agent hosts are
machines in a group that reads dev (`group token`), never devices. Agents
get values only as a running command's environment, masked in its output
(`run --mask`, `ESEC_VAULT_MASK`); make values with `secrets set --generate`
or ask a person for them (`secrets request`, a desktop dialog); and label
their reads (`ESEC_VAULT_SESSION`) for the audit log and the dialog.

## The checkout registry

`~/.config/esec/projects.toml` lists checkouts: a project's global id and a
directory on this machine, several per project for clones and worktrees.
Commands that find an `esec.toml` add theirs; `projects scan` walks a
directory. `projects`, `verify` and the Mac app build on it. It is local and
holds no secret.

## The Mac app

A SwiftUI menu bar app (`macos/EsecVault`) over `esec-vault ... --json`: it
shows the registry, environments, guard state, secrets files and key health,
and runs the same commands as actions. It never reads values, so it adds no
place values could leak from.
