# esec-vault: identity, backup and sharing for esec keyrings

**esec-vault** is the companion CLI to [esec](https://github.com/mscno/esec). esec encrypts
secrets files with per-project, per-environment NaCl keypairs; **esec-vault manages the private
keys**: where they live, how they're backed up, how you recover them, how teammates get them,
and how agents get scoped access without ever holding key material.

The `esec` core stays slim and auditable. Everything here treats esec as a library — all crypto
primitives (NaCl box, sealed boxes, HKDF) come from `github.com/mscno/esec/pkg/crypto`.

```
mnemonic (24-word BIP39 recovery phrase, cold storage)
  └─HKDF→ master keypair (deterministic, cold)
       └─seals→ identity keypair (random; lives in your OS keyring)
                     └─seals→ vault blob (encrypted backup of all project keyrings)
```

## Installation

```sh
go install github.com/mscno/esec-vault/cmd/esec-vault@latest
```

If `esec` is also installed, every `esec-vault ...` command is reachable as `esec vault ...`
(git-style subcommand passthrough).

## Quick start

```sh
# 1. Create your identity — prints a 24-word recovery phrase. Write it down.
esec-vault identity init

# 2. Move a repo's keyring out of the working tree into the global store
#    (~/.config/esec/keyrings/<org>_<repo>.keyring)
cd your/project
esec-vault keyring migrate --delete-local

# 3. Back up every keyring, sealed to your identity key
esec-vault backup
```

Core esec decrypts as usual — its key lookup now falls back to the global store
(`ESEC_KEYRING_DIR`, project-keyed via the committed `.esec-project` file).

## Recovery

On a fresh machine, with your recovery phrase and a copy of the vault blob
(`~/.config/esec/vault.esec` — it's ciphertext, so you can store it anywhere, including a
private git repo):

```sh
esec-vault recover                 # mnemonic -> identity -> restore keyrings
```

The identity keypair can be rotated (`esec-vault identity rotate`) without changing the
recovery phrase; old sealed blobs must then be re-created (`backup`, and teammates re-share).

## The broker: scoped secret access for agents

`esec-vault agent` is an ssh-agent-style daemon: it holds project keys in memory and answers
policy-checked decryption requests over a unix socket. Key material never crosses the socket —
clients receive only decrypted secret *values*, per policy.

```sh
# ~/.config/esec/policy.toml
default = "deny"

[[rule]]                      # agents may decrypt dev environments
project = "*"
env = ["dev", "dev-agent"]
action = "allow"

[[rule]]                      # prod needs an interactive approval
project = "*"
env = ["prod"]
action = "ask"
```

```sh
esec-vault agent --ttl 4h &          # start the broker
esec-vault run dev -- npm run dev    # child gets decrypted env vars
esec-vault approve <id>              # approve an "ask" request
esec-vault agent stop                # revoke everything
```

Every decision is appended to `~/.config/esec/audit.log`. Because the socket authenticates
peers by uid (Linux `SO_PEERCRED`, macOS `LOCAL_PEERCRED`), agents running as a different
user or in a container can be given only socket access — no keyring files exist in their
filesystem view at all.

## Team sharing (no server)

Members prove ownership of their esec identity key by signing it with their GitHub-registered
SSH key; verification fetches `github.com/<login>.keys`. Pins are trust-on-first-use.

```sh
# New member, from their machine, in the repo:
esec-vault members prove --login alice      # writes .esec/members/alice.proof -> open a PR

# Existing member, after verifying the proof and fingerprint:
esec-vault members trust alice

# Share the project keys (writes committed, per-member sealed blobs):
esec-vault share --to alice                 # -> .esec/vault/alice.esec

# Alice, after cloning/pulling:
esec-vault sync                             # opens her blob into her global keyring store
```

Offboarding: delete the member's blob, rotate the affected environment keys, re-share.

## Layout

```
~/.config/esec/                      # ESEC_VAULT_HOME overrides
  keyrings/<org>_<repo>.keyring      # global keyring store (0600)
  identity.esec                      # identity key sealed to the master key (0600)
  vault.esec                         # all keyrings sealed to the identity key (0600)
  agent.sock, agent.pid, audit.log   # broker
  policy.toml                        # broker policy
  trusted.toml                       # TOFU member pins
```

## Security notes

- The 24-word recovery phrase is the only cold-recovery secret. Anyone with it controls your
  identity. Store it offline.
- All vault/share blobs are NaCl sealed boxes; the Poly1305 tag plus an inner SHA-256 detects
  tampering.
- The broker is a decryption oracle, not a key store: `deny` by default, `ask` requires
  interactive approval, and nothing on the socket exposes private keys.
- `esec-vault` never runs git mutations — it writes files; you commit and push.
