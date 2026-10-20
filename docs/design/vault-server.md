# Design: esec vault server, device sync, and encrypted key cache

Status: phases 1–4 implemented: devices and sync (§1–§13), shared projects
(§14) and machines (§15). Passkey approval is sketched at the end. The
section "Changes made during implementation" lists where the code differs
from the first draft.

## Goal

On a fresh machine:

```sh
go install github.com/mscno/esec/cmd/esec@latest
go install github.com/mscno/esec-vault/cmd/esec-vault@latest
esec vault login https://vault.example.com
# approve from the laptop, or use the forwarded SSH agent, or the recovery phrase
cd ~/projects/store && esec run dev -f env -- npm run dev
```

No rclone, S3 credentials, or `remote.toml` on the new machine.

## Principles

1. **Secret values stay in git**, encrypted to the environment's public key, as
   they are today.
2. **The server only syncs keys**, and only as ciphertext. Signing in with
   GitHub lets a client *download* ciphertext. It never lets the client
   *decrypt* it.
3. **Decryption reaches a new device** in one of three ways: an existing device
   approves it, the forwarded SSH agent unlocks it, or the recovery phrase
   restores it.
4. **The server is not trusted for integrity.** Every change to the set of
   devices or keys is signed and checked by clients. A compromised server can
   withhold data or refuse service. It cannot read keys, add a device, or swap
   a public key.
5. **Keys change rarely**, so sync is a versioned object with compare-and-swap.
   No CRDTs are needed.

## Decisions taken

| Question | Decision |
|---|---|
| How does a new machine get keys? | Approval from another device. The recovery phrase is the fallback. An SSH-agent unlock slot is optional (§8). The server never holds a key that unlocks anything on its own. |
| How does the CLI sign in? | Our own OAuth device authorization grant (RFC 8628), with a Crockford base32 `XXXX-XXXX` user code that is always typed in the browser (no prefilled link). GitHub is the only identity provider. The server issues its own sessions; GitHub tokens are used once and thrown away. |
| Email sign-in? | Not in v1. It adds SMTP to run, and anyone who takes over the mailbox could sign in. The identity-provider interface leaves room to add it later. |
| Local key storage | Core esec reads a keyring file encrypted under a per-device cache key held in the OS secret store. Plaintext keyrings keep working (§7). |

## 1. Keys

| Key | Type | Where the private half lives | Purpose |
|---|---|---|---|
| Master key | X25519, derived from phrase | Nowhere (re-derived from phrase) | Unwraps `identity.esec`; second seal on vault blobs. Unchanged. |
| User key **U** (version *n*) | X25519 (`U.enc`) + **new** Ed25519 (`U.sign`) | Each device's secret store; master-wrapped on the server | Opens the personal vault blob; signs the user's chain. `U.enc` is today's identity key. |
| Device key **D** | X25519 (`D.enc`) + Ed25519 (`D.sign`) | That device's secret store only | Receives U ("device box"); signs API requests. |
| Cache key **C** | 32-byte symmetric | That device's secret store only | Encrypts local keyring files (§7). |
| Environment keys | X25519 (esec) | Inside vault blob; local cache | Unchanged. |

`identity.esec` moves to format v3: the master-wrapped payload adds the `U.sign`
private key. The header already carries the master public key, so a device that
holds U can upgrade the file without the recovery phrase.

### Signed envelopes

Every signed object is sent as the exact bytes that were signed. Nothing is
re-encoded into a canonical form:

```json
{"v":1,"kind":"chain-link","body":"<base64 of JSON bytes>","sigs":[{"key":"<hex Ed25519 public key>","sig":"<base64>"}]}
```

Each signature covers `"esec-vault/" + kind + "/v1\n" + body`. Each kind has
its own prefix, so a signature made for one kind cannot be passed off as
another.

An envelope can carry several signatures: `ukey_rotate` is signed by the old
and the new user key. The envelope hash covers the kind and body only. The
chain's `prev` links therefore refer to content, not to a particular set of
signatures.

### Fingerprint words

A fingerprint shown to people is `SHA-256(keys...)` shown as BIP39 English
words, 11 bits each. BIP39 is already a dependency.

| Fingerprint | Words | Bits | Why that many |
|---|---|---|---|
| Device | 6 | 66 | Compared once, while a device waits up to 15 minutes. |
| Account key | 8 | 88 | Never changes, so an attacker could search for a matching chain root offline for a long time. |

## 2. User chain

A user's chain is an append-only, hash-linked list of signed links. It is the
only authority for which U version is current and which devices are trusted.

```json
{"seq":7,"prev":"<sha256 of link 6 envelope>","ctime":"…","type":"device_add",
 "user":"gh:1234567","ukey_version":2,"body":{…}}
```

| Type | Signed by | Body |
|---|---|---|
| `init` | U(1), and the master signing key over the root statement | `U.enc`, `U.sign` public keys, master public key, master signing public key, root signature |
| `device_add` | current U; the body embeds a `device-proof` envelope signed by the new D (proves the device holds D and binds it to this user) | device, proof, method: `approval\|recovery\|ssh_agent\|first`, approving device id or slot id |
| `device_revoke` | current U | device id, reason |
| `device_rename` | current U | device id, new name |
| `ukey_rotate` | old U **and** new U | new public keys, list of surviving devices |
| `agent_slot_add` / `agent_slot_remove` | current U | slot id, SSH key fingerprint, expiry |

Rules every client enforces:

- Verify from `seq 1`. Cache the verified head as `(seq, hash)` in
  `~/.config/esec/account.toml`. Reject any head with a lower `seq`, or the
  same `seq` with a different hash (fork or rollback).
- A device whose latest link is `device_revoke` is untrusted. So is a device
  that was not carried over by a `ukey_rotate`.
- The server verifies too, but only to reject bad data early. Clients never
  rely on the server's check.
- The **account key** words come from the hash of the first link. They stay
  the same across user-key rotations and are the same on every device.

Users are keyed by numeric GitHub user ID, never login. A login can be renamed
and later claimed by someone else.

## 3. Sign-in and sessions

### Device authorization grant

```
CLI                                   Server                       Browser (any machine)
 | POST /v1/auth/device               |                             |
 |  {name, platform, D.enc, D.sign}   |                             |
 |<- device_code, user_code K7QM-2XDP |                             |
 |   verification_uri                 |                             |
 | print code + link; poll /token  -->|                             |
 |                                    |<-- GET /device, code typed   |
 |                                    |    GitHub OAuth (if needed)  |
 |                                    |--> confirm page: code, device name,
 |                                    |    platform, requesting IP
 |                                    |<-- POST confirm (CSRF token) |
 |<- session (status: pending|active) |                             |
```

- User codes use Crockford base32 (no I, L, O, U): 8 characters, 40 bits. They
  expire after 10 minutes. Wrong codes are limited per address and per
  signed-in user (see "Rate limits"). Input is normalized: case-folded, `O→0`,
  `I/L→1`, dashes and spaces removed.
- **A waiting device's fingerprint is shown only on that device.** No web
  page, notification or CLI listing shows it, so the words typed into
  `devices approve` can only come from the new machine's own screen.
- **The code is always typed.** The server never issues a link with the code
  in it, and the page ignores a `?code=` parameter (RFC 8628 §5.4). A link
  someone mails you therefore cannot carry their code; you would have to type
  a code you did not see in your own terminal.
- The device keys are registered with the device code, so a session is bound
  to a device key from the start.
- The polling interval is 5 seconds. Polling faster returns `slow_down`.
- **Only allowlisted GitHub accounts can sign in.** Without a list, anyone with
  a GitHub account could create an account on the server. They could not
  decrypt anything, but they could store data and create devices. The list
  starts with one entry, the owner: `53101343` (`mscno`). See §10 for the
  configuration.
- **The list uses GitHub's numeric user ID, never the username.** GitHub lets
  people rename their accounts, and after a rename someone else can register
  the old name. A list entry of `mscno` would let that stranger in. The
  numeric ID never changes and is never reused. To find it, run
  `gh api user --jq .id`.

### Session lifecycle

- A device that has never been approved gets a **pending** session. It learns
  nothing about an existing account: not the chain, not the wrapped
  identity, not the agent slots. It may only:
  - read its own status and the account's two public recovery keys;
  - create the account when none exists;
  - prove the recovery phrase (a signature by the phrase-derived master
    signing key over its device id and the time, `POST /v1/recovery`) to get
    the chain and the wrapped identity;
  - prove an SSH key (an SSHSIG in its own namespace over its device id and
    the time, `POST /v1/agent-slots/unlock`) to get the chain and that key's
    slot;
  - post a self-signed `device_add` link.

  A device signed in with a phished code therefore learns nothing and can
  do nothing until someone approves it, which requires its own fingerprint
  words.
- After approval the same session becomes **active**. No second sign-in is
  needed.
- The session token is opaque and checked against SQLite. **Every request is
  also signed with `D.sign`**:

  ```
  Esec-Signature: sig over method, path, sha256(body), timestamp, nonce
  ```

  The server allows ±60 seconds of clock skew and remembers nonces for
  5 minutes. A token copied off the disk is useless without the device key.
- Sessions expire after 30 days idle or 90 days total (configurable). When one
  expires, `esec vault login` runs the device code flow again. The device is
  already trusted, so it is **not re-approved**. Signing in again only
  re-proves the GitHub account.
- Revoking a device ends its sessions immediately.

## 4. Adding a device

### Approval (default)

```
vm$ esec vault login https://vault.example.com
  Open https://vault.example.com/device and enter K7QM-2XDP
  ✓ Signed in as mscno (GitHub 1234567)
  New device "hetzner-3"  fingerprint: tiger-lamp-orbit-maple-cream-thumb
  Waiting for approval. On a trusted device run: esec vault devices approve
  Other options: --ssh-agent, --recover

laptop$ esec vault devices approve
  Pending: hetzner-3  linux/amd64  from 203.0.113.7  40s ago
  Account key: river-cloud-anchor-plume-…
  Type the fingerprint words shown on the new device to approve it: tiger lamp orbit maple cream thumb

vm$ Account key: river-cloud-anchor-plume-…
  Is this the account key your other devices show? [y/N] y
  ✓ Approved by macbook.
  ✓ Synced 4 projects, 11 environments.
```

The approving device does the following:

1. Fetch the pending device's self-signed proof and verify it. Compute the
   fingerprint words locally from the proof's keys, but do **not** show them:
   the person approving types the words shown on the new device, and the
   approval proceeds only if they match. No web page, notification or CLI
   listing shows a waiting device's words, so the typed words can only come
   from the new machine's own screen.
2. If they match, append `device_add` (signed by U), upload
   `device_box = SealAnonymous(U.enc.priv ‖ U.sign.priv ‖ ukey_version, D.enc)`,
   and post the approval.

The new device does the following:

1. Open the device box and derive U's public keys.
2. Check the chain head: U must be the current version, and its own
   `device_add` must be present and signed by that U.
3. Countersign the link with `D.sign`, so the link carries both signatures, and
   start syncing.

**A brand-new device must confirm the account key.** A malicious server
could send it a fake U together with a fake chain, sealed to the device's
public `D.enc`. So a device with no pinned chain shows the account key words
and asks for confirmation **before** it installs any key or syncs anything.
`login --account-key WORDS` checks them without a prompt.

The other two paths authenticate the account without this check:
- **SSH agent:** the slot box opens only under a key derived from the agent's
  signature, which the server never sees.
- **Recovery phrase:** the phrase derives the master signing key, which must
  have signed the chain root (see below).

**Recovery authenticates the root.** The master X25519 public key is not
secret: the server sees it in the chain and in identity headers. So the phrase
also derives an Ed25519 **master signing key**
(`HKDF(stretched seed, "esec-master-sign-v1")`). It signs
`"esec-vault root v1\n" + U.enc + "\n" + U.sign` for the account's first user
key, and the `init` link carries that signature.

A recovering device derives the signing key itself and requires both master
keys to match the chain. A server cannot build a chain around the user's
master public key with its own user key.

`identity init`, `identity recover` and `identity rotate` already hold the
phrase, so they store this authorization in `root-auth.json` (public data).
An identity from an older version gets it at account creation, which then
asks for the phrase once.

**An account created by someone else is refused.** If the server's chain
names a different master key than this machine's identity, login stops. That
covers an account created by someone who took over the GitHub account before
the user's first login. `--replace-identity` overrides the check for a
deliberate identity change.
Pending devices expire after 15 minutes.

### Recovery phrase

`esec vault login --recover` signs in, then asks for the phrase:

1. Derive the master key and fetch the master-wrapped `identity.esec` from the
   server.
2. Unwrap U and check it against the chain head.
3. Append a self-signed `device_add` with `method: recovery`.

### First device (account creation)

On a machine that already has an identity, the first `esec vault login` does
the following:

1. Upgrade `identity.esec` to v3 by generating `U.sign`. The upgrade itself does
   **not** ask for the recovery phrase. Creating the account needs the
   phrase's root authorization (§4), which identities from `identity init`
   already have. The reasons the upgrade does not need it:

   ```
   24 words ──► master key ──► opens identity.esec ──► U
   ```

   - Today's identity key can encrypt but cannot sign. The chain needs
     signatures, so U gains an Ed25519 half. `identity.esec` must then be
     written again, still sealed so that only the master key can open it.
   - Sealing needs only the master **public** key. Opening needs the
     **private** key, which only the phrase can derive.
   - The v2 header already stores `MasterPublic`. The device has U, so it can
     re-seal U plus `U.sign` to that public key without the phrase, and the
     phrase stays the only way to open the file.
2. Post `init` and `device_add method: first`.
3. Upload the master-wrapped identity and the current vault blob.

If you sign in from a machine with no identity, it offers `identity init` or
`--recover`.

## 5. Personal vault sync

- **The object** is today's `ESECVLT` v2 blob. It is sealed to U and to the
  master key, and it has a monotonic generation counter inside. It holds the
  keyrings and the master-wrapped identity. It does not hold local settings
  (policy, trust pins, remote config), which differ between machines. The
  server stores a version history, keeping the last 50 versions by default.
- **Every upload is signed by U.** A sealed box can be created by anyone who
  knows U's public key, the server included. Without a signature, a server
  could plant its own environment keys. The signature covers
  `"esec-vault/vault/v1\n" + user + "\n" + sha256(blob)`. The server checks it
  against the chain's current key, and every client checks it again before
  opening the blob.
- **Writes** use compare-and-swap (`if_match`: the server version the client
  last saw). If another write landed first, the client gets 409, pulls,
  merges, and pushes again.
- **Three-way merge.** Each machine keeps the last vault version it synced
  (`vault-server.esec`, the server's own ciphertext) as the common ancestor:
  - An entry changed only on the server is taken from it, for example a key
    another device rotated.
  - An entry changed only locally is kept and pushed.
  - An entry changed on both sides is a conflict. An interactive sync asks; the
    daemon leaves it, reports it in `status`, and pushes nothing until it is
    resolved.
  - Nothing local is ever deleted.
- **Rollback protection:** a client rejects a blob whose inner generation is
  lower than the last one it applied.
- **Project index (optional, on by default).** With each push, a device can
  publish a separately signed, secret-free index for the web UI's `/projects`
  page. It holds project ids, environment names and public keys. The server
  validates every string before storing it. Turn it off with
  `esec vault index off` or `login --no-index`.
- **The daemon** reuses the existing change detection, debounce, and job
  machinery. It pushes on change and long-polls `GET /v1/events?after=<id>` to
  pull, merge, and refresh the broker cache.
- **The server becomes a remote type.** `remote.toml` keeps rclone, restic,
  file, and exec as optional offline backups. Sync is set by
  `esec vault login`, not by `remote add`.

## 6. Revocation and rotation

- **Lost or retired device:** `esec vault devices revoke hetzner-3` runs from
  any active device. It does the following:
  1. Append `device_revoke`.
  2. Rotate U: append `ukey_rotate`, re-encrypt U to every surviving device,
     re-wrap U to the master key, and re-seal the vault blob to the new U.
  3. Invalidate agent slots; they need a re-run of `enable`.

  The revoked device has seen the plaintext environment keys, so the CLI lists
  which environments it held and offers `esec vault env rotate`.
- **The web UI can suspend a device:** it blocks sessions and API access
  immediately, from a phone. Cryptographic revocation is completed by the next
  CLI run, and the daemon prompts for it.
- **`esec vault env rotate <env>`** (phase 2):
  1. Create a new keypair.
  2. Re-encrypt every file in the repository that uses the old public key.
  3. Keep the old key as `retired` so git history still decrypts.
  4. Push the vault.

  The command prints the reminder that values the revoked device already saw
  must be rotated at their provider.

## 7. Encrypted local keyring cache (esec core change)

### Format

A keyring file is sealed when its first line is exactly the magic line
`ESEC-SEALED-KEYRING-V1`. After that line comes base64 of:

```
nonce (24) ‖ XChaCha20-Poly1305(C, plaintext dotenv keyring, aad = "esec-keyring/v1\n" + keyring basename)
```

The basename in the authenticated data stops someone from swapping one
project's sealed file for another's.

### Reading (`findPrivateKeyForData`, `sniffFromKeyring`)

- A file without the magic line is parsed as plaintext dotenv, exactly as
  today. Plaintext and sealed keyrings can sit side by side, and environment
  variables still take priority.
- For a sealed file, load C from the device secret store (§9) and decrypt in
  memory. If C is not available, fail with a specific error that names the
  file and points to `esec vault status`. Never treat a sealed file as
  "key not found".
- **New package:** `github.com/mscno/esec/pkg/keyringfile`, with `Read(path)`,
  `Write(path, entries, sealed bool)`, and `IsSealed`. It also holds the
  secret-store abstraction. esec-vault's `keystore` uses this package, so the
  format has one implementation.

### Writing

- `esec keygen --save` keeps the file's current mode: sealed stays sealed.
  Writes are atomic: temp file, fsync, rename.
- **New commands:** `esec vault keyring seal [--all]` and
  `esec vault keyring unseal` (asks for confirmation). On a device with C, new
  keyrings are sealed by default.

### Compatibility

- Older esec versions **fail loudly** on a sealed file. This was checked:
  godotenv v1.5.1 returns `unexpected character "-" in variable name`, so old
  esec reports `failed to parse keyring file`, not "key not found". A test pins
  this so a godotenv upgrade can't quietly change it.
- The README states the minimum esec version.
- esec-vault refuses to seal unless the esec on `PATH` reports a version that
  understands sealed files. The user can override this.

### What sealing protects against

It protects against:
- leaks from disk images, backups, and dotfile sync;
- an accidental `cat` or commit of a keyring;
- on macOS, any process that lacks Keychain access (the Keychain access
  control list prompts).

It does not protect against:
- same-user processes on Linux once the Secret Service is unlocked;
- a compromised account.

## 8. Optional SSH-agent unlock

This lets `ssh -A vm` followed by `esec vault login --ssh-agent` add the VM
without the laptop CLI or the recovery phrase.

### Enabling (on a device that holds U)

```sh
esec vault agent-unlock enable --key ~/.ssh/esec_ed25519.pub --expires 90d
```

1. **Accept only key types whose signatures always come out the same for the
   same input:** `ssh-ed25519` and `rsa-sha2-256`/`rsa-sha2-512`. Reject
   ECDSA, `sk-*` (FIDO keys include a counter), and Secure-Enclave agents such
   as Secretive, which are P-256.
2. Create a 32-byte `salt` and a `slot_id`. The challenge is:

   ```
   "esec-vault agent-unlock v1\n" + user_id + "\n" + slot_id + "\n" + hex(salt)
   ```

   It is signed as an SSHSIG with namespace `esec-vault-unlock`. That namespace
   is separate from the `esec-vault` proof namespace.
3. **Ask the agent to sign twice and require identical signatures.** This
   catches agents whose signatures vary.
4. Derive the wrapping key:

   ```
   KEK = HKDF-SHA256(ikm = raw signature, salt = salt, info = "esec-vault agent-unlock kek v1")
   slot_box = XChaCha20-Poly1305(KEK, U privs ‖ ukey_version, aad = slot_id ‖ user_id)
   ```
5. Upload `{slot_id, ssh_key_fp, salt, slot_box, expires}` and append
   `agent_slot_add` signed by U.

### Using it

1. Sign in with the device code. GitHub authentication is still required.
2. Fetch the slots for the account.
3. Find a matching key in `SSH_AUTH_SOCK`, sign the challenge, and derive KEK.
4. Unwrap U and check it against the chain head.
5. Append `device_add method: ssh_agent slot: <id>`, signed by U and D.

### Security and auditability

- **Two factors are needed:** a GitHub session and an agent signature. Neither
  the server alone nor the agent alone is enough.
- **Every use is an entry in the signed chain and the server audit log.** Every
  other active device's daemon shows an OS notification ("hetzner-3 added via
  SSH agent"). `esec vault devices` and the web UI show the method for each
  device.
- **Slots expire** (90 days by default, 1 year at most). They can be listed and
  disabled (`agent-unlock list|disable`), and they are invalidated when U
  rotates. The rotating device re-wraps them if the agent is available.
  Otherwise the CLI asks to run `enable` again.
- **Docs recommend:**
  - a dedicated key, kept apart from the general SSH key;
  - per-use confirmation (`ssh-add -c` or the 1Password agent prompt);
  - turning off agent forwarding after the device is added.
- **Remaining risk:** root on a host where the agent is forwarded *and* a
  session has been obtained can add a device. Per-use confirmation and the
  notifications above are what catch that.

## 9. Device secret store

The secret store holds D, U, C, and the session token, behind one interface in
`esec/pkg/keyringfile` (`secretstore`). It is picked in this order:

1. **macOS:** Keychain. **Windows:** Credential Manager. Both go through
   go-keyring, as today.
2. **Linux, when a Secret Service answers on D-Bus:** go-keyring.
3. **Linux headless with a TPM** (vTPM on most cloud VMs: GCP Shielded VM,
   Azure Trusted Launch, AWS NitroTPM): `systemd-creds encrypt --with-key=tpm2`
   into `~/.config/esec/secrets/*.cred`. This survives reboots. Copying the
   disk image to another machine does not expose the secrets.
4. **Linux headless without a TPM:** a 0600 file,
   `~/.config/esec/secrets/device.toml`. It also survives reboots, with the
   same protection as `~/.ssh/id_ed25519`. `status` labels it
   `file (no hardware binding)`.

A **logged-in VM stays logged in across restarts.** Restarting does not need a
new approval.

Without hardware binding, the cache key C sits next to the sealed keyrings. On
such a machine, sealing only protects against copying the keyring files
without the rest of the home directory. The CLI says this in `status`, and
does not claim more.

`--secret-store keyctl` (kernel keyring, cleared at reboot) is an opt-in for
throwaway VMs that should forget keys when they restart.

`esec vault status` and `doctor` show the backend in use. If D is lost, the
machine counts as a new device.

## 10. Server

### Shape

- **Code:** `cmd/esec-vault-server` in this module. Uses the standard library
  `net/http`, `modernc.org/sqlite` (no cgo), and `html/template`. The web UI
  contains no JavaScript cryptography.
- **Deployment:** Fly.io or any VM, as one binary with a volume. Litestream
  replicates the database continuously to the R2 bucket. TLS comes from the
  platform.
- **Configuration** comes from a TOML file. Every setting can be overridden by
  an `ESEC_SERVER_*` environment variable. Secrets come only from the
  environment, never from the file.

  ```toml
  base_url = "https://vault.example.com"
  db_path = "/data/esec-vault.db"
  vault_history = 50

  [github]
  client_id = "Iv23li..."           # client_secret: ESEC_SERVER_GITHUB_CLIENT_SECRET

  [access]
  # Numeric GitHub user IDs (gh api user --jq .id). Never usernames.
  allowed_github_ids = [
    53101343,  # mscno (owner)
  ]

  [sessions]
  idle = "720h"       # 30 days
  absolute = "2160h"  # 90 days
  ```

  - When a person signs in, the server looks up their numeric ID from GitHub
    and checks it against `allowed_github_ids`. It stores the username only
    for display.
  - An ID not on the list is refused before any account or device is created.
  - Removing an ID from the list blocks that account's sessions on its next
    request.

### Data model

```
users(id, github_id UNIQUE, login, created_at)
devices(id, user_id, name, platform, enc_pub, sign_pub, status[pending|active|suspended|revoked],
        method, created_at, last_seen_at, last_ip)
device_codes(device_code_hash, user_code_hash, device_id, user_id NULL, status, attempts, expires_at)
sessions(token_hash, user_id, device_id, created_at, last_used_at, expires_at, revoked_at)
nonces(device_id, nonce, seen_at)                 -- PoP replay cache, pruned
chain_links(user_id, seq, hash, envelope, created_at)   PRIMARY KEY(user_id, seq)
device_boxes(device_id, ukey_version, box)
identity_blobs(user_id, ukey_version, blob)       -- master-wrapped U
vault_versions(user_id, version, blob, sig, index_json, sha256, pushed_by, created_at)
agent_slots(id, user_id, ssh_key_fp, salt, box, ukey_version, expires_at, disabled_at)
audit(id, user_id, device_id, ip, action, detail_json, created_at)
alert_outbox(id, user_id, kind, channel[email|webhook], recipient, payload, created_at,
             attempts, next_at, sent_at, failed_at, last_error)
users.alert_email, alert_email_pending, alert_email_token (hash), alert_email_expires
projects(id, created_by, created_at, seq, updated_at)
project_links(project, seq, hash, envelope, signer, created_at)   PRIMARY KEY(project, seq)
project_members(project, user_id, login, admin, envs, active)     -- mirror of the verified chain
project_machines(id, project, name, sign_pub, active, created_at, last_used_at, last_ip, uses)
project_grants(id, project, to_id, to_ukey_version, envs, envelope, created_by, created_at)
project_holdings(project, holder, env, public_key, updated_at)    -- keys a member confirmed
project_audit(id, project, actor, ip, action, detail, created_at)
account_proofs(user_id, login, root, signature, created_at)
```

### API

All endpoints are JSON, `/v1`. Every endpoint except `auth/*` needs a session
and a request signed with `D.sign`.

| Endpoint | Purpose |
|---|---|
| `POST auth/device`, `POST auth/token` | Device code flow |
| `GET me` | Account, device status, account-key fingerprint |
| `POST auth/logout` | End this session |
| `GET chain?after=` | Read links (devices waiting for approval: only while no account exists) |
| `POST commit` | Append links together with the device boxes, identity, vault and slot data they need, in one transaction. Approval, revocation, rotation, renames and slots all go through it. |
| `POST devices/self/proof` | Store this device's self-signed proof (pending devices) |
| `GET devices`, `POST devices/{id}/suspend` | Devices |
| `GET devices/self/box` | Encrypted U for this device |
| `GET identity` | Master-wrapped U (approved devices) |
| `POST recovery` | Prove the recovery phrase; returns the chain and the master-wrapped U |
| `POST agent-slots/unlock` | Prove an SSH key; returns the chain and its slot |
| `GET/PUT vault`, `GET vault/versions`, `GET vault/versions/{v}` | Vault sync (CAS on PUT; blob and index signed by U) |
| `GET agent-slots`, `DELETE agent-slots/{id}` | §8 (approved devices) |
| `GET events?after=&wait=` | Long poll for the daemon |
| `GET audit` | Audit log |
| `GET users?login=`, `GET users/{id}` | Another account's user chain and GitHub proof (§14) |
| `PUT account/proof` | Publish this account's GitHub SSH proof |
| `GET projects`, `GET projects/{org}/{repo}/chain`, `…/status`, `POST …/commit` | Shared projects: list, signed chain with its signers' user chains, key delivery, append links and grants (§14) |
| `GET grants`, `POST grants/ack` | Keys waiting for this account; acknowledge and record what is now held |
| `POST machines/keys` | A machine's sealed keys; no session, signed by the machine key, with an OIDC token when its policy asks (§15) |

### Web pages

| Page | Contents |
|---|---|
| `/` | GitHub sign-in |
| `/device` | Code entry and confirm |
| `/account` | Overview: what needs attention, devices (status, method, last seen, suspend), sessions (end), agent slots (disable), signed-in browsers (sign out), recent activity, account-key fingerprint |
| `/devices/{id}` | One device: fingerprint (never for a waiting device), sessions, activity |
| `/activity` | The account's audit log, filtered by kind or device, paged |
| `/projects` | The published project index: projects, environments, public keys; search |
| `/vault` | Stored vault versions: size, hash, pushing device |
| `/admin`, `/admin/users/{id}` | Read-only, for `admin_github_ids`: server status, alert delivery, accounts, server-wide security events. No keys, fingerprints or creation tokens |
| `/alerts/confirm` | Confirms an alert address from the emailed link. Opening the link changes nothing (mail scanners open links); the button does |
| `/teams/{org}/{repo}` | A shared project: members and what each reads, key delivery per environment, machines and their last use, keys to rotate, the chain's history and key deliveries. Members, and admins read-only |

The pages use secure cookies (`SameSite=Lax` for OAuth), CSRF tokens, a strict
CSP, and no third-party scripts. One first-party script adds copy buttons,
confirmations, local times and table filters; every page works without it.

### Alerts

Security events (a device signed in, approved, suspended or revoked, a web
sign-in from a new browser) are queued in `alert_outbox` in the transaction
that records them, and a worker delivers them: email through Lettermint to
the account's confirmed address and the operator's `email_to`, and a signed
JSON post to the operator's webhook. Retries back off for about 11 hours;
4xx answers are final. An address gets alerts only after its owner opens the
emailed link and presses Confirm; a change or removal is told to the old
address, so someone in the browser cannot silently redirect alerts. Alerts
carry only metadata the server already holds. In shared projects, adding
someone alerts them; removing someone or someone leaving alerts every
remaining member, since the keys they could read need replacing; adding or
removing a machine alerts the admins.

### Rate limits

| Action | Limit |
|---|---|
| Wrong codes (entry or confirm form) | 30 per address per hour, 10 per signed-in user per 10 minutes, reserved before the lookup |
| GitHub sign-in starts | 30 per address and 300 per network per hour; 200,000 open sign-ins server-wide |
| `auth/device` | 10 per address and 100 per network per hour; 200,000 open registrations server-wide |

The server-wide caps protect the database. Devices the server already
trusts, and browsers that signed in before (a 180-day cookie), bypass them,
so a flood can only delay brand-new devices and browsers. Token polls are
limited per address and network, refused without any write when early or
expired, and serialized per code by a compare-and-swap. A sweep of the counter table keeps every counter at half its limit or
more.
| Agent-slot reads | 10 per user per hour |

An address is an IPv4 address or an IPv6 /64; a network is an IPv4 /24 or an
IPv6 /48. Anonymous and signed-in counters are kept apart, so a flood of
anonymous requests cannot evict signed-in counters. A full counter table
(100,000 keys) evicts its oldest counters that have not reached their limit,
so a flood cannot reset a limit that was reached. Only if an attacker
exhausts a million counters does the table refuse new keys; that takes
hundreds of networks, and the emergency switch below covers it.

Requests declare the SHA-256 of their body in `Esec-Body-Sha256`, which the
signature covers. The server checks the signature and the device's rate
limit, and records the nonce, before it reads any body; a session token used
without the device key gets nothing more. Only then does it reserve memory
for the body and check the body against the signed hash. Bodies held in
memory are capped per account (32 MiB) and in total (128 MiB). Devices
waiting for approval have their own pools and may send at most 64 KiB
except the commit that creates their account: 256 KiB in flight per device
(64 MiB in all), and one account-creating commit per account (64 MiB in
all). So phished or takeover devices block neither trusted devices' uploads
nor the owner's own new device; filling the shared pending pool would take
hundreds of pending devices, each needing a confirmed sign-in. Requests
without a session read their small bodies as data arrives, after their
address limits, so stalled connections hold almost no memory. Clients before v0.4.2 send no body hash; their requests without a
body still work, and those with one are refused with an upgrade hint.

## 11. CLI changes

```
esec vault login [URL] [--ssh-agent | --recover] [--name NAME] [--no-index] [--no-seal]
esec vault logout [--forget-device]        # ends session; keeps device keys unless asked
esec vault devices [list|approve [ID]|revoke ID|rename ID NAME|suspend ID]
esec vault sync --server                   # interactive pull, merge and push
esec vault index [on|off]                  # publish the secret-free project index
esec vault agent-unlock [enable --key K [--expires D]|list|disable ID]
esec vault keyring [seal [--all]|unseal]
esec vault env rotate ENV                  # phase 2; in a shared project, also sends the new key
esec vault status                          # + server, session, device, secret store, chain head, sync state
esec vault team [show|create|add LOGIN --env E|set LOGIN --env E|remove LOGIN|leave|sync|publish ENV|prove]
esec vault machine [create NAME --env E [--github-repo R --github-ref REF]|list|remove NAME]
esec-vault machine [run -- CMD|env]        # in a CI job or app, with ESEC_VAULT_MACHINE_KEY
```

Account state lives in `~/.config/esec/account.toml`: server URL, user id,
device id, and the pinned chain head. The secrets themselves are in the
secret store.

## 12. Threat summary

| Attacker | Outcome |
|---|---|
| Full server and database compromise | Metadata (devices, times, IPs, and project/env names if the index is on); refuse service; delete data (local cache plus offline remotes are the fallback); hold back updates (heads pinned). **Cannot** decrypt, add devices, or plant keys: chain links, vault blobs and the index are signed by U. Cannot inject a fake U into existing devices. A brand-new device is protected by the account-key words (§4). |
| GitHub account takeover | Can create pending devices. Cannot decrypt without an approval, the phrase, or the agent. Shows up as pending devices, notifications and, with alerts on, an email and webhook post for each new device and new browser. Turning email alerts off or changing the address tells the old address. At most 50 devices wait for approval at once; beyond that the oldest is dropped, so the owner's new device always gets in. Before the user's first login, the attacker could create the account with their own keys. A machine holding the user's identity refuses to join it (different master key), and a new device sees unknown account-key words. |
| Alert channel compromised (Lettermint or the webhook receiver) | It sees the alerts' metadata (logins, device names, addresses, times) and can drop alerts. It cannot affect the vault: alerts carry no keys, words or tokens except an address's own confirmation link. |
| An admin's GitHub account taken over | The admin pages are read-only: the attacker sees every account's metadata (logins, device names, addresses, activity, storage) and which allowed ids have no account yet, but cannot change anything, see keys or fingerprint words, or get account creation tokens. Keep `admin_github_ids` short, and secure admins' GitHub accounts as you would the server. |
| Takeover before the first login | Creating an account needs the server's bootstrap token, which the operator hands out separately; a GitHub session alone cannot create one. If the token also leaked: a machine with the user's identity refuses the foreign account, and a new device warns that the account already exists and asks for the account key, which a user who never set up esec vault must reject. |
| Flooding sign-ins from thousands of networks | Availability only: new devices and new browsers may have to wait for the flood to pass. Devices and browsers that signed in before keep working, and nothing is disclosed. The operator can also close the server to new devices (`new_devices = "closed"`) until it passes. Floods of that size are otherwise a job for upstream protection (a proxy or WAF), as for any internet service. |
| Flooding devices that wait for approval | They see nothing and cannot be approved without their own fingerprint words. There is no per-account cap to fill (registrations are limited per address and network instead), so a flood cannot keep the owner's new device out or evict it. Desktop notifications are limited to 5 an hour, then one warning. |
| Chain at `MaxLinks` (10,000 links) | The account freezes: no more revocations or rotations. That is far beyond normal use; start a new account if it ever happens. |
| Code phishing | There are no prefilled links: the victim would have to type an attacker's code into the page by hand, on a page warning that only self-started sign-ins should be confirmed. Even then the attacker's device is only pending: it sees nothing of the account without proving the recovery phrase or an SSH key. It cannot be approved by answering yes: `devices approve` requires typing the fingerprint words from the new device's own screen, and they appear nowhere else. |
| Stolen session token | Useless without `D.sign`. |
| Stolen VM disk | With macOS Keychain or a TPM-bound secret store, sealed keyrings are useless without C. With the 0600 file store, everything is exposed: revoke and rotate. |
| Live compromise of an active device | Everything that device can decrypt. Response: revoke, rotate U, rotate env keys, rotate values. |
| Server compromise, for shared projects | The same as above: it sees who reads which environment, and can withhold links and grants. It cannot add a member or machine, change access, or swap an environment key: links are signed by admins' user keys, checked against their own chains from the roots the project recorded, and grants carry keys the chain names. Members pin project chains and colleagues' chains, so it cannot roll either back for a device that saw them. |
| A colleague on the same server | They can create a shared project under any name (even one you use) and add you. Your device takes in nothing from a project until you accept it the first time, and never replaces a key you hold with one that project merely claims was earlier: such a key is kept and you are asked. |
| A removed member, or an admin's device that was revoked | They keep the keys they had: the project page, `team show`, an alert to the remaining members, and the admins' daemons list every environment to rotate. A revoked device holds its owner's old user key: it cannot sign as of a chain position after the rotation, nor before a position its owner has signed at since. A grant signed with it can only carry the chain's current keys to people who may read them. |
| A revoked admin device together with a compromised server | Until the admin signs anything in the project with the new key, the old key can sign a link as of the time before the rotation, which the server (if compromised) can accept, for example adding someone. Every device of the admin's account points such a change out ("your account added X from another device"), the project page and alerts show it, and the admin's next link makes any further one impossible. After revoking a device, admins of shared projects should check them. |
| A compromised server that withholds a member's key rotation | Admins' devices keep sealing keys to the member's last key they saw. If the member rotated because a device was revoked, that device and the server together can open those grants. The member's own devices drop grants sealed to an old key and report it, and the project page shows their keys as waiting; the member then signs in from a fresh device or asks an admin to check. |
| Machine key leaked | Removing the machine stops the server from handing its keys out at once. A machine bound to GitHub Actions is useless outside its repository, ref and environment even before that: its keys are released only with a valid OIDC token for this server. The leak is visible in the project's log (each use, with address, and refused tokens). |
| GitHub OIDC issuer or a workflow in the bound repository compromised | Someone who can run a workflow on an allowed ref of the repository, and who has the machine key, gets that machine's keys. Bind machines to protected branches or deployment environments. |

## 13. Milestones

Each milestone is a PR with tests. The client tests run against an in-process
server (`httptest`) with a memory secret store.

1. **esec core:** `pkg/keyringfile` (sealed format, secret-store interface,
   compatibility tests, pinned godotenv test). Read path in
   `findPrivateKeyForData` and `sniffFromKeyring`. `keygen --save` keeps the
   file's mode. Release esec v0.9.0.
2. **Keys:** device keypair, `identity.esec` v3 with `U.sign`, signed envelopes,
   chain types, and chain verification with property tests: fork, rollback,
   bad signature, revoked signer.
3. **Server, part 1:** schema, GitHub OAuth, device code flow, sessions,
   request signing, `me`, the web pages, rate limits, audit log.
4. **Login and approval:** `login`, `devices list|approve`, `--recover`, first
   device `init`, device boxes. End-to-end test with two clients and one
   server.
5. **Vault sync:** server remote, CAS push, merge on conflict, events long
   poll, daemon integration, broker cache refresh.
6. **Local seal:** `keyring seal|unseal`, default-sealed on enrolled devices,
   and the esec version check.
7. **Revocation:** `devices revoke` with U rotation, suspend from the web UI,
   daemon notifications.
8. **Agent unlock:** `agent-unlock enable|list|disable` and
   `login --ssh-agent`, with a determinism test against a real `ssh-agent` in
   CI.
9. **`env rotate`.**
10. **Deployment:** Fly config, Litestream, and an operations runbook.

## Changes made during implementation

| Draft | Built | Why |
|---|---|---|
| `device_add` signed by U and D | Signed by U; the body embeds a `device-proof` envelope signed by D | The proof is created when the device registers, before anyone approves it. |
| Account key words from U | From the first chain link | Stays the same across key rotations. |
| `POST chain` plus separate writes | One `POST /v1/commit` | Links and the boxes, identity and vault they require are written atomically. |
| Vault blob only sealed | Sealed **and** signed by U | Sealed boxes do not authenticate the sender; see §5. |
| Union merge with prompts | Three-way merge against the last synced version | A plain union let a stale device undo a key rotation. |
| Local settings in the synced vault | Keyrings and identity only | Settings differ per machine and caused needless pushes. |
| `--secret-store keyctl` as default for VMs | TPM or 0600 file by default; keyctl opt-in | Signed-in VMs must survive restarts. |
| No project browsing | Optional signed index and a `/projects` page | Requested during implementation. |
| — | `device_rename` link | `devices rename` needs the chain to agree on names. |
| Recovery checks the master X25519 key | Recovery also checks a phrase-derived signing key's authorization of the chain root | The X25519 key is public, so a server could build a forged account around it (found in security review). |
| 4-word fingerprints, shown after login | 6-word device and 8-word account fingerprints; a new device confirms the account key before installing anything | Short words could be searched for offline; the late check let keys sync to a forged account (found in security review). |
| Boxes and identity upserted | Write-once boxes; identity only with a new user key | A compromised device could otherwise silently break recovery and other devices (found in security review). |
| Any allowlisted GitHub session can create an account | Creating an account needs a per-user token, HMAC-derived from `ESEC_SERVER_BOOTSTRAP_TOKEN` and the GitHub id | Closes takeover before the first login; a token cannot create anyone else's account (found in security review). |
| Server and chain parsed link bodies differently | One strict decoder (`envelope.DecodeStrict`) everywhere, rejecting trailing data | A crafted body could otherwise be seen as different link types by the server's checks and the chain (found in security review). |
| Login state saved before confirmation | Commands refuse an account this machine never pinned; a declined account key deletes the half-finished login | A declined account could otherwise be installed by the next background sync (found in security review). |
| Root signature over the user key only | Also covers the master X25519 key; passphrase changes refresh it, and are blocked while signed in | A stale authorization could make recovery impossible (found in security review). |
| Approve with y/N after comparing words | Type the new device's fingerprint words | A yes-click could approve a phished device (found in review). |
| Devices waiting for approval read the chain, identity and slots | They read nothing until approved or until they prove the phrase or an SSH key | A phished sign-in learns nothing about the account (found in review). |
| — | `new_devices = "closed"` emergency switch | Lets the operator refuse all brand-new devices and browsers during an attack while trusted ones keep working. |
| Link with the code prefilled | Code always typed; `?code=` ignored | Removes one-click code phishing (RFC 8628 §5.4). |
| `login --recover`/`--ssh-agent` on a device the server calls active fell back to the account-key prompt | The same proof as for a pending device: the phrase must match the chain's master keys, or the SSH-agent slot must open; an identity on the machine must match the account's recovery keys | A server could otherwise skip the requested proof by lying about the device's status (found in security review). |
| Bodies read whole before the signature check | The signature covers a declared body hash and is checked first; small bodies for pending devices; per-account and total caps on bodies in memory, with a separate pool for pending devices | A copied session token could make the server buffer many 16 MiB uploads, and a first fix let pending devices block every account's uploads (found in security review). |
| Pending devices told when a link's seq was stale | The same error as any rejected link | The 409 let a pending device probe the chain length (found in security review). |
| Rate limits on all code entries | Limits on wrong codes, on both forms, per address (IPv6 /64) and per user; caps on open registrations, OAuth states and pending devices | Found in security review. |
| Teams: grants encrypted to a member's current U, imported by their device | The same, plus holdings: members report the keys they hold, and admins' devices send whatever is missing | U rotates, members are added by admins who lack a key, and machines need new keys after a rotation; nobody should have to remember to resend. |
| Teams: member keys checked with SSHSIG proofs against `github.com/<login>.keys` | The proof signs the account root, not a key | The root never changes, so one proof survives user key rotations; every key since is verified from it. |
| Teams: project chain signed by admins | Signed by each admin's own user key at a named version and user chain position; positions never go back per signer | A revoked device holds its owner's old user key. A first version compared times, which a backdated rotation could use to break a project for good (found in review). |
| — | Grants supersede older grants to the same member; at most 50 wait per project and member | A global cap let anyone block a member's grants everywhere (found in review). |
| — | A device accepts a project before taking in its keys, and replaces only keys it got from that project | Anyone on the server can name a project after any repository (found in review). |
| Machines: a keypair whose private key is a CI secret | The same, optionally bound to GitHub Actions OIDC: the server releases the sealed keys only to matching jobs | A leaked secret alone is then not enough. |

## 14. Shared projects

A shared project gives a team the keys of a project's environments without
committing anything to the repository, and without trusting the server with
who may read what.

### The project chain

Each project (`org/repo`) has a chain like a user's: an append-only,
hash-linked list of signed links, envelope kind `project-link`:

```json
{"project":"acme/store","seq":4,"prev":"<sha256 of link 3>","ctime":"…","type":"member_add",
 "signer":"gh:53101343","signer_ukey_version":2,"signer_seq":9,"body":{…}}
```

| Type | Signed by | Body |
|---|---|---|
| `init` | its creator, who becomes the first admin | creator (GitHub id, login, account root), environments with public keys |
| `member_add` | an admin | the member's GitHub id, login and account root; admin, or the environments they read; how the admin checked the account |
| `member_update` | an admin | new role and environments |
| `member_remove` | an admin, or the member leaving | member, reason |
| `env_set` | an admin | an environment and its (new) public key |
| `machine_add` / `machine_remove` | an admin | a machine's id, name and public keys, its environments and OIDC policy (§15) |

Each link names the signer's user key version and the length of the
signer's user chain when they signed (`signer_seq`). A verifier checks the
signature against the signer's own user chain, verified from the account
root the project recorded when the signer was added, and requires the named
version to be the key current at that chain position. The account root is
the hash of the first link of a user chain (the account key words come from
it), so it never changes. Positions, unlike times, cannot be skewed: a
rotation dated before a link (a wrong clock, or a member trying to break the
project) changes nothing. A signer's position never goes back within a
project chain, so once its owner has signed with a new key, an old key held
by a revoked device cannot sign as of the time before the rotation.

Rules every verifier applies: admins read every environment; others read
the environments listed, which must exist; a project keeps at least one
admin; an environment's keys are never reused. When someone loses access to
an environment (removed, left, access changed, a machine removed), the
environment records them as **exposed**: they may still hold its current
key. A new key for the environment (`env_set`) clears the list. Exposures
are the project's rotation to-dos.

Clients pin each project chain's head in `teams.toml`, and the heads of
colleagues' user chains, and refuse a chain shorter than the pin or forked
from it. The server verifies everything too, but only to reject bad data
early; it also requires links and grants to be signed by the caller's
current user key, and a new member to be that person's account on this
server.

### Adding someone

1. The new member proves their account: `team prove` signs
   `"esec-vault account v1\n" + user id + "\n" + login + "\n" + account root`
   as an SSHSIG (namespace `esec-vault-account`) with an SSH key registered
   on their GitHub account, from the agent or a key file, and publishes it.
2. The admin's device fetches the person's user chain and proof, verifies
   the chain, and checks the proof against `https://github.com/LOGIN.keys`,
   fetched from GitHub, not the server. Without a proof, the admin types the
   account key words the person reads out from `esec vault status`. Either
   way, the server cannot pass off an account of its own as the colleague's.
3. The admin's device appends `member_add` and, in the same commit, a grant.

### Grants

A grant (envelope kind `project-grant`) carries environment keys to one
member or machine. It is signed by an admin's user key and names the
project, the chain length the admin verified, the recipient, the user key
version and public key it is sealed to, and each environment with its public
key; the keys themselves are in a sealed box to the recipient's current
user key (or the machine's key), whose content names the project and the
recipient again. The recipient checks that the grant is from an admin, that
every environment is one it may read, and that every key matches the public
key the chain names now. A grant made before a key changed, or sealed to a
user key the recipient has since replaced, is out of date and dropped.

A member's device acknowledges the grants it took in and reports the keys it
now holds; the server keeps those as **holdings** and shows, for every
member and environment, whether the keys are held, waiting for the member's
device, or not sent yet. Admins' devices (their daemons, or `team sync`)
send whatever is not sent: after a member's user key rotated, to a member
added by an admin who lacked a key, to a machine after a rotation. The
server only says who is missing what; the admin's device checks it against
the verified chain before sealing anything.

The first time a device sees keys from a project, it asks before taking them
in (`team sync`; the daemon notifies instead), and it does not do so at all
for a project it never accepted. Anyone on the server can create a shared
project under any name, so without this a colleague could hand you keys for a
project you have, or will create. A project this account created or changed
is accepted. After that, keys are taken in automatically. A granted key
replaces a key the device holds only if that key is an earlier key of the
same environment that this device got from or gave to the project;
otherwise the device's key is kept and the person is asked. A replaced key
stays in the keyring under its public key, so older files still decrypt.
Received keys reach the member's other devices through their vault.

### Removing someone, rotating keys

Removing a member (or a machine, or an environment from a member's access)
leaves those environments exposed. `team remove` and `team set` list them,
the project page and `team show` show them, every remaining member gets an
alert, and admins' daemons notify. `env rotate` in a shared project (admins
only) re-encrypts the files, appends `env_set` with the new public key, and
sends the new key to everyone who reads the environment, machines included.
`env add` adds an environment the same way. `team publish ENV` does it for a
key changed by other means.

The git-committed shares of `esec vault share` stay for people without a
server.

## 15. Machines

A machine is a non-person identity, for a CI job or a deployed app: an
X25519 key that receives environment keys and an Ed25519 key that signs its
requests. An admin creates one (`machine create`), which appends
`machine_add` with the machine's public keys, environments and optional OIDC
policy, and seals the keys to it in a grant. The machine's secret is one
token, `esecm1_…`, holding the server, project, the hash of the project
chain's first link, the machine id and both private keys.

In the job, `esec-vault machine run -- CMD` (or `machine env`) signs a
request to `POST /v1/machines/keys` over the machine id, project, time, a
nonce and the hash of an OIDC token. There is no session: the server checks
the signature against the machine's key in the verified chain, refuses
replays, and returns the project chain, the user chains of its signers and
the machine's latest grant. The machine verifies the chain from the root in
its token, trusting nothing else the server says, checks that it is still an
active machine of the project and that the grant comes from an admin with
the chain's current keys, and opens it. `machine run` sets
`ESEC_PRIVATE_KEY_<ENV>` for the command, which core esec reads.

**OIDC.** A machine bound to GitHub Actions (`--github-repo`, optionally
`--github-repo-id`, `--github-ref`, `--github-environment`) gets its keys
only with a GitHub Actions OIDC token: in a job with
`permissions: id-token: write`, `machine run` requests one with the server's
origin as audience. The server checks the RS256 signature against GitHub's
published keys, the issuer, audience and lifetime, and the policy:
repository (and its id, which survives renames), ref (exact, or a prefix
ending in `*`) and deployment environment. The policy is in the signed
chain, so the server cannot loosen it unnoticed, and the keys stay sealed to
the machine key, so the server cannot read them either. A leaked machine key
alone is useless outside the allowed repository and refs; a valid OIDC token
alone opens nothing.

Every fetch is logged in the project's log with the address and, for OIDC
jobs, the repository, ref, run and actor; refused tokens are logged too. A
machine keeps exactly one grant with all its environments; admins' devices
send a new one after a rotation. Removing a machine stops the server from
handing it keys and leaves its environments exposed.

## 16. Machine groups

A machine group (`acme/production`) gives many machines the same
environments of one or more shared projects, each machine with its own key.
Machines come and go all the time, so a new one must work without an
admin's device being online, and removing one must not touch the others.

### The group chain

Each group has a chain like a project's, envelope kind `group-link`,
signed by its admins' user keys with the same `signer_ukey_version` and
`signer_seq` rules (§14):

| Type | Signed by | Body |
|---|---|---|
| `init` | its creator, the first admin | creator; the group key, version 1 (X25519 public key) |
| `admin_add` / `admin_remove` | an admin | the admin's account (checked like a project member), or who leaves |
| `machine_add` | an admin, or an enrollment token | the machine's id, name, X25519 and Ed25519 public keys, optional OIDC policy, and the join request it answers |
| `token_add` | an admin | a token's id, name, keys, expiry and optional OIDC policy |
| `remove` | an admin | a machine or token; `destroyed` when its keys went with it |
| `key_rotate` | an admin | the next group key version |
| `access_add` / `access_remove` | an admin | a project, with the hash of its chain's first link |

A token may sign only `machine_add`, before it expires, and the machine
must carry the token's OIDC policy. A removed machine, token or admin (not
destroyed) leaves the group key **exposed** until `key_rotate`.

A project grants a group environments with a `group_set` link (group id,
group root, environments; none removes it). Reducing them exposes the
environments, like a member's. Both sides must agree: the project chain
grants, and the group chain lists the project's root. A machine accepts a
project's keys only from a project its group chain lists, verified from the
root listed there, so neither the server nor another account can feed it
keys of a look-alike project.

### Keys

The group key is sealed to every machine, token and admin in a **key
grant** (kind `group-key`), signed by an admin or, for a machine it
enrolls, a token. The key inside is checked against the public key the
chain names, so whoever made the grant cannot hand out another key. Each
project's admins seal the environments the group reads once, to the group
key, in an ordinary grant to the holder `g:<group>` (§14). A machine fetches
everything in one signed request: the group chain and its signers' user
chains, its key grant, and for each project the group lists, the project
chain and its grant to the group. It verifies the group chain from the
root its key names, that it is an active member, opens the group key, then
verifies each project chain and opens its grant.

Removing a machine (not destroyed) rotates the group key in the same
commit: the new key is sealed to everyone left, and the remover's device
re-seals the projects it administers; other projects' admins' devices do
the same when told. The removed machine may still hold earlier environment
keys, so each environment the group read whose key was set before the
removal is a rotation to-do of its project. Link times have whole seconds;
a removal in the same second as a key counts as exposing it, and a device
dates a new key after the removals it knows of. Admins' devices also
re-send key grants the server reports missing, and rotate the group key on
their own when someone who left still holds it, or when no admin can open
it any more (their user keys changed).

### Bringing machines in

- **Enrollment token** (`esecg1_…`, holding the server, the group, its root,
  the token id and its private keys). A job uses it directly. A machine
  joins with it: it creates its own keys, signs `machine_add` with the
  token, seals the group key (which the token opens) to itself, and sends
  both to `POST /v1/fleet/enroll`. No admin needs to be online. The root
  comes from the token, so the server cannot substitute a group.
- **Join request.** The machine creates its keys and sends them to
  `POST /v1/fleet/join`; the server answers with the group's root. The
  machine shows six words over the group, that root and its keys. The admin's
  device computes the words from the root it verified and the request; when
  the person types matching words, it signs `machine_add` and a key grant.
  The server cannot get its own key let in. The machine trusts the server's
  root the first time unless it is given the group's fingerprint (8 words
  over the group and its root, from `group show`), which it then checks.
- **A key made on the admin's device**, copied to the machine.

### Web changes

The web pages show each group's machines, tokens, use and a project ×
environment table, and each project's members. Changes made there are
stored as **web changes** (table `changes`, scope `group` or `project`): who
a group reads, removing a machine or token, adding a member, changing what
one reads, removing one. The server cannot sign links, so an admin's device
signs them (`esec vault changes`), after showing each; nothing that gives
access is signed without asking, and a new member's GitHub SSH proof is
checked as for `team add`. Only admins of the group or project can make
them. A
removal blocks the machine on the server at once, before it is signed;
dismissing it lets the machine back in. A malicious server can always
withhold keys, so blocking gives it nothing new. A new group key is not
sealed to blocked machines or expired tokens.

### Threats

| Threat | Outcome |
|---|---|
| Server adds a machine | Refused: `machine_add` needs an admin's or a token's signature. |
| Server feeds a machine keys of a project the group did not choose | Refused: the project must be in the group chain with its root. |
| Server swaps a joining machine's key | The admin's words differ; it is not let in. |
| Server puts a joining machine in a look-alike group | Only when the machine was given neither a token nor the fingerprint; the admin's words then differ, which tells them. |
| Leaked token | Enrolls machines and reads the group's environments until removed or expired. With an OIDC policy, only from that repository. Remove it: the group key rotates; rotate the environments. |
| Removed machine | Gets nothing from the server; holds the old group key, which no new grant uses; earlier environment keys are rotation to-dos. |
| Another account grants a group from its own project, to see it | Refused: only the group's admins choose the projects it reads, and only members of those projects (and the admins) can read the group. A `group_set` needs the group to list the project. |
| Web change invented by the server | Shown to the admin before signing; `approve --yes` signs only removals, never access. Only group admins, or admins of a project the group reads, can propose. |
| Server freezes a project admin's view of a group | The admin's device pins the group chain as far as it saw it; a server that withholds a later removal and key rotation keeps the admin sealing to the old group key, which the removed machine could open with the server's help. The same withholding class as §14; group admins see the true state. |
| Expired token | Refused by the server; a token signs `machine_add` only before its expiry, but its clock is its own, so expiry is the server's to enforce. |

## 17. Live web pages

The signed-in pages use Datastar (v1.0.4, vendored in `static/`) and its Go
SDK. Every page still works without scripts: forms post and redirect. With
scripts, a form is sent in place (`@post(path, {contentType: 'form'})`,
the same urlencoded fields and CSRF token) and the server answers with
server-sent events that patch parts of the page by id and show a message;
read-only parts (machines, joins, key delivery, history, logs) refresh
every 10 to 15 seconds while the page is visible. Forms being filled in are
not refreshed under the person.

Datastar evaluates the expressions in `data-*` attributes. It runs in its
nonce mode: each page carries a fresh nonce in `<html data-nonce>`, Datastar
reads and removes it and runs each expression as a script with that nonce,
and the content security policy allows scripts only from the site and with
that nonce (`script-src 'self' 'nonce-…'`, `connect-src 'self'`), never
`unsafe-eval`. Expressions are built only by two template functions from
paths that match a strict pattern (no quotes, backslashes or `//`); names,
logins and other data never go into one, and html/template escapes them
everywhere else, so no attribute can be injected. A request Datastar sends
for a signed-out page gets a message to reload, not a redirect.

## Later phases (sketch)

- Passkey-PRF approval in the browser (requires trusting the JavaScript the
  server sends).
- OIDC tokens of other platforms (Fly.io machines, GitLab, cloud workload
  identity) for machines and enrollment tokens.
- Machine heartbeats and stale-machine clean-up for groups.
