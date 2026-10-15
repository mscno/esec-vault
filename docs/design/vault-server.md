# Design: esec vault server, device sync, and encrypted key cache

Status: phases 1–2 implemented (branch `feat/vault-server`; core esec branch
`feat/sealed-keyring`). Phases 3–4 are sketched at the end. The section
"Changes made during implementation" lists where the code differs from the
first draft.

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
| How does the CLI sign in? | Our own OAuth device authorization grant (RFC 8628), with a Crockford base32 `XXXX-XXXX` user code and a prefilled link. GitHub is the only identity provider. The server issues its own sessions; GitHub tokens are used once and thrown away. |
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
 |   verification_uri(+_complete)     |                             |
 | print code + link; poll /token  -->|                             |
 |                                    |<-- GET /device?code=K7QM-2XDP
 |                                    |    GitHub OAuth (if needed)  |
 |                                    |--> confirm page: code, device name,
 |                                    |    platform, IP, D fingerprint words
 |                                    |<-- POST confirm (CSRF token) |
 |<- session (status: pending|active) |                             |
```

- User codes use Crockford base32 (no I, L, O, U): 8 characters, 40 bits. They
  expire after 10 minutes. Wrong codes are limited per address and per
  signed-in user (see "Rate limits"). Input is normalized: case-folded, `O→0`,
  `I/L→1`, dashes and spaces removed.
- The prefilled link still needs an explicit **Confirm** click, with the code
  shown. This defends against someone mailing you a link they started.
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

- A device that has never been approved gets a **pending** session. It can do
  only these things: read its own status, read the master-wrapped identity
  (recovery path), read its agent slots (§8), and post a self-signed
  `device_add` link. All of these are useless without U.
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
  Open https://vault.example.com/device?code=K7QM-2XDP
  (or go to https://vault.example.com/device and enter K7QM-2XDP)
  ✓ Signed in as mscno (GitHub 1234567)
  New device "hetzner-3"  fingerprint: tiger-lamp-orbit-maple
  Waiting for approval. On a trusted device run: esec vault devices approve
  Other options: --ssh-agent, --recover

laptop$ esec vault devices approve
  Pending: hetzner-3  linux/amd64  203.0.113.7  40s ago
  Fingerprint: tiger-lamp-orbit-maple      ← computed here from D, not sent by the server
  Account key: river-cloud-anchor-plume
  Approve? [y/N] y

vm$ ✓ Approved by macbook. Account key: river-cloud-anchor-plume
  ✓ Synced 4 projects, 11 environments.
```

The approving device does the following:

1. Fetch the pending device's public keys. Compute the fingerprint words
   locally and show them.
2. If you confirm, append `device_add` (signed by U), upload
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
```

### API

All endpoints are JSON, `/v1`. Every endpoint except `auth/*` needs a session
and a request signed with `D.sign`.

| Endpoint | Purpose |
|---|---|
| `POST auth/device`, `POST auth/token` | Device code flow |
| `GET me` | Account, device status, account-key fingerprint |
| `POST auth/logout` | End this session |
| `GET chain?after=` | Read links |
| `POST commit` | Append links together with the device boxes, identity, vault and slot data they need, in one transaction. Approval, revocation, rotation, renames and slots all go through it. |
| `POST devices/self/proof` | Store this device's self-signed proof (pending devices) |
| `GET devices`, `POST devices/{id}/suspend` | Devices |
| `GET devices/self/box` | Encrypted U for this device |
| `GET identity` | Master-wrapped U |
| `GET/PUT vault`, `GET vault/versions`, `GET vault/versions/{v}` | Vault sync (CAS on PUT; blob and index signed by U) |
| `GET agent-slots`, `DELETE agent-slots/{id}` | §8 |
| `GET events?after=&wait=` | Long poll for the daemon |
| `GET audit` | Audit log |

### Web pages

| Page | Contents |
|---|---|
| `/` | GitHub sign-in |
| `/device` | Code entry and confirm |
| `/account` | Devices (status, method, last seen, suspend), sessions (end), agent slots (disable), audit log, account-key fingerprint |
| `/projects` | The published project index: projects, environments, public keys |

The pages use secure cookies (`SameSite=Lax` for OAuth), CSRF tokens, a strict
CSP, and no third-party scripts.

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
evicts its oldest entries; it never refuses new keys.

## 11. CLI changes

```
esec vault login [URL] [--ssh-agent | --recover] [--name NAME] [--no-index] [--no-seal]
esec vault logout [--forget-device]        # ends session; keeps device keys unless asked
esec vault devices [list|approve [ID]|revoke ID|rename ID NAME|suspend ID]
esec vault sync --server                   # interactive pull, merge and push
esec vault index [on|off]                  # publish the secret-free project index
esec vault agent-unlock [enable --key K [--expires D]|list|disable ID]
esec vault keyring [seal [--all]|unseal]
esec vault env rotate ENV                  # phase 2
esec vault status                          # + server, session, device, secret store, chain head, sync state
```

Account state lives in `~/.config/esec/account.toml`: server URL, user id,
device id, and the pinned chain head. The secrets themselves are in the
secret store.

## 12. Threat summary

| Attacker | Outcome |
|---|---|
| Full server and database compromise | Metadata (devices, times, IPs, and project/env names if the index is on); refuse service; delete data (local cache plus offline remotes are the fallback); hold back updates (heads pinned). **Cannot** decrypt, add devices, or plant keys: chain links, vault blobs and the index are signed by U. Cannot inject a fake U into existing devices. A brand-new device is protected by the account-key words (§4). |
| GitHub account takeover | Can create pending devices. Cannot decrypt without an approval, the phrase, or the agent. Shows up as pending devices and notifications. At most 5 devices can wait for approval at once. Before the user's first login, the attacker could create the account with their own keys. A machine holding the user's identity refuses to join it (different master key), and a new device sees unknown account-key words. |
| Takeover before the first login | Creating an account needs the server's bootstrap token, which the operator hands out separately; a GitHub session alone cannot create one. If the token also leaked: a machine with the user's identity refuses the foreign account, and a new device warns that the account already exists and asks for the account key, which a user who never set up esec vault must reject. |
| Filling the 5 pending-device slots | Someone with the GitHub session can keep approval slots full. The owner suspends those devices on the web page and secures the GitHub account. |
| Chain at `MaxLinks` (10,000 links) | The account freezes: no more revocations or rotations. That is far beyond normal use; start a new account if it ever happens. |
| Phishing with a prefilled code link | The victim must click Continue and Confirm on a page warning that only self-started sign-ins should be confirmed. A confirmed attacker device is only pending: it can read the chain, the wrapped identity and slot data (all useless without the phrase or agent). It cannot be approved by answering yes: `devices approve` requires typing the fingerprint words from the new device's own terminal, which only the attacker sees. |
| Stolen session token | Useless without `D.sign`. |
| Stolen VM disk | With macOS Keychain or a TPM-bound secret store, sealed keyrings are useless without C. With the 0600 file store, everything is exposed: revoke and rotate. |
| Live compromise of an active device | Everything that device can decrypt. Response: revoke, rotate U, rotate env keys, rotate values. |

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
| Rate limits on all code entries | Limits on wrong codes, on both forms, per address (IPv6 /64) and per user; caps on open registrations, OAuth states and pending devices | Found in security review. |

## Later phases (sketch)

- **Phase 3, teams:**
  - Each project has members and per-environment grants, recorded in a project
    chain signed by admins.
  - A grant encrypts environment keys to the member's current U and puts them
    in a server inbox. The member's device imports them into its vault.
  - Member keys are also checked with the existing SSHSIG proofs against
    `github.com/<login>.keys`, so the server isn't trusted to map a login to a
    key.
  - Git-committed `.esec/vault/*.esec` shares stay as an option for people
    without a server.
- **Phase 4, machines:**
  - Service identities: a keypair whose private key is a CI secret, with
    environment keys encrypted to it.
  - Downloads authorized by GitHub Actions OIDC tokens, without a stored server
    credential.
  - Passkey-PRF approval in the browser (requires trusting the JavaScript the
    server sends).
