# Design: esec vault server, device sync, and encrypted key cache

Status: draft, not implemented. Covers phases 1–2 in detail and sketches 3–4.

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
{"v":1,"kind":"chain-link","body":"<base64 of JSON bytes>","signer":"<key fp>","sig":"<base64 Ed25519>"}
```

The signature covers `"esec-vault/" + kind + "/v1\n" + body`. Each kind has its
own prefix, so a signature made for one kind cannot be passed off as another.

### Fingerprint words

A fingerprint shown to people is `SHA-256(keys...)`, truncated to 44 bits and
shown as 4 BIP39 English words (e.g. `tiger-lamp-orbit-maple`). BIP39 is
already a dependency.

## 2. User chain

A user's chain is an append-only, hash-linked list of signed links. It is the
only authority for which U version is current and which devices are trusted.

```json
{"seq":7,"prev":"<sha256 of link 6 envelope>","ctime":"…","type":"device_add",
 "user":"gh:1234567","ukey_version":2,"body":{…}}
```

| Type | Signed by | Body |
|---|---|---|
| `init` | U(1) | `U.enc`, `U.sign` public keys, master public key |
| `device_add` | current U **and** the new D (proves the device holds D) | device id, name, `D.enc`, `D.sign`, method: `approval\|recovery\|ssh_agent\|first`, approving device id or slot id |
| `device_revoke` | current U | device id, reason |
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
  expire after 10 minutes and allow 5 failed confirmations per code. Input is
  normalized: case-folded, `O→0`, `I/L→1`, dashes removed.
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

**Remaining risk:** a malicious server could send a brand-new VM a fake U,
together with a fake chain. The fake U would be encrypted to the VM's real
`D.enc`, which is public. Both terminals therefore print the **account key**
words. They are the same for every device you own, so a mismatch stands out.
The SSH-agent and recovery paths verify U without relying on this check.
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

1. Upgrade `identity.esec` to v3 by generating `U.sign`. This does **not** ask
   for the recovery phrase. The reasons:

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

- **The object** is today's `ESECVLT` v2 blob. It is already sealed to U and to
  the master key, and it has a monotonic generation counter inside. The server
  stores a version history, keeping the last 50 versions by default.
- **Writes** use `PUT /v1/vault` with `If-Match: <server version>`. If another
  write landed first, the client gets 409 and does the following:
  1. Pull and open the latest blob.
  2. Merge keyrings with the existing `sync` semantics: union of entries; the
     same name with a different value asks the user; the daemon never resolves
     a conflict on its own and leaves it pending.
  3. Push again.
- **Rollback protection:** a client rejects a blob whose inner generation is
  lower than the last one it applied.
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
vault_versions(user_id, version, blob, sha256, pushed_by_device, created_at)
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
| `GET chain?after=`, `POST chain` | Read and append links (append checks seq and prev) |
| `GET devices`, `POST devices/{id}/approve`, `POST devices/{id}/revoke`, `POST devices/{id}/suspend` | Devices |
| `GET devices/self/box` | Encrypted U for this device |
| `GET/PUT identity` | Master-wrapped U |
| `GET/PUT vault`, `GET vault/versions`, `GET vault/versions/{v}` | Vault sync (CAS on PUT) |
| `GET/POST/DELETE agent-slots` | §8 |
| `GET events?after=&wait=` | Long poll for the daemon |
| `GET audit` | Audit log |

### Web pages

| Page | Contents |
|---|---|
| `/` | GitHub sign-in |
| `/device` | Code entry and confirm |
| `/account` | Devices (status, method, last seen, suspend), sessions (end), agent slots (disable), audit log, account-key fingerprint |

The pages use secure cookies (`SameSite=Lax` for OAuth), CSRF tokens, a strict
CSP, and no third-party scripts.

### Rate limits

| Action | Limit |
|---|---|
| Code confirmation | 5 per code, 30 per IP per hour |
| `auth/device` | 10 per IP per hour |
| Agent-slot reads | 10 per user per hour |

## 11. CLI changes

```
esec vault login [URL] [--ssh-agent | --recover] [--name NAME]
esec vault logout                          # ends session; keeps device keys
esec vault devices [list|approve [ID]|revoke ID|rename ID NAME]
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
| Full server and database compromise | Metadata (project/env names, devices, times, IPs); refuse service; delete data (local cache plus offline remotes are the fallback); hold back updates (heads pinned). **Cannot** decrypt or add devices. Cannot inject a fake U into existing devices. A brand-new device is protected by the account-key words (§4). |
| GitHub account takeover | Can create pending devices. Cannot decrypt without an approval, the phrase, or the agent. Shows up as pending devices and notifications. |
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
