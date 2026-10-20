# Run the esec vault server

This runbook covers setup, deployment, backup, access changes and incident
response for `esec-vault-server`. For the design, see
[the design document](../design/vault-server.md).

## What the server holds

| Stored | Readable by the server? |
|---|---|
| Vault blobs (all environment private keys) | No. Sealed to your user key and signed by it. |
| Device boxes (your user key, one per device) | No. Sealed to each device's key. |
| Master-wrapped identity | No. Needs your recovery phrase. |
| SSH-agent unlock slots | No. Needs a signature from your SSH key. |
| Device chain (devices, key versions) | Yes, public metadata. Signed; clients verify it. |
| Project and machine group chains (members, machines, who reads what) | Yes, metadata. Signed by their admins; clients and machines verify them. |
| Grants and group key grants (environment and group keys) | No. Sealed to each recipient's key. |
| Project index (project ids, environment names, public keys) | Yes, if devices publish it (`esec vault index`). |
| Sessions, audit log, IP addresses, GitHub ids and logins | Yes. |

The server never receives a GitHub token for storage. It uses the token
once at sign-in to read the numeric user id and login, then discards it.

## Step 1: Create a GitHub OAuth app

1. Open GitHub → Settings → Developer settings → OAuth Apps → New OAuth App.
2. Set **Homepage URL** to your server origin, for example
   `https://vault.example.com`.
3. Set **Authorization callback URL** to
   `https://vault.example.com/auth/github/callback`.
4. Leave **Enable Device Flow** off. The server runs its own device flow.
5. Copy the client id. Generate a client secret and keep it for step 3.

The app requests no scopes. It reads only the public profile.

## Step 2: Write the configuration

Start from [`deploy/server.toml`](../../deploy/server.toml):

```toml
base_url = "https://vault.example.com"
db_path = "/data/esec-vault.db"

[github]
client_id = "Iv23li..."

[access]
allowed_github_ids = [
  53101343, # mscno (owner)
]
admin_github_ids = [
  53101343, # may open the admin page
]
```

List numeric GitHub user ids, never usernames. Find an id with
`gh api users/<login> --jq .id`.

`admin_github_ids` is optional. Each admin must also be allowed. Admins get
a read-only **Admin** page; see [Monitor](#monitor).

Every setting can be overridden from the environment:

| Variable | Setting |
|---|---|
| `ESEC_SERVER_CONFIG` | Path of the TOML file |
| `ESEC_SERVER_BASE_URL` | `base_url` |
| `ESEC_SERVER_LISTEN` | `listen` (default `:8080`) |
| `ESEC_SERVER_DB_PATH` | `db_path` |
| `ESEC_SERVER_GITHUB_CLIENT_ID` | `github.client_id` |
| `ESEC_SERVER_GITHUB_CLIENT_SECRET` | The client secret (environment only) |
| `ESEC_SERVER_BOOTSTRAP_TOKEN` | Bootstrap secret, 16+ characters, from which each person's account creation token is derived (environment only, required) |
| `ESEC_SERVER_ALLOWED_GITHUB_IDS` | Comma-separated numeric ids |
| `ESEC_SERVER_ADMIN_GITHUB_IDS` | `access.admin_github_ids`, comma-separated |
| `ESEC_SERVER_CLIENT_IP_HEADER` | `client_ip_header`; set only behind a proxy that sets it |
| `ESEC_SERVER_VAULT_HISTORY` | `vault_history` (default 50) |
| `ESEC_SERVER_NEW_DEVICES` | `new_devices`: `open` (default) or `closed`, the emergency switch below |
| `ESEC_SERVER_ALERT_EMAIL_FROM` | `alerts.email_from` |
| `ESEC_SERVER_ALERT_EMAIL_TO` | `alerts.email_to`, comma-separated |
| `ESEC_SERVER_LETTERMINT_ROUTE` | `alerts.lettermint_route` |
| `ESEC_SERVER_LETTERMINT_TOKEN` | Lettermint project token (environment only) |
| `ESEC_SERVER_ALERT_WEBHOOK_URL` | Webhook for alerts (environment only: chat webhook URLs are secrets) |
| `ESEC_SERVER_ALERT_WEBHOOK_SECRET` | Signs webhook posts (environment only) |

`base_url` must use https. Plain http is accepted only for `localhost`.

## Step 3: Deploy on Fly.io

These steps use [`deploy/fly.toml`](../../deploy/fly.toml) and
[`deploy/Dockerfile`](../../deploy/Dockerfile). Replace the `REPLACE` values
in `fly.toml` first.

```sh
fly launch --no-deploy --copy-config --config deploy/fly.toml
fly volumes create esec_vault_data --size 1 --config deploy/fly.toml
fly storage create -a <app>   # a Tigris bucket; sets AWS_* and BUCKET_NAME on the app
fly secrets unset AWS_ENDPOINT_URL_S3 --stage -a <app>
fly secrets set --config deploy/fly.toml \
  ESEC_SERVER_GITHUB_CLIENT_ID=Iv23li... \
  ESEC_SERVER_GITHUB_CLIENT_SECRET=... \
  ESEC_SERVER_BOOTSTRAP_TOKEN="$(openssl rand -base64 24)" \
  LITESTREAM_BUCKET=<the BUCKET_NAME it printed> \
  LITESTREAM_ENDPOINT=fly.storage.tigris.dev \
  LITESTREAM_REGION=auto
fly deploy --config deploy/fly.toml --dockerfile deploy/Dockerfile
```

Litestream reads the Tigris credentials from `AWS_ACCESS_KEY_ID` and
`AWS_SECRET_ACCESS_KEY`. `AWS_ENDPOINT_URL_S3` is removed because it bypasses
Litestream's Tigris detection, which turns on Tigris's strong consistency.
Any other S3-compatible bucket works too: set `LITESTREAM_ENDPOINT`,
`LITESTREAM_REGION`, `LITESTREAM_ACCESS_KEY_ID` and
`LITESTREAM_SECRET_ACCESS_KEY` for it.

Run a single machine. The database is SQLite on the volume.

Use a dedicated bucket for Litestream, with credentials limited to it. Keep
those credentials outside the vault: you need them to restore the server.
A Tigris bucket belongs to the same Fly account as the app; the
full-loss procedure below covers losing both.

The server is built from this repository alone; it depends on esec v0.9.0
or later from the module proxy.

## Step 4: Connect your first machine

On a machine that already has your identity and keyrings:

First print your account creation token. Each GitHub user id has its own
token, derived from the bootstrap secret:

```sh
fly ssh console --config deploy/fly.toml -C "esec-vault-server -bootstrap-token-for 53101343"
```

Then sign in, and paste the token when asked:

```sh
esec vault login https://vault.example.com
```

The token is needed once per account, at its creation. A GitHub login alone
cannot create an account. Without the token, someone who took over an
allowlisted GitHub account before its owner's first login could create the
vault account with their own keys.

A token works only for its own GitHub id. Give each person theirs through
another channel. The CLI reads it from a hidden prompt or from
`ESEC_VAULT_BOOTSTRAP_TOKEN`; there is no command-line flag, because command
lines are visible to other users of the machine.
Changing the bootstrap secret invalidates tokens not yet used; existing
accounts are not affected.

1. Open the printed address and sign in with GitHub.
2. Type the code your terminal shows, then confirm.
3. The first login creates the account and uploads the vault.

Write down the **Account key** words it prints. Every later device shows the
same words.

## Run without Fly

Build the binary and run it behind a TLS-terminating proxy:

```sh
go build -o /usr/local/bin/esec-vault-server ./cmd/esec-vault-server
```

Example systemd unit:

```ini
[Unit]
Description=esec vault server
After=network-online.target

[Service]
User=esec
Environment=ESEC_SERVER_CONFIG=/etc/esec-vault/server.toml
EnvironmentFile=/etc/esec-vault/secrets.env
ExecStart=/usr/local/bin/esec-vault-server
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/esec-vault
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

Set `client_ip_header` only when the proxy overwrites that header on every
request, or appends to it. The server takes the last address across all
lines of the header, so a proxy that adds its own line is fine. Otherwise
clients could choose the address recorded in the audit log and used for rate
limits.

## Back up and restore

Litestream replicates every write to the bucket within about a second.

To restore onto an empty volume, start the container: the entrypoint runs
`litestream restore -if-db-not-exists -if-replica-exists` first. To restore
by hand:

```sh
litestream restore -config deploy/litestream.yml -o restored.db /data/esec-vault.db
```

Replication runs about a second behind, so a restore can miss the last
writes. A client that saw them refuses the restored, older chain as a
rollback, which is the intended protection. Sign such a device in again with
`esec vault logout --forget-device` and `esec vault login`.

If the server and its backups are both lost:
- Every signed-in machine still has its keyrings and identity.
- Deploy a new server with an empty database.
- On one machine, run `esec vault logout --forget-device`, then
  `esec vault login`. The account is created again from that machine.
- Other machines sign in again and are approved as new devices.

The new account has a new chain, so its account key words change. Tell
everyone who checks them.

## Manage access

| Task | How |
|---|---|
| Add a person | Add their numeric id to `allowed_github_ids` and redeploy. Print their token with `esec-vault-server -bootstrap-token-for <id>` and send it to them. They sign in and create their own account. The Admin page shows when they have. |
| Remove a person | Remove the id and redeploy. Their sessions fail on the next request. Their data stays until you delete it. Shared projects still list them (their pages mark them "removed from the server"): an admin of each project removes them with `esec vault team remove LOGIN` and rotates the keys they could read. |
| Rotate the GitHub client secret | Generate a new secret in the OAuth app, run `fly secrets set ESEC_SERVER_GITHUB_CLIENT_SECRET=...`, then delete the old secret. |

## Everyday operations

| Task | How |
|---|---|
| Let a person in | Add their numeric GitHub id to `allowed_github_ids`, redeploy, send them `esec-vault-server -bootstrap-token-for <id>`. They run `esec vault login URL` and `esec vault team prove`. |
| Share a project with them | In the repository: `esec vault team create` (once), `esec vault team add LOGIN --env dev`. Or on the project's page, then sign it. |
| Give CI its secrets | A machine group per environment, a token per repository bound to it: `esec vault group token acme/ci deploy --github-repo acme/store --github-ref refs/heads/main --out - \| gh secret set ESEC_VAULT_MACHINE_KEY`. See the README's recipes for the workflow. |
| Run an app (Fly.io, containers) | The group token as the app's secret `ESEC_VAULT_MACHINE_KEY`; start it with `esec-vault machine run -- esec run prod -- ./app`. |
| Add a server | On it: `esec-vault machine join GROUP --server URL --fingerprint WORDS`; on a laptop: `esec vault group approve GROUP`. |
| Autoscaling | `esec vault group token GROUP autoscale --expires 90d` in the image; machines run `esec-vault machine join` at boot. |
| Remove a machine or token | The group's page › **Remove** (blocked at once), or `esec vault group remove GROUP NAME`. Rotate what it lists. |
| Remove a person | `esec vault team remove LOGIN` in each project, then `esec vault env rotate ENV` for each environment listed; remove their id from `allowed_github_ids`. |
| Approve web changes | `esec vault changes`, the dialog on a computer running the background service, or a passkey on the Changes page. |
| See what needs doing | The web overview; `esec vault team`, `esec vault group`, `esec vault changes`. |
| Upgrade | Deploy the new server version, then update the CLIs (`go install ...@vX` or the release archives) and run `esec-vault daemon upgrade` on each computer. Read the CHANGELOG first: some releases need every colleague's CLI updated before a feature is used. |

## Respond to incidents

| Event | Response |
|---|---|
| Lost or stolen device | On a trusted device: `esec vault devices revoke <id>`. Or suspend it at once on the web overview or the device's page, then revoke. Rotate the environment keys it could read (`esec vault env rotate`) and the secret values at their providers. |
| Unknown pending device | Do not approve it. Suspend it on the web overview. Check the **Activity** page, and secure your GitHub account. With [alerts](#send-alerts) on, you are told when one appears. |
| Unknown device added via SSH agent | Revoke it. Disable the slot (`esec vault agent-unlock disable`). Treat the SSH key as exposed. |
| Server compromised | The attacker gets metadata and can deny service. They cannot decrypt anything or add devices: clients verify the chain and refuse rollbacks. Redeploy from a clean image, rotate the GitHub client secret and Litestream credentials, and review the audit log. |
| GitHub account taken over | The attacker can create pending devices but cannot decrypt anything without approval, the recovery phrase, or an SSH-agent slot. Secure the GitHub account, then suspend any unknown devices. |
| Someone leaves a team | An admin runs `esec vault team remove LOGIN`, then `esec vault env rotate ENV` in the repository for each environment it lists, and changes the secret values they may have seen. The project page shows what is left. |
| Machine key leaked | `esec vault machine remove NAME`: the server stops handing it keys at once. Rotate the environments it could read. A machine bound to GitHub Actions is useless outside its repository and refs even before that. |
| Group machine or enrollment token leaked | Remove it on the group's web page (it is blocked at once), or `esec vault group remove GROUP NAME`. The group gets a new key; rotate the environments `group show` lists. Machines it enrolled are listed with it on the group page: remove those you do not recognise. |
| A passkey is lost or stolen | Remove it on **Overview › Signing** and sign that on a device, or run `esec vault delegate remove NAME`. Its signatures stop counting from then on. Review the projects' and groups' histories for changes it signed. |
| The server's database leaked | Besides the metadata, the attacker holds the server's signing key: they can sign removals for people who let the server do so (never additions). Everyone turns it off with `esec vault delegate server --off`; redeploy, and they turn it on again for the new key. |
| Unknown machine asks to join a group | Turn it away on the group's page, or answer `no` in `esec vault group approve`. If the words a machine shows do not match the ones your device shows, do not let it in, and delete the machine's key file: the server may be lying to it. |

## Close the server to new devices during an attack

If a flood of sign-ins is slowing the server, or you suspect someone controls
an allowlisted GitHub account, close it to new devices:

```sh
fly secrets set --config deploy/fly.toml ESEC_SERVER_NEW_DEVICES=closed
```

While closed, devices that are already trusted can still sign in, and so can
browsers that signed in before. New devices and new browsers are refused.
Set it back to `open` when the attack is over; nothing else changes.

## Send alerts

The server can tell people about security events on their account:

- a new device signed in and waits for approval;
- a device was approved (or the account was created);
- a device was suspended or revoked;
- someone signed in on the web from a browser the account never used, or
  one that signed out since;
- in a shared project: someone was added (to them), someone was removed
  or left (to every remaining member, since the keys they could read need
  replacing), and a machine was added or removed (to the project's
  admins).

Alerts go by email, through [Lettermint](https://lettermint.co), and to a
webhook. Both are optional, and the server runs without either.

**Email.** Verify a sending domain in Lettermint, create a project token,
then:

```toml
[alerts]
email_from = "esec vault <vault@example.com>"
email_to = ["security@example.com"]   # the operator: every account's alerts
```

```sh
fly secrets set --config deploy/fly.toml ESEC_SERVER_LETTERMINT_TOKEN=lm_...
```

With email on, each person can enter an address under **Alerts** on their
overview. Alerts go there only after they open the confirmation link sent to
it and press **Confirm**. When the address changes or alerts are turned
off, the old address is told. `email_to` is optional; without it, only
people who confirmed an address get email. Emails are plain text, with open
and click tracking off.

**Webhook.** Set `ESEC_SERVER_ALERT_WEBHOOK_URL` (it receives every
account's alerts) and, to sign posts, `ESEC_SERVER_ALERT_WEBHOOK_SECRET`.
Each post is JSON:

```json
{"id": "alt_42", "type": "device.registered", "time": "2026-10-19T20:23:52Z",
 "server": "https://vault.example.com",
 "account": {"id": "gh:53101343", "github_id": 53101343, "github_login": "mscno"},
 "device": {"id": "d_...", "name": "laptop", "platform": "darwin/arm64"},
 "ip": "203.0.113.7", "title": "New device waiting for approval",
 "text": "esec vault: A new device, \"laptop\" ... https://vault.example.com/devices/d_...",
 "url": "https://vault.example.com/devices/d_..."}
```

`type` is `device.registered`, `device.added`, `device.suspended`,
`device.revoked`, `web.new_browser`, `project.member_added`,
`project.member_removed`, `project.machine_added`,
`project.machine_removed`, `group.machine_added`, `group.machine_removed`
or `group.admin_added`; project alerts also carry `project`, and group
alerts `group`. `text` is the whole message, so a
Slack incoming webhook shows it as is. The headers are
`X-Esec-Vault-Event` (the type), `X-Esec-Vault-Delivery` (the id),
`X-Esec-Vault-Timestamp` (Unix seconds) and, with a secret,
`X-Esec-Vault-Signature`: `sha256=` and the hex HMAC-SHA256, keyed with the
secret, of the timestamp, a `.`, and the raw body. Check it in constant time
and reject old timestamps.

**Delivery.** Alerts are queued in the database in the same transaction as
the event, so a crash or restart loses none. A worker sends them within
seconds and retries failures for about 11 hours (server errors, timeouts,
rate limits). An email Lettermint rejects, or a webhook answering 4xx, is not
retried. Retries reuse a Lettermint idempotency key, so an email is never
sent twice. The Admin page shows how many alerts were sent, are waiting or
failed in the last 7 days, and the last error. Sent and failed alerts are
deleted after 30 days.

Check the setup from the server:

```sh
fly ssh console --config deploy/fly.toml -C "esec-vault-server -test-alert"
```

It sends a test alert to `email_to` and the webhook right away and prints
any error.

Alerts carry metadata the server already holds: logins, device names and
platforms, addresses, times. Lettermint and the webhook's receiver see it.
They never carry keys or the words a new device shows.

## Shared projects and machines

Shared projects need nothing to set up: any account on the server can
share a project and add other accounts. The server stores each project's
signed chain and the grants that carry keys, sealed to their recipients,
and checks them with the same rules clients use; it cannot read the keys or
change who may read them.

Machines fetch their keys from `POST /v1/machines/keys` without a session:
the machine's own key signs each request, and a nonce stops replays. For a
machine bound to GitHub Actions, the server also checks the job's OIDC
token: its signature against the keys at
`https://token.actions.githubusercontent.com/.well-known/jwks` (fetched on
first use and cached for a day, so the server needs outbound HTTPS), the
issuer, the audience (the server's `base_url`), its lifetime, and the
repository, its id, the ref and the deployment environment the machine
allows. Requests are limited to 600 an hour per machine and per address.
Each use is in the project's log on its page, with the repository, ref and
run of an OIDC job; refused tokens are logged too.

## Machine groups

Machine groups need nothing to set up either. A group's chain records its
admins, machines, enrollment tokens, its key and the projects it takes keys
from; the server checks it with the same rules machines use. Machines use
four endpoints without a session, each signed by the machine's or token's
own key:

| Endpoint | What | Limit |
|---|---|---|
| `POST /v1/fleet/keys` | a machine's group key and its projects' keys, all sealed | 600 an hour per machine; 1200 an hour per address |
| `POST /v1/fleet/enroll` | a token adds a machine (signed link and key grant) | 300 an hour per token and per address |
| `POST /v1/fleet/join` | a machine asks to join | 30 an hour per address; 100 waiting per group and 10 per address, each for 24 hours |
| `POST /v1/fleet/join/status` | whether it was let in | 1200 an hour per address |

A token or machine bound to GitHub Actions is checked like a project
machine (above). The server refuses removed, expired and blocked machines
and tokens; removing one on the web page blocks it at once, before an
admin's device signs the removal. Every fetch, enrollment, refusal and
join request is in the group's log on its page. A group's page, chain and
log are shown to its admins and to members of the projects it takes keys
from; addresses, join requests and the log only to its admins and server
admins. Machines' join requests,
web changes and the log are deleted after 7 days, 90 days and a year.

## Signing on the web

People can let a passkey, or the server, sign some changes for them
(**Overview › Signing**).

Passkeys work only on the **signer page**, a static page (`signer/` in the
esec-vault repository) hosted apart from the server, at `signer_url`
(default `https://sign.` and the server's host). Publish it with GitHub Pages
(the repository's "Signer page" workflow does) or any static host, at that
name, with its `CNAME` file set to it. Its origin is the passkeys' relying
party, and devices accept only passkeys bound to it, so the vault server
cannot make or use one. Whoever controls the signer's host is trusted
instead: keep it on an account apart from the server, verify the domain with
GitHub so nobody else can claim it, and review changes to `signer/`. The
server answers the signer's requests (`/signer/v1/...`) only from that
origin (CORS, with a header no form can send), using the person's web
session cookie; the two hosts must be on the same site (same registrable
domain). The server's own Ed25519 key is made on first use
and kept in the `server_keys` table; back it up with the database. Losing it
only means people let the server sign removals again; anyone with it can sign
removals for the people who allowed it, so treat the database as the secret
it is. Passkeys need the server's `base_url` to be its real https origin:
they are bound to it, and changing the domain means registering them again.

## Web pages

The signed-in pages are live (Datastar, vendored with the server; no
outside scripts or CDNs). Each page has its own content security policy
nonce. Open pages poll the server every 10 to 15 seconds, only while
visible; behind a proxy, that is a few small GET requests a minute per open
tab. Changes made on the pages wait in the `changes` table for an admin's
device (`esec vault changes`); applied and dismissed ones are deleted after
90 days.

## Monitor

- `GET /healthz` returns `ok`.
- Logs are JSON on stderr. A `request failed` line is a server error.
- Each person's **Overview** page shows their devices with last address and
  time, unlock slots, signed-in browsers, and what needs attention: devices
  waiting for approval, suspended devices not yet revoked, devices unseen
  for 90 days, slots about to expire, and an account only one device can
  open. **Activity** lists their audit log with filters, and **Vault** the
  stored versions.
- The read-only **Admin** page, for `admin_github_ids`, shows the server's
  version and settings, totals of accounts, devices, sessions and storage,
  every allowed id with its state (never signed in, no account yet, active,
  removed from the allowlist), and server-wide security events: refused
  sign-ins, new devices, suspensions, revocations and key rotations. Each
  account has a page with its devices and activity. It never shows keys,
  fingerprint words or account creation tokens, and it cannot change
  anything: only the account owner suspends devices or ends sessions.
  It also shows whether email and webhook alerts are on, and their delivery
  in the last 7 days, and every shared project with its members, machines,
  keys still to send and keys to rotate. Each project's page (read-only for
  admins) shows who reads which environment, whether their devices have the
  keys, the machines with their last use, and the project's history.
