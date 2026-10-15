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
```

List numeric GitHub user ids, never usernames. Find an id with
`gh api users/<login> --jq .id`.

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
| `ESEC_SERVER_CLIENT_IP_HEADER` | `client_ip_header`; set only behind a proxy that sets it |
| `ESEC_SERVER_VAULT_HISTORY` | `vault_history` (default 50) |

`base_url` must use https. Plain http is accepted only for `localhost`.

## Step 3: Deploy on Fly.io

These steps use [`deploy/fly.toml`](../../deploy/fly.toml) and
[`deploy/Dockerfile`](../../deploy/Dockerfile). Replace the `REPLACE` values
in `fly.toml` first.

```sh
fly launch --no-deploy --copy-config --config deploy/fly.toml
fly volumes create esec_vault_data --size 1 --config deploy/fly.toml
fly secrets set --config deploy/fly.toml \
  ESEC_SERVER_GITHUB_CLIENT_ID=Iv23li... \
  ESEC_SERVER_GITHUB_CLIENT_SECRET=... \
  ESEC_SERVER_BOOTSTRAP_TOKEN="$(openssl rand -base64 24)" \
  LITESTREAM_BUCKET=esec-vault-server \
  LITESTREAM_ENDPOINT=https://<account>.r2.cloudflarestorage.com \
  LITESTREAM_REGION=auto \
  LITESTREAM_ACCESS_KEY_ID=... \
  LITESTREAM_SECRET_ACCESS_KEY=...
fly deploy --config deploy/fly.toml --dockerfile deploy/Dockerfile
```

Run a single machine. The database is SQLite on the volume.

Use a dedicated bucket for Litestream, with credentials limited to it. Keep
those credentials outside the vault: you need them to restore the server.

The code needs esec v0.9.0, which is not released yet. Until then `go.mod`
pins v0.8.1, and a local `go.work` (not committed) builds against the
`feat/sealed-keyring` branch in `../esec`. A Docker or CI build without that
workspace fails. Tag and push esec v0.9.0, run
`go get github.com/mscno/esec@v0.9.0`, and commit `go.mod` and `go.sum`
before you deploy.

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
request. Otherwise clients could choose the address recorded in the audit
log and used for rate limits.

## Back up and restore

Litestream replicates every write to the bucket within about a second.

To restore onto an empty volume, start the container: the entrypoint runs
`litestream restore -if-db-not-exists -if-replica-exists` first. To restore
by hand:

```sh
litestream restore -config deploy/litestream.yml -o restored.db /data/esec-vault.db
```

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
| Add a person | Add their numeric id to `allowed_github_ids` and redeploy. Print their token with `esec-vault-server -bootstrap-token-for <id>` and send it to them. They sign in and create their own account. |
| Remove a person | Remove the id and redeploy. Their sessions fail on the next request. Their data stays until you delete it. |
| Rotate the GitHub client secret | Generate a new secret in the OAuth app, run `fly secrets set ESEC_SERVER_GITHUB_CLIENT_SECRET=...`, then delete the old secret. |

## Respond to incidents

| Event | Response |
|---|---|
| Lost or stolen device | On a trusted device: `esec vault devices revoke <id>`. Or suspend it at once on the web account page, then revoke. Rotate the environment keys it could read (`esec vault env rotate`) and the secret values at their providers. |
| Unknown pending device | Do not approve it. Suspend it on the account page. Check the audit log, and secure your GitHub account. |
| Unknown device added via SSH agent | Revoke it. Disable the slot (`esec vault agent-unlock disable`). Treat the SSH key as exposed. |
| Server compromised | The attacker gets metadata and can deny service. They cannot decrypt anything or add devices: clients verify the chain and refuse rollbacks. Redeploy from a clean image, rotate the GitHub client secret and Litestream credentials, and review the audit log. |
| GitHub account taken over | The attacker can create pending devices but cannot decrypt anything without approval, the recovery phrase, or an SSH-agent slot. Secure the GitHub account, then suspend any unknown devices. |

## Monitor

- `GET /healthz` returns `ok`.
- Logs are JSON on stderr. A `request failed` line is a server error.
- The web account page shows each device's last address and time, the slots,
  and the last 100 audit entries.
