# esec runbook: projects, people, workloads and keys

How to set up a project, give people and apps access, and keep keys fresh,
with zero-knowledge sharing for people and keyless workloads on Fly.io
backed by a cloud KMS. Replace `acme`, `acme/api` and the names with yours.

## Who holds what

| Where | Holds | Unlocked by |
|---|---|---|
| Git repository | encrypted secrets files (`.env.prod`, `prod.etoml`, ...) and `.esec-project` | nothing: ciphertext only |
| Your laptop, your dev VMs | the environment keys you may read, in your keyring | your identity (recovery phrase) and device keys |
| Vault server | signed chains (who belongs to the organisation, who reads what), keys sealed to people, groups and workloads | nothing: it cannot open any of them |
| Cloud KMS (GCP) or OpenBao | RSA keys that wrap group keys, approved in the organisation's chain | only the workloads its IAM policy (or JWT role) names |
| Fly.io app | nothing secret: a workload descriptor in `fly.toml` | its Fly.io OIDC token, at each start |

A secret's value lives only in git (encrypted) and in the memory of the
people and apps allowed to read it.

## One-time setup

### Your machine

```sh
esec vault setup                                   # identity, recovery phrase, backup, background service
esec vault login https://vault.parap.ly
esec vault access prove                            # GitHub SSH proof, so others can add you
```

Write the 24-word recovery phrase down offline. Optional:

```sh
esec vault delegate server                         # let the server sign removals made on the web
```

and add a passkey under **Overview › Signing** to sign web changes with a touch.

### Your organisation

```sh
esec vault org create acme                       # you are its first admin
esec vault org add acme bob --admin              # a second admin, so it never depends on one person
esec vault org add acme alice                    # members
esec vault org set acme --members-only --require-github-proof --max-token-days 90
```

Its chain records who belongs to acme, the KMS keys its workloads may use,
and its rules; devices check all three when they sign. Every other admin of
an acme project or group confirms its fingerprint once on their device
(`esec vault org trust acme`, comparing the words `esec vault org acme`
shows on yours); until then their device takes nobody out of what they
administer. Only its people
create projects and groups named `acme/...` from then on. Projects made
before keep working; their members' devices now tell them whether a
project's creator belongs to acme. Everything here has a form on
`https://vault.parap.ly/orgs/acme` too, signed by your device (a dialog of
the background service, or `esec vault changes`) or a passkey.

### Google Cloud KMS for workloads (once per Fly.io organisation)

```sh
esec vault kms setup gcp --project acme-vault --fly-org acme --fly-app api,web           # prints the commands
esec vault kms setup gcp --project acme-vault --fly-org acme --fly-app api,web --apply   # runs them
```

It creates one software RSA key (`rsa-decrypt-oaep-3072-sha256`), a workload
identity pool trusting `https://oidc.fly.io/acme`, and an IAM binding per
app, which decides which apps may decrypt with the key. It prints the
`--gcp-key` and `--gcp-provider` values for the next step. To let a new app
in later, run it again with that app in `--fly-app`: what exists already is
left as it is.

Then approve the key in the organisation; your device reads its public half
from Cloud KMS (gcloud signed in), so the approval names the real key:

```sh
esec vault org kms add acme gcp-prod --gcp-key projects/acme-vault/locations/europe-west1/keyRings/esec/cryptoKeys/workloads/cryptoKeyVersions/1 \
  --gcp-provider projects/123456789/locations/global/workloadIdentityPools/esec-workloads/providers/fly-acme --default
esec vault org set acme --fly-org acme           # the Fly.io organisation new apps run in
```

Cost: about $0.06 a month per key, $0.03 per 10,000 decrypts (one per app
start); token exchange is free. One key can serve every group and app, but
then each app's IAM binding lets it unwrap the others' group keys too (it
still gets only its own sealed keys from the vault). With many apps, give
each its own key (`--key esec-APP` in `kms setup gcp`) and approve it with
`--groups acme/APP`, so it serves that app's group alone: a hundred apps
cost about $6 a month.

### Or a self-hosted OpenBao

```sh
esec vault kms setup openbao --addr https://bao.acme.dev --fly-org acme --fly-app store,api   # prints the bao commands
BAO_ADDR=https://bao.acme.dev BAO_TOKEN=... esec vault org kms add acme fly-store --openbao-key https://bao.acme.dev/transit/esec-store/1 \
  --openbao-role jwt/fly-store --groups acme/store
```

Each app gets its own Transit key, a decrypt-only policy and a JWT role bound
to its Fly.io app. Run OpenBao apart from the vault server, so breaking into
one is not enough.

### The server admins' policy (optional)

On `https://vault.parap.ly/orgs/acme/settings`, the server's admins can add
rules of their own: the longest token lifetime, GitHub proofs required,
whether the server may sign removals, and how often access is reviewed. The
stricter of theirs and the organisation's applies.

## Bootstrap a new project

In the repository:

```sh
esec vault project init acme/api --env dev,staging,prod   # .esec-project, keys, encrypted files
$EDITOR .env.prod                                         # add values (plain)
esec encrypt .env.prod                                    # encrypt them in place
git add .esec-project .env.* && git commit -m "secrets"
esec vault access create                                  # share it; you are its admin
```

### People

```sh
esec vault access grant alice --env dev,staging           # one person
esec vault group create acme/backend                      # or a team
esec vault group add acme/backend alice
esec vault access grant acme/backend --env dev,staging
```

Their devices take the keys in on their next sync (they confirm the
project once). Someone without an account yet: add them on the project's web
page; the invite waits for them.

### A Fly.io app, with no secret stored anywhere

```sh
esec vault org fly-app acme api --read acme/api:prod --read acme/shared:prod
```

or the **Workloads** page of the organisation (**Add a Fly.io app**). It
creates the app's group (`acme/api`) if it is new, lets it read what you
name (you administer those projects), and adds the app as a workload bound
to Fly.io's OIDC tokens for that app, wrapped with the organisation's
default KMS key (`--kms NAME` for another). By hand, the same steps are:

```sh
esec vault group create acme/api
esec vault access grant acme/api --env prod               # in each project it reads
esec vault group workload acme/api api --fly-org acme --fly-app api --gcp-key ... --gcp-provider ...
```

Put the descriptor it prints into `fly.toml` (it is not a secret; the
Workloads page has a copy button for it):

```toml
[env]
  ESEC_VAULT_WORKLOAD = "esecw1_..."
```

and start the app through esec-vault; the image holds `esec`, `esec-vault`,
`.esec-project` and the encrypted files:

```dockerfile
CMD ["esec-vault", "machine", "run", "--", "esec", "run", ".env.prod", "--", "/app/server"]
```

At each start: the Machine asks `/.fly/api` for an OIDC token; the vault
checks it against the workload's policy (org `acme`, app `api`) and returns
the sealed keys; Google exchanges a second token for a short-lived credential
that may decrypt with the KMS key; the group key unwraps in memory and opens
the project's keys; `esec run` decrypts the file. No `fly secrets` at all.

Without a cloud KMS, a group token bound to the app works too (a stored
secret, useless outside the app):

```sh
fly secrets set -a api ESEC_VAULT_MACHINE_KEY="$(esec vault group token acme/production api \
  --expires 90d --fly-org acme --fly-app api --out -)"
```

### CI (GitHub Actions)

```sh
esec vault machine create deploy --env prod --github-repo acme/api --github-ref refs/heads/main --out - \
  | gh secret set ESEC_VAULT_MACHINE_KEY
```

The job needs `permissions: id-token: write` and runs
`esec-vault machine run -- ./deploy.sh`.

## Decrypt locally

### Your laptop

Keys reach your keyring by sync; then, in the repository (name the file, or
use the environment name with `--format env`; `prod` alone means `.ejson.prod`):

```sh
esec run .env.dev -- npm start            # values as environment variables
esec decrypt .env.prod                    # print a file decrypted
esec vault run dev -- npm start           # via the background service: no key file read
```

A new laptop: `esec vault login https://vault.parap.ly`, then approve it from
another device (`esec vault devices approve`, typing the words it shows), or
recover with the phrase (`esec vault login --recover`).

### A remote dev VM (you, working there)

Treat it as one of your devices:

```sh
esec vault login https://vault.parap.ly --no-browser   # on the VM; then approve from your laptop
```

It gets your keys like your laptop. Revoke it when you are done with it
(`esec vault devices revoke ID`, or the device's web page).

### A server VM (an app, not a person)

Make it a machine of a group, so it reads only what the group reads:

```sh
sudo esec-vault machine join acme/production --server https://vault.parap.ly \
  --fingerprint WORD-WORD-...            # from: esec vault group show acme/production
esec vault group approve acme/production # on your laptop, comparing the words
```

## Operate

| Task | Command |
|---|---|
| See what needs doing | web **Access** page, or `esec vault access` and `esec vault group` |
| Add or change a secret value | edit the file, `esec encrypt .env.prod`, commit, deploy: no key moves |
| Give access for a while | `esec vault access grant alice --env prod --for 8h` |
| Answer access requests | `esec vault access requests` (`--grant ID`, `--deny ID`) |
| Remove someone | `esec vault access revoke alice` or `esec vault access offboard alice` |
| Someone leaves the company | `esec vault org remove acme alice` (or **People** › **Remove**): every admin's device takes them out of its projects and groups |
| Approve, or withdraw, a KMS key | `esec vault org kms add` / `remove`, or **Settings** › **KMS keys** |
| Add a Fly.io app | `esec vault org fly-app acme APP --read acme/api:prod`, or **Workloads** › **Add a Fly.io app** |
| Change the rules | `esec vault org set acme ...`, or **Settings** › **Rules and defaults** |
| Review who reads a project | `esec vault access review` (or the project page) |
| Sign changes made on the web | `esec vault changes` (or a passkey) |
| A device is lost | suspend it on its web page, then `esec vault devices revoke ID` |
| Remove an app | `esec vault group remove acme/production api` |

## Rotate keys

**Environment keys** (the keys that encrypt the files). Rotate when someone
who could read an environment loses access (esec lists it after every
removal), when a device or app may be compromised, and on a schedule if you
want one:

```sh
esec vault env rotate prod               # in the repository: new key, files re-encrypted
git commit -am "rotate prod" && fly deploy
```

People get the new key by sync; groups get it sealed to the group key at
once, so workloads pick it up at their next start. Also change the secret
values themselves where someone who left may have seen them.

**Group keys** rotate on their own when a person, machine, token or
workload leaves a group (`esec vault group rotate acme/production` by hand).
Workloads need nothing: their new grant is wrapped locally with the KMS
public key.

**The KMS key**: create a new key version in Cloud KMS (or OpenBao), approve
it (`esec vault org kms add acme gcp-prod-2 ...`), and move the workloads to
it: **Workloads** › **Move**, or

```sh
esec vault group rekey-workloads acme/api --gcp-key .../cryptoKeyVersions/2 --gcp-provider ...
```

Their descriptors stay; they unwrap with the new key from their next start.
Then withdraw the old key (`esec vault org kms remove acme gcp-prod`) and
disable its version. The same moves a workload from Cloud KMS to OpenBao.
Only the wrapping of group keys changes; no secret moves.

**Your own user key**: `esec vault devices revoke` rotates it; the vault
re-seals everything to your other devices.

## Troubleshooting

| Message | Fix |
|---|---|
| `this needs an OIDC token from Fly.io Machines of acme` | run on a Fly.io Machine of that app; the app name must match `--fly-app` |
| `google's token exchange refused ... attribute condition` | the app is in another Fly.io organisation than the provider trusts; run `kms setup gcp` again with `--fly-org` |
| `cloud KMS refused to decrypt` | the IAM binding for the app is missing: `kms setup gcp ... --apply` |
| `the group key was not sent to it yet` | an admin's device sends it: `esec vault access sync` |
| `... is archived` | the project was archived or moved; `esec vault access` shows where |
| `the organisation acme has not approved that KMS key` | approve it first: `esec vault org kms add` (or Settings on the web) |
| `acme is an organisation, and you are not in it` | an admin adds you: `esec vault org add acme LOGIN` |
| `acme lets only its people into its projects and groups` | add them to the organisation first, or turn off `--members-only` |
| `projects or groups named acme/... exist on this server` (org create) | an admin of one of them, or a server admin, sets the organisation up |
