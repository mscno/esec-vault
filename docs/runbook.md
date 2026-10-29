# esec runbook: projects, people, workloads and keys

How to set up a project, give people and apps access, and keep keys fresh,
with zero-knowledge sharing for people and keyless workloads on Fly.io
backed by a cloud KMS. Replace `acme`, `acme/api` and the names with yours.

## Who holds what

| Where | Holds | Unlocked by |
|---|---|---|
| Git repository | encrypted secrets files (`.env.prod`, `prod.etoml`, ...) and `esec.toml` | nothing: ciphertext only |
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
esec vault kms setup gcp --project acme-vault --fly-org acme --fly-app api,web                     # prints the commands
esec vault kms setup gcp --project acme-vault --fly-org acme --fly-app api,web --apply --approve   # runs them, approves the keys
esec vault org set acme --fly-org acme           # the Fly.io organisation new apps run in
```

It creates a workload identity pool trusting `https://oidc.fly.io/acme`, and
for each app its own software RSA key (`esec-api`, `esec-web`;
`rsa-decrypt-oaep-3072-sha256`) that only that app may decrypt with. With
`--approve` your device then reads each key's public half from Cloud KMS
(gcloud signed in) and approves it in the organisation for that app's group
alone (`acme/api`), so the approval names the real key. Without it, the
command prints the `esec vault org kms add` lines to run. To add an app
later, run it again with that app: what exists already is left as it is.

Cost: about $0.06 a month per key, $0.03 per 10,000 decrypts (one per app
start); token exchange is free: a hundred apps cost about $6 a month. One
key for every app (`--key workloads`) is cheaper, but then each app may
decrypt what is wrapped for the others, should the server hand it over:
keep a key per app.

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
esec vault project init acme/api --env dev,staging,prod   # esec.toml, keys, encrypted files
$EDITOR .env.prod                                         # add values (plain)
esec encrypt .env.prod                                    # encrypt them in place
git add esec.toml .esec .env.* && git commit -m "secrets"
```

### People

```sh
esec vault share dev,staging --with alice                 # one person, pinned by GitHub id
esec vault share dev,staging --with "group acme/backend"  # or a team
git add esec.toml .esec && git commit -m "share dev and staging"
```

They open the keys sealed to them in `.esec/` with their own keys after
`git pull`; someone without an account yet is sealed in once they sign up.
On the vault server (membership, groups, offboarding, machines):

```sh
esec vault access create                                  # you are its admin
esec vault access grant alice --env dev,staging           # one person
esec vault group create acme/backend                      # or a team
esec vault group add acme/backend alice
esec vault access grant acme/backend --env dev,staging
```

Their devices take the keys in on their next sync (they confirm the
project once). Someone without an account yet: add them on the project's web
page; the invite waits for them.

### CI and deploys

```sh
esec vault ci add actions --env staging,prod --github acme/api   # the GitHub secret ESEC_AGE_IDENTITY
esec vault ci add deploy --env prod --fly api                    # the Fly.io secret
```

Each gets its own age key, sealed into those environments (commit `.esec/`),
and runs `esec run prod -- ./deploy.sh` with esec alone. Most CI needs only
this. The advanced route below, for workloads that hold no secret, needs the
project shared on the vault server (`esec vault access create`).

### A Fly.io app, with no secret stored anywhere

In the app's repository, beside its `fly.toml`:

```sh
esec vault kms setup gcp --project acme-vault --fly-org acme --fly-app api --org acme --apply --approve   # once per app: its own key
esec vault app init --env prod     # checks the repository, sets up the app, writes fly.toml, checks again
git add fly.toml && git commit -m "esec vault workload" && fly deploy
esec vault env status prod         # the app started with its keys
```

`app init` refuses to set anything up while the repository would ship a
broken app: no secrets file for the environment, a value in the clear, a
`.dockerignore` that leaves the encrypted file out of the image. It warns
when the Dockerfile does not start the app through `esec-vault machine run`.
Then it makes the app's group (`acme/api`), lets it read the environment
(keeping what it reads already), adds the app as a workload bound to
Fly.io's OIDC tokens of that app alone, wraps the group key with the app's
own KMS key, and writes the descriptor into `fly.toml`.

Before every deploy, in CI too, check it still holds:

```sh
esec vault app check --env prod    # exits 1 with how to fix each finding
```

It checks the files (nothing in the clear, each encrypted to the current
key), `fly.toml` (the descriptor names a workload of that very app),
`.dockerignore` and the Dockerfile, that the group reads the environment
and has its key, that the workload's group key was sent, and that its KMS
key is one the organisation approves.

For several apps at once, or apps whose repositories you do not have:

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
`esec.toml` and the encrypted files:

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

### CI bound to the repository (GitHub OIDC, on the vault server)

```sh
esec vault machine create deploy --env prod --github-repo acme/api --github-ref refs/heads/main --out - \
  | gh secret set ESEC_VAULT_MACHINE_KEY
```

The job needs `permissions: id-token: write` and runs
`esec-vault machine run -- ./deploy.sh`.

## Decrypt locally

### Your laptop

Keys open from `.esec/` when they are sealed to you, or reach your keyring by
sync; then, in the repository, name the file or the environment. For a name,
esec searches every supported format and naming pattern, and fails when more
than one file matches (then pass `--format` or the path):

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
| Remove someone | `esec vault unshare prod --with alice --rotate`; on the server `esec vault access revoke alice` or `esec vault access offboard alice` |
| Someone leaves the company | `esec vault org remove acme alice` (or **People** › **Remove**): every admin's device takes them out of its projects and groups |
| Approve, or withdraw, a KMS key | `esec vault org kms add` / `remove`, or **Settings** › **KMS keys** |
| Add a Fly.io app | `esec vault org fly-app acme APP --read acme/api:prod`, or **Workloads** › **Add a Fly.io app** |
| Change the rules | `esec vault org set acme ...`, or **Settings** › **Rules and defaults** |
| Review who reads a project | `esec vault access review` (or the project page) |
| Sign changes made on the web | `esec vault changes` (or a passkey) |
| A device is lost | suspend it on its web page, then `esec vault devices revoke ID` |
| Remove an app | `esec vault group remove acme/production api` |

## Run many projects at once

| Task | Command |
|---|---|
| Everything that waits for you | `esec vault todo` (`--json`) |
| Every key to rotate, across projects | `esec vault access list --needs rotate --org acme` |
| Give a team several projects at once | `esec vault access grant acme/backend --env dev,staging --project 'acme/*' --skip-missing-env` |
| Take someone out of several projects | `esec vault access revoke alice --project acme/api,acme/web --yes` |
| Set up many Fly.io apps | `esec vault kms setup gcp --project acme-vault --fly-org acme --fly-app api,web,worker --apply --approve`, then `esec vault org fly-app acme api web worker --read acme/shared:prod --json` |
| See every workload, the idle ones | `esec vault org workloads acme --idle 30d` (or the Workloads page, with its filters) |
| Move every workload to a new key | `esec vault org rekey acme --from gcp-prod --to gcp-prod-2 --dry-run`, then without `--dry-run` |

Setup commands (`group create`, `group add`, `org create`, `org add`,
`access create`, `org fly-app`) are safe to run again, so a script can make
sure things are in place.

## Rotate a credential (a database password, an API key)

The value lives in the encrypted files of each repository that uses it.
Find them, give them the new value, deploy, check, then revoke the old one:

```sh
esec vault secrets where DATABASE_URL --root ~/src                          # every file that holds it
esec vault secrets rotate DATABASE_URL --env prod --root ~/src --dry-run     # what would change
esec vault secrets rotate DATABASE_URL --env prod --root ~/src               # asks for the new value
```

The value is typed (twice, never shown) or piped in (`op read ... |`), never
put on the command line. `--generate 32` makes a random one for secrets you
own (session keys, webhook secrets). Only that line of each file changes,
and no private key is needed to write it; where your device has the key it
reads the value back first. Then, in each repository:

```sh
git commit -am "rotate DATABASE_URL" && fly deploy
esec vault env status prod --since 15m     # ✗ for each deployment still running with the old value
```

Revoke the old value at the database or provider only when every
deployment shows ✓. One value in one repository: `esec vault secrets set
API_KEY --env prod`.

Keep values from slipping in unencrypted with a pre-commit check:

```yaml
# lefthook.yml
pre-commit:
  commands:
    secrets:
      run: esec vault secrets lint
```

## Rotate keys

**Environment keys** (the keys that encrypt the files). Rotate when someone
who could read an environment loses access (esec lists it after every
removal), when a device or app may be compromised, and on a schedule if you
want one:

```sh
esec vault env rotate prod               # in the repository: new key, files re-encrypted
git commit -am "rotate prod" && fly deploy
esec vault env status prod               # every deployment started with the new key
```

After someone leaves, everything at once, across your checkouts:

```sh
esec vault access list --needs rotate --org acme
esec vault env rotate-exposed --root ~/src --org acme     # then commit and deploy each
```

People get the new key from its seal, or by sync; groups get it sealed to the group key at
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
The group key is the same, so if you move because the old KMS (or its
host, or its federation) may be compromised, also give the group a new key:
`esec vault group rotate acme/api`. When you remove a workload, remove its
IAM binding on the KMS key (or its OpenBao role) as well.
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
| `the group key was not sent to it yet` | an admin's device sends it: `esec vault sync` |
| `... is archived` | the project was archived or moved; `esec vault access` shows where |
| `app check`: `is left out of the image by .dockerignore` | add `!.env.prod` to `.dockerignore`: the file is encrypted |
| `app check`: `encrypted to an earlier prod key` | the file was not re-encrypted after a rotation: `esec vault env rotate prod` in that repository |
| `app check`: `bound to ... not to the app fly.toml names` | the descriptor belongs to another app: `esec vault app init` |
| `secrets lint`: `in the clear` | a value was added after encrypting: `esec encrypt FILE` |
| `the organisation acme has not approved that KMS key` | approve it first: `esec vault org kms add` (or Settings on the web) |
| `acme is an organisation, and you are not in it` | an admin adds you: `esec vault org add acme LOGIN` |
| `acme lets only its people into its projects and groups` | add them to the organisation first, or turn off `--members-only` |
| `projects or groups named acme/... exist on this server` (org create) | an admin of one of them, or a server admin, sets the organisation up |
