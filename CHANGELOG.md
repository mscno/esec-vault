# v0.22.0

Needs esec v0.12.0. Redeploy the vault server before registering security
keys: it must accept the new `security_key_add` chain links.

**Keys live with the code.** Each environment's private key is sealed in
its repository, `.esec/<env>.age` (a standard age file), to its readers and
always to a recovery key the 24 words derive. The repository and the phrase
are enough to recover every key in every commit; nobody handles a key.

- **Readers by GitHub id**: `esec vault share dev --with alice` pins alice by
  her numeric GitHub id, seals to her user key (or, for guarded
  environments, her YubiKeys) from her signed chain; someone without an
  account is pinned and sealed in once they sign up. `unshare --rotate`.
- **Signed records** in `.esec/seals.toml`: `seal check`, `secrets lint`
  (staged too), the pre-commit hook and CI catch a swapped key, an unsealed
  reader or a seal without a recovery key, with no network.
- **YubiKeys as things you plug in**: `security-keys add` registers plugged-in
  keys with a name in your signed chain (everyone who seals for you uses
  them), `setup` provisions one, `test`, `remove`; the background service
  notices a new one. Guarded environments are sealed straight to security
  keys: one touch opens one environment. The shared guard identity is gone
  (`guard init`, `holders`, `recover`, `check`, `export`).
- **`seal`**: `status`, `sync` (reseal what changed, open what you can into
  the keyring cache), `check`, `migrate`, `recover` (the phrase reseals
  everything, no security key needed).
- **`ci add NAME --env prod --github OWNER/REPO | --fly APP`**: CI gets its
  own age key, stored with gh or fly, never shown; `esec run` reads with
  `ESEC_AGE_IDENTITY` and nothing else.
- **A new machine needs only your identity**: `setup` (and the background
  service) open every unguarded key of every checkout from the repository.
- **Machines and OIDC workloads still get keys over the network**, guarded
  ones too: the vault server's machines, groups and workloads are sent keys
  the keyring no longer keeps by opening them from the checkout (a guarded
  one with one touch per command); `env rotate` sends the new key it just
  made. `team create` shares every environment of `esec.toml`.
- **Embedded seals** (esec): a binary that embeds `esec.toml`, its file and
  `.esec/<env>.age` needs only `ESEC_AGE_IDENTITY`, which survives
  rotation; `ESEC_PRIVATE_KEY_<ENV>` as a root secret still works.
- `drill` opens every seal with the phrase alone; `verify` counts a sealed
  key as kept in two places. `project init`, `env add`, `env rotate` seal
  before they write (`--offline` is gone).

Many independent projects, keys that cannot be lost, and prod keys only a
touch of your YubiKey opens, so agents can work beside them.

- **`esec.toml` replaces `.esec-project`** (no compatibility): the project
  id, how its files are named (`[files] format`, `name`, applied on every
  machine over `config.toml`), and each environment's current public key
  and guard. `project init`, `env add`, `env rotate` and `guard enable` keep
  it up to date. Needs esec with the same change.
- **Keys are only ever added**: every key is filed under its public key, and
  no write, sync or merge may change or drop one. `keyring repair` files
  keys of older keyrings.
- **Stored twice before use**: `project init`, `env add` and `env rotate`
  wait for a new key to reach the vault server (or the backup destination)
  before encrypting anything to it; a failed upload stops them, and a
  rotation points back at the old key. `--offline` skips it.
- **`esec vault guard`**: environment keys wrapped (with age) to your
  YubiKeys (age-plugin-yubikey) and your recovery key. Every read shows a
  dialog naming the file and the programs that asked, then waits for a
  touch; `session` keys stay open until lock. `guard init`, `enable`,
  `holders add/remove`, `check`, `export` (plain age files for rage).
  `project init --guard prod`, `env add --guard touch`; `env rotate` keeps
  guarded keys guarded. Plain `esec run` says when a key is guarded.
- **`esec vault forward HOST`**: an SSH session whose machine may ask this
  one for guarded keys, each read after a dialog and a touch here.
- **For agents**: `run --mask` / `ESEC_VAULT_MASK` hides values in a
  command's output; `ESEC_VAULT_SESSION` labels reads in the audit log and
  dialogs, which now record the asking programs; `secrets request KEY`
  asks a person for a value in a desktop dialog.
- **`esec vault projects`**: every project on this machine and where it is
  checked out, like a git client's repository list; `show`, `scan`, `add`,
  `remove`, `prune`, with `--json`.
- **`esec vault verify`**: every key used by a checkout or its git history
  is on this device and in a second place, held somewhere at all, and used
  by one project only. The background service runs it daily and notifies
  on problems; `doctor` reports it. **`esec vault drill`** proves the newest
  backup opens with the phrase alone and holds every key.
- **`esec vault activity`**: the local audit log, newest first: which
  programs and agent sessions asked for which keys, and what was decided.
- **Many agents at once**: a command changing keys waits for another one
  (which may be waiting for a touch) instead of failing; the checkout list
  locks too, so no agent's checkout is lost.
- **`esec.toml` edits keep your comments**: only changed lines are
  rewritten. Unknown keys warn instead of failing (a newer esec wrote them);
  `files.name` must show its format and agree with `files.format`, which
  also beats `ESEC_FORMAT` from a shell. `secrets lint` fails a file
  encrypted to another key than esec.toml names.
- **`projects`** says what to fix per environment (`action` in JSON);
  `project init` can be run again safely and prints next steps;
  `guard holders add` with no argument adds every plugged-in YubiKey.
- **`esec vault setup`** onboards a machine in one go: joins your account
  (or recovers from a backup, or creates your first identity, never a
  second one unasked), syncs keys, a second place, the background service,
  your checkouts, guards here what you guard elsewhere, and verifies.
  `--check` only reports; `--json` for scripts and the Mac app.
- **`esec vault hook install`**: a pre-commit hook running `secrets lint
  --staged --offline`, which checks what a commit holds (including a plain
  secrets file for a declared environment) without the network.
- **`project init --json`**: what was set up, and next steps.
- **Mac app** (`macos/EsecVault`): a menu bar app and window over the
  above: a setup checklist (from `setup --check`), activity, projects with actions (new project,
  add environment, rotate, guard), live updates, open at login. Metadata
  only, never values.

Fixed along the way: storing a new key in a backup destination from
`project init`, `env add` or `env rotate` failed with "writer busy" (the
command already held the keyring lock); a monorepo's subprojects were
reported as sharing keys; keys of other people's projects were reported as
lost; `verify` read every object of every repository once per worktree;
`env rotate-exposed` left esec.toml naming the old key and skipped projects
with worktrees; `guard enable` left a clear copy of a key another device had
guarded already; test rigs could reach the real keychain.

# v0.21.0

Rotating credentials and keys, and setting up apps, with checks that
catch mistakes before they ship; findings of another security review.

- **`esec vault secrets`**: secrets files keep key names in the clear, so
  values can be found and replaced without private keys, one line each.
  - `secrets where KEY --root ~/src`: every file that holds a key.
  - `secrets set KEY --env prod`: one value, typed twice unseen or piped,
    never on the command line; `--generate 32` for random ones; read back
    with this device's key where it has it.
  - `secrets rotate KEY --env prod --root ~/src`: one new value in every
    repository that uses it (a database password several services share).
  - `secrets lint`: fails on a value in the clear and on a file encrypted to
    an earlier or another key; for pre-commit hooks and CI.
- **`esec vault env status prod [--since 15m]`**: which deployments started
  with a change and which still run with what they had; people whose
  devices lack the key. It exits 1 while any deployment is behind, so you
  revoke an old credential only once nothing uses it.
- **`esec vault env rotate-exposed --root ~/src`**: rotates every
  environment someone who left may hold, across your checkouts, and sends
  the new keys.
- **`esec vault app init`**: sets up the app in a repository from its
  fly.toml: checks the repository first (secrets file, nothing in the clear,
  `.dockerignore`, Dockerfile), makes its group and workload, keeps what the
  group reads, writes the descriptor into fly.toml, then checks it.
- **`esec vault app check`**: a preflight before each deploy, in CI too:
  files, fly.toml, `.dockerignore`, Dockerfile, the workload being that
  app's, the group reading the environment and holding its key, the
  workload's key sent, its KMS key approved. Each finding says how to fix
  it; it exits 1 on any failure (`--strict`: on warnings too).
- Security review fixes:
  - `group create` and `org create` say "exists already" only for a group or
    organisation this account created: someone else could make one first and
    make you its admin unasked, and a script would then grant it prod;
    `org fly-app` and `app init` likewise use an existing group only when
    you, or someone in the anchored organisation, made it;
  - `access create` checks the verified chain, not the server's word;
  - `kms setup gcp --approve` refuses when another key is approved under the
    name it would use;
  - grants and revokes across projects warn about projects this device saw
    that the server no longer lists;
  - refused workload requests are logged up to a limit per hour, so they
    cannot push the rest out of a group's log; refusal details on project
    pages and exports are for admins.

# v0.20.0

Running many projects, environments and apps; findings of a security
review.

- **`esec vault todo`**: everything that waits for you across every
  project, group and organisation, from the chains your device checks:
  keys to rotate, web changes to sign, machines asking to join,
  organisations to confirm, people who left and are still in, workloads on
  keys not approved. `--json` for scripts and agents.
- **`esec vault access list --needs rotate [--org acme]`**: every
  environment, across projects, whose key someone who left may hold. The
  counts on `access list`, the Projects page and organisation pages now
  include keys exposed through groups, which they left out.
- **Grants and revokes across projects**: `--project acme/api,acme/web` or
  `--project 'acme/*'` (the projects you administer), with
  `--skip-missing-env` where environments differ; one JSON result each.
- **Workloads at scale**: `esec vault org workloads acme` (`--kms`,
  `--never-started`, `--idle 30d`, `--problems`, `--json`, with
  descriptors); `esec vault org rekey acme --to gcp-prod-2 [--from ...]
  [--dry-run]` moves workloads across groups at once;
  `group rekey-workloads --kms NAME` takes an approved key by name.
- **`esec vault org fly-app acme api web worker`**: several apps in one
  command, each with its own group and, by default, its own key; `--json`
  prints each app's descriptor. Running it again says when it moved an app
  to another key.
- **A key per app by default**: `esec vault kms setup gcp` makes `esec-APP`
  for each app, which only that app may decrypt with, and with `--apply
  --approve` approves each in the organisation for that app's group. One
  shared key (`--key`) let each app decrypt what is wrapped for the others,
  should the server hand it over.
- **Safe to run again**: `group create`, `group add`, `org create`, `org add`
  and `access create` succeed with "nothing changed" when it is in place.
- **Web pages**: filters on the tables of Projects, Groups, Access and
  organisations, with chips on Workloads (never started, key problems,
  blocked, by key); copy buttons and filters keep working after a form; the
  organisation page refreshes changes waiting and workloads by itself (a
  new app's descriptor shows once a device signed it); dismissing keeps the
  tab; group pages show a workload's approved key and a Copy descriptor
  button; organisation pages build what each person reads only on People.
- `access offboard --json` shows the plan before it asks.
- Security review fixes:
  - an organisation chain is anchored only by a link signed with the
    person's current user key, so a revoked device's old key cannot make
    their devices trust a chain it made up;
  - devices refuse removals the server signed in an organisation whose
    rules forbid server signing;
  - a group's machine activity (addresses, refused attempts, OIDC claims)
    and a project's addresses show to admins only, on live updates too;
  - a workload's rate limit counts only requests whose OIDC token checks
    out, so knowing its descriptor is not enough to lock it out;
  - organisation pages name no project to someone who may not set it up,
    and a group page names no project to someone who may not change it;
  - removing a workload reminds you to remove its IAM binding or OpenBao
    role, and moving workloads off a key says when to rotate the group key.

# v0.19.1

Fixes from a review of the organisations.

- A device signs in an organisation's chain only once it anchored it
  (created it, or `esec vault org trust`), and only links signed with the
  person's own user key anchor it on their other devices: a link the
  server or a passkey signed for them no longer does, so neither can make
  a device start acting on a chain it made up.
- `changes --yes` signs nothing in an organisation this device has not
  confirmed, and a removal it signs (marked `keep_admin_roles`) leaves the
  person's admin roles alone on every admin's device, not only its own.
- A former member who is still an admin somewhere no longer notifies every
  device that can see it, only the devices of that project's admins, once.
- Dismissing a change keeps the organisation page on its tab; OpenBao's
  `BAO_ADDR` is named wherever `BAO_TOKEN` is; the page of an organisation
  you are not in no longer says it has no rules.

# v0.19.0

Organisations with a signed chain, OpenBao, and rekeying workloads.

- **Organisations** (`esec vault org create acme`): the acme of acme/store
  gets its own chain, signed on its admins' devices like a group's, and
  pinned by every device that sees it. It records:
  - **its people** (`org add`, `org remove`). Once it has a chain, only its
    people create projects and groups named `acme/...` on the server.
    Removing someone takes them out of every project and group of acme: the
    remover's device at once, every other admin's device (and background
    service) at its next sync, for what each administers. Someone added
    again later is left alone.
  - **approved KMS keys** (`org kms add`, `org kms remove`). Devices wrap
    the group keys of acme's workloads only with them, so a server cannot
    slip in a key of its own; the approving device reads a key's public half
    from the KMS itself. A key can be limited to some groups (a per-app key).
  - **rules and defaults** (`org set`): only its people join its projects
    and groups, GitHub SSH proofs only, the longest token, no server-signed
    removals, access reviews, and the Fly.io organisation and KMS key new
    apps use. Devices check them when they sign; the server when it stores
    links, together with its admins' policy (the stricter applies).
  - A member's device says whether the creator of a project they are added
    to belongs to acme, and asks before taking in its keys if not.
  - What a chain lets a device do by itself (take people out, wrap keys
    with an approved key named in a web change) waits until the device
    anchored it: this account signed in it, or its person compared its
    fingerprint with an admin's (`esec vault org trust acme`). A server
    cannot make up an organisation to act through. Removals signed by a
    passkey or the server, or with `changes --yes`, leave admins' roles
    alone. Only an admin of the first project or group named after an
    organisation (or a server admin) can set it up.
- **`esec vault org fly-app acme store --read acme/store:prod`**: a Fly.io
  app reading its keys with no secret, in one step: its group (made when
  new), what it reads, and a workload bound to the app's OIDC tokens,
  wrapped with an approved key. It prints the descriptor for `fly.toml`.
- **Web pages for organisations** (`/orgs`, `/orgs/acme`): Overview (what
  needs doing), People (add, remove, who left and where they still are),
  Workloads (add a Fly.io app with one form, copy descriptors, move apps to
  another key, remove them, export JSON) and Settings (approve and withdraw
  KMS keys; rules and defaults). Each form proposes a change for a device
  (a dialog of the background service, or `esec vault changes`) or, where
  its scope allows, a passkey to sign; the server signs removals for people
  who let it, unless the organisation forbids that.
- **OpenBao** as a self-hosted KMS (`--openbao-key`, `--openbao-role`;
  `esec vault kms setup openbao` prints a Transit key, a decrypt-only policy
  and a JWT role per app).
- **Rekeying workloads** (`esec vault group rekey-workloads`, or Workloads ›
  Move): a workload moves to another KMS key or another KMS, keeping its id
  and descriptor.
- `esec vault group show` lists workloads with their descriptors.
- `esec vault kms setup gcp --apply` leaves what exists alone when run again
  for another app, and its provider trusts the Fly.io organisation, while
  each key's IAM binding names the apps that may decrypt with it.

Older versions cannot read organisation chains, and do not apply their
rules or removals; projects and groups work as before.

# v0.18.0

Workloads with no secret: Fly.io OIDC and a cloud KMS.

- **Workloads** (`esec vault group workload GROUP NAME --fly-org ORG
  --fly-app APP --gcp-key ... --gcp-provider ...`): a member of a group that
  holds no secret. Its group key is wrapped, on the admin's device, with the
  public half of a key in Google Cloud KMS. At each start the app proves
  where it runs with its Fly.io OIDC token (to the vault, which checks the
  workload's policy, and to Google, whose workload identity federation lets
  it decrypt with that one key), unwraps the group key in memory and opens
  its project keys. The vault server can open none of it; the KMS never sees
  a secret. The app's configuration holds only a descriptor
  (`ESEC_VAULT_WORKLOAD=esecw1_...`), no secret; `esec-vault machine run`,
  `machine env` and `machine whoami` use it.
- **`esec vault kms setup gcp`** prints, or with `--apply` runs, the gcloud
  commands for the one-time setup: one software RSA key, a workload identity
  pool trusting `https://oidc.fly.io/ORG` for the apps named, and their IAM
  bindings. About $0.06 a month for the key and $0.03 per 10,000 app starts.
- **KMS providers sit behind one interface** (`internal/kms`): wrapping is
  local (RSA-OAEP-SHA256), and a provider only unwraps, so AWS KMS, Azure
  Key Vault or OpenBao can follow. Google Cloud is the first, over plain
  REST (token exchange, optional service account impersonation, KMS
  asymmetric decrypt with checksums).
- New group keys reach workloads with no KMS call on the admin's side; a
  removed workload gets nothing from its next start. Group pages list
  workloads, with their KMS key and where they run.
- **Runbook** (`docs/runbook.md`): bootstrapping a project, people, Fly.io
  apps, CI, decrypting on your laptop and VMs, and rotating every kind of
  key.

Older versions cannot verify a group chain with a workload in it.

# v0.17.0

Fly.io workload identity.

- Machines and group tokens can be bound to Fly.io Machines:
  `--fly-org ORG [--fly-app APP,...]` on `machine create`, `group token`
  and `group add-machine`. The server then hands the sealed keys only to
  requests carrying an OIDC token from `https://oidc.fly.io/ORG` for one of
  those apps, verified against Fly.io's published keys. On a Fly.io Machine,
  `esec-vault machine run`, `machine env` and `machine join` ask the
  Machine's `/.fly/api` for the token by themselves. A leaked
  `ESEC_VAULT_MACHINE_KEY` is useless outside the app.
- The audit log names the Fly.io app, Machine and region that fetched keys.

# v0.16.0

Project settings and device management on the web.

- **Archive** a project (`esec vault access archive`, `--undo`), signed by a
  passkey or a device: an archived project sends no keys, its machines get
  none, and nothing in its chain changes but members leaving.
- **Delete** an archived project from the server (`esec vault access
  delete`, or the project's page): its chain, members and waiting keys go;
  its log stays, and keys stay in keyrings. Devices forget it once gone, so
  a project made again under the name is not taken for a rollback.
- **Rename** a project (`esec vault access move acme/shop`): a new chain
  with the same environment keys and people, who get the keys again; the
  old project is archived, naming the new one, and members' devices follow
  it without asking (unless they hold keys of the new name already). Groups
  you administer move too; machines and other admins' groups are listed.
- **Hand over admin** (`esec vault access handover alice --step-down`).
- **On the web**, the project's page has a Settings section: archive,
  unarchive, delete, rename and hand over admin (proposed for a passkey or a
  device to sign; renaming and admin changes only a device signs), and
  **Leave the project** for members (signed by the server or a passkey when
  you let them, otherwise by your device).
- **Devices on the web**: a device's page asks your devices to approve a new
  device, rename one, or revoke one. Your user key signs these, so a device
  does, in `esec vault changes`; to approve, you type the words the new
  device shows into the approving device, never into the web page. The
  background service's dialogs leave approvals to `esec vault changes`.

Older versions cannot verify a project chain with an archive link in it:
update esec-vault on every device of such a project.

Security fixes, from an audit of v0.13.0 to v0.15.0:

- `access requests --grant ID` showed nothing and asked nothing, so a
  malicious server could answer with another person and project than the
  admin saw. It now shows the request and asks; `--yes` needs `--login`,
  `--project` and `--env`, which the request must match.
- A group member made an admin stayed a member too, so `access offboard`
  (which removed the admin) left them in the group with the new group key.
  An admin is now an admin only, in the group chain itself.
- `changes --yes` judged a change a narrowing on one fetch of the chains and
  signed it from another, and for a group's access did not check that the
  group chain was the one the project names. It now signs unasked only
  through a narrow-only path that checks on the very state it signs from,
  refuses anything that gives access, and never removes an admin unasked.
- Timed access that could not end (a busy server, too many waiting changes)
  was marked failed and kept for good. It now stays open, is retried every
  round, and shows why on the project's page and in `access show`.
- The web review removed anyone not in the submitted form, such as someone
  added after the page was shown; it now removes only those ticked. A
  review of a project with machines could not be recorded.
- A member blocked on the web could still fetch a new group key; a block
  could outlive a proposal that failed.
- `access grant --for` ended environments the person already read before;
  it now ends only those the grant added.
- Text from the server is cleaned before the CLI prints it in more places;
  access requests are rate-limited; old requests, invites and timed access
  are cleaned up; invites whose redemption failed are retried.
- The Access, person and organisation pages count a group's admins among
  its readers (they hold its key); adding someone to a group checks the
  server's allowlist; a project's page shows a group's people only while
  the group takes its keys; a member fetching a group's keys is logged; the
  prompt for a project reached through a group says who added you.

# v0.15.0

Organisations, their policies, and access reviews.

- **Organisation pages** (`/orgs/acme`, linked from projects' and groups'
  pages) and **`esec vault org [ORG]`**: what you can see of an
  organisation's shared projects, groups and people, and its policy. With
  `--json`.
- **Policies**, set on the organisation's page by the server's admins and
  enforced by the server on every new change (a check on top of the signed
  chains, which can refuse but never grant):
  - the longest enrollment token, and no tokens that never expire;
  - people added only with a GitHub SSH proof, not account key words;
  - no removals signed by the server, even for people who let it;
  - an access review every so many days.
- **Access reviews.** `esec vault access review` asks about each member,
  group and machine of a project (admins stay), takes access away from those
  you say (`--remove bob,machine:old-ci`, `--keep-all`), and records the
  review. On the web: the project's page › **Review who reads it**. When a
  policy asks for reviews, the overview and the project's page remind its
  admins when one is due.
- Machines of a project can be removed from the web too (in a review); the
  device or passkey signs it like any removal.

# v0.14.0

More of it on the web, access requests, and access that ends by itself.

- **Access page** (`/access`): everyone who reads something of your shared
  projects, directly or through a group, with what needs doing first (keys
  to rotate, keys not sent, requests to answer, tokens about to expire). A
  page per person lists what they read, with **Offboard**: every removal
  you may sign is signed by the server (when you let it sign removals) or
  proposed for your passkey or device, and groups stop giving them keys at
  once.
- **Invites.** Adding someone on the web who has no vault account here yet
  stores an invite; once they create their account it becomes a change for
  the admin who invited them to sign. Projects' and groups' pages list
  invites, and cancel them.
- **Access requests.** `esec vault access request --env staging` (or the
  forms on a project's page and on the Access page) asks a project's
  admins; `esec vault access requests` lists what waits, with `--grant ID`,
  `--deny ID` and `--withdraw ID`, and `--json`. Admins answer on the
  project's page too. The server answers the same whether or not the
  project exists.
- **Timed access.** `esec vault access grant alice --env prod --for 8h`:
  when the time comes, the server signs the removal for the admin who set
  it, if they let it sign removals, and otherwise proposes it. `access show`
  and the project's page list it, and admins can keep the access instead.
- **`changes --yes`** now also signs changes the verified chain shows only
  take access away (a member or group left reading less), such as a timed
  access ending.
- **Groups' pages** warn of enrollment tokens that expire within two weeks
  (or did), and machines that fetched no keys for 30 days; the overview
  lists them too.
- **Activity** has a search, and exports (CSV and JSON); projects' and
  groups' histories export too, signed changes and what the server recorded.
  CSV cells that a spreadsheet would run as formulas are escaped.

# v0.13.0

Teams: groups of people, one command to grant and revoke, and offboarding.

- **Groups hold people.** A group (`acme/backend`) now holds people as well
  as machines. `esec vault group add acme/backend alice` checks alice's
  account like a new project member and seals the group's key to her; her
  devices then take in the keys of every project the group reads, verified
  like a machine of the group verifies them, after she accepts each project
  once. `group remove` takes a person out (the group gets a new key at
  once), and `group leave` lets a member go (an admin's device gives the
  group a new key on its next sync). Removed members show up in each
  project's rotation to-do. Group admins manage a group without reading
  through it.
- **`team` is now `access`.** `esec vault access ...` is the new name;
  `esec vault team ...` still works.
- **`access grant` and `access revoke`** take a GitHub login or a group:
  `access grant alice --env staging` adds staging to what alice reads (and
  adds her if she is new), `access grant acme/backend --env dev` does the
  same for a group, and `access revoke` takes environments, or everything,
  away, listing what to rotate. Both take `--json`.
- **`access offboard alice`** lists every project and group alice reads
  that you can see (`--dry-run` stops there), takes her out of each one you
  administer, and lists the environments to rotate. With `--json`.
- **The web pages** show each group's people. Admins add a person (signed
  with a passkey or on a device, which checks the person's GitHub proof
  before it seals the group key to them) and remove one: the server stops
  giving them keys at once, and the server or a passkey signs the removal.
  The signer page describes these changes. Pages say "group" instead of
  "machine group", and project pages list each group's people.
- `access show` lists each group's people and machines; `group list` and
  `group show` list people; the help puts `group` with `access`.
- The server stores group members, gives a member the group's keys
  (`GET /v1/groups/{org}/{name}/keys`), and alerts on members added and
  removed.

Older versions cannot verify a group chain with members in it: update
esec-vault on every device and machine of such a group.

# v0.12.1

- `status --json` now fills in `daemon.cli_version` and
  `daemon.up_to_date`, and lists a daemon older than the CLI under
  `problems`. Before, `up_to_date` was always `false` there, and the
  mismatch showed only in the text output.
- The README recipes install esec-vault v0.12.0 and esec v0.11.0.

# v0.12.0

The CLI is easier to find your way in, for people and for agents.

- **Help in sections.** `esec vault` (or `esec vault --help`) lists the
  commands in seven sections, from "Get started" to "Sharing through git",
  with a quick start, instead of 100 lines of subcommands. `esec vault help
  <command>` works like `<command> --help`, and about 35 commands now have
  examples and a few lines on what they do.
- **`--json`** on `team list`, `team show`, `group list`, `group show`,
  `machine list`, `machine whoami`, `devices list`, `env list`,
  `keyring list`, `delegate list` and `changes` (as on `status`). It shows
  names, public keys and fingerprints, never a private key.
- **`changes --list`** shows the changes waiting without signing them.
- **No hanging, no guessing.** A question with no terminal and no answer on
  stdin stops the command with a hint naming its `--yes` or `--force` flag.
  `changes` with no answer signs nothing, and says how many it left.
- **Hints.** Errors end with a `hint:` line where there is a next step, such
  as creating a `.esec-project`. `env list` without keys and `keyring list`
  without keyrings say how to make some; an unknown remote with none
  configured says how to add one.
- Usage errors print the usage on stderr, keeping stdout clean. The
  service's own entry point (`daemon run`) is hidden from the help.

# v0.11.0

Passkeys move to a signer page hosted apart from the vault server.

- **The signer page** (`signer/`, published by GitHub Pages at
  `https://sign.` and the server's host): passkeys are made and used only
  there. The vault server's own pages can neither make a passkey nor have one
  sign anything, so a compromised server cannot slip in a key of its own or
  get something signed that the person did not see.
- The signer shows a new passkey's fingerprint, worked out itself; devices
  add a passkey only if it is bound to the signer origin they work out from
  their own server URL. Before each signature, it decodes the exact change
  and shows it, with accounts looked up at GitHub, and refuses what it cannot
  describe.
- Server: `signer_url` (default `https://sign.<host>`); the signer's API is
  under `/signer/v1/`, for its origin only. The passkey endpoints of v0.10
  on the vault's own pages are gone; passkeys made there (none should exist)
  are not accepted by devices.

# v0.10.1

- **Quick recipes** in the README: sharing a project, GitHub Actions, Fly.io
  apps (with a Dockerfile), servers, autoscaling, removing people and
  machines, approving web changes. The runbook gains a table of everyday
  operations.

# v0.10.0

Sign changes made on the web: on your computer, with a passkey, or by the
server for removals.

- **Dialogs on your computer.** When a change made on the web pages waits,
  the background service shows it in a dialog with Sign, Later and Dismiss.
  The device writes the text from the change it signs, so the page cannot
  show one thing and have another signed; Later is the default button.
  `ESEC_VAULT_DIALOGS=off` turns them off.
- **Passkeys.** Register a YubiKey, Touch ID or phone passkey under
  Overview › Signing, add it from a device (`esec vault changes`, after
  checking its fingerprint), then sign changes on the pages with one touch.
  A passkey signs adding members, changing what members and already-granted
  machine groups read, and removals; never admins, never keys, never a new
  group for a project. Members it adds get keys only
  after an admin's device has checked their GitHub SSH proof.
- **Removals by the server.** `esec vault delegate server` (or the Signing
  page) lets the server sign changes that only take access away, so they take
  effect at once. It can never add anyone or grant anything.
- Under the hood: delegates in the user chain (`delegate_add`,
  `delegate_remove`), links signed by a delegate (`signer_delegate`), checked
  for scope by every device; WebAuthn assertions in envelopes. Everyone you
  share projects with needs v0.10 to read chains with these links.
- `esec vault delegate` lists, adds and removes them; `esec vault changes`
  signs every kind of web change, the account's too.

# v0.9.0

A web UI for running the team and the fleet.

- **Live pages.** The signed-in pages update in place and refresh on their
  own while open, with Datastar (vendored, v1.0.4) and its Go SDK. They
  still work without scripts. Datastar runs in its nonce mode: a fresh
  nonce per page, no `unsafe-eval`, scripts only from the site; expressions
  are built only from checked paths, and forms carry the same CSRF token
  and origin check as before.
- **Manage members on the web.** A project's admins add members, change what
  they read and remove them on its page. Group pages already let you choose
  what a group reads, remove machines and turn joining machines away.
- **Web changes, signed on your device.** Changes made on the pages wait in
  one list (**Changes** in the menu) until a device signs them:
  `esec vault changes` shows each and asks; a new member's GitHub SSH proof
  is checked first, as with `team add`. The background service tells you
  when changes wait. Only admins can make them.
- Group pages show machine names in their changes; a favicon.

# v0.8.0

Machine groups: run a fleet of machines that read the same environments.

- **Machine groups.** `esec vault group create acme/production` and
  `group grant acme/production --project acme/store --env prod` give a set
  of machines the environments of one or more shared projects. Each machine
  has its own key; the projects' keys are sealed once, to the group's key,
  so a new machine reads them at once, without an admin's device online.
  Both sides agree to each project: the project's admins grant it, the
  group's admins list it, and machines accept keys only from projects their
  group's signed chain lists.
- **Three ways in.** An enrollment token (`group token NAME --expires 90d`,
  optionally bound to GitHub Actions) works directly as a CI job's
  `ESEC_VAULT_MACHINE_KEY`, and enrolls machines on its own:
  `ESEC_VAULT_ENROLL_TOKEN=… esec-vault machine join`. Or a machine asks to
  join (`machine join GROUP --server URL`), shows six words, and an admin
  lets it in with `group approve` after checking them; `--fingerprint`
  pins the group. Or `group add-machine` makes a key to copy over.
- `esec-vault machine run` and `machine env` work with group keys and with a
  joined machine's key file (`/etc/esec-vault/machine.key` as root on Linux).
  Keys are set by public key, so files of any project the group reads
  decrypt; the current directory's project also gets them by name.
  `machine whoami` shows the machine, its group and what it reads.
- `group remove` stops a machine or token at once, gives the group a new key
  sealed to everyone left, re-seals the projects you administer, and lists
  the environments to rotate; `--destroyed` (deleted with its disk) needs no
  rotation. `group rotate`, `group admin LOGIN [--remove]`, `group show` and
  `group` round it off. Admins' background services re-send missing keys,
  rotate a group key someone who left still holds, and notify when machines
  wait to join.
- **Web.** A **Machines** page lists groups; each group's page shows its
  machines (last use and address), tokens, a project × environment table,
  history and log. Ticking environments, removing a machine or turning a
  join request away works there; removal blocks the machine on the server at
  once, and an admin's device signs the change (`group approve`). Project
  pages list the groups that read them; the overview and admin pages show
  groups and what waits.
- Alerts `group.machine_added`, `group.machine_removed` and
  `group.admin_added` go to the group's admins.
- Fix: a machine's per-machine rate limit (project machines too) is
  counted only after its request's signature checks, so someone who knows
  a machine's id can no longer use it up.

# v0.7.0

Shared projects and machine identities.

- **Shared projects.** `esec vault team create` shares a project with you as
  its admin; `team add LOGIN --env dev` adds a colleague on the same server
  and sends them the keys of the environments they may read, sealed to their
  own key. Who may read what is kept in a project chain signed by the
  admins and checked by every device: the server can neither add anyone nor
  swap a key. `team set`, `team remove` and `team leave` change access;
  `team show` and `team` list members, keys and what needs doing.
- New members prove their account with an SSH key on their GitHub account
  (`team prove`, checked against `github.com/LOGIN.keys`), or the admin types
  their account key words.
- A device asks before it first takes in a project's keys (`team sync`;
  the daemon notifies), then takes in new keys on its own. A key it holds is
  replaced only by a newer key of the same project, and kept under its
  public key so older files still decrypt.
- Admins' daemons send keys members and machines are missing, for example
  after a member's user key changed. `team sync` does it by hand.
- Removing someone, or their access to an environment, marks it to rotate:
  shown by `team remove`, `team show`, the project's web page and the admins'
  daemons, and alerted to every remaining member. In a shared project,
  `env rotate` and `env add` (admins only) send the new key to everyone who
  reads the environment.
- **Machines.** `esec vault machine create deploy --env prod` gives a CI job
  or app its own key (`ESEC_VAULT_MACHINE_KEY`); `esec-vault machine run --
  CMD` runs a command with its keys, `machine env --format github` exports
  them masked in GitHub Actions. With `--github-repo` (and `--github-ref`,
  `--github-environment`, `--github-repo-id`) the server hands the keys only
  to GitHub Actions jobs of that repository that prove it with an OIDC
  token. `machine list` and `machine remove` manage them; every use is
  logged.
- **Web.** `/teams/ORG/REPO` shows a shared project's members, what each
  reads and whether their devices have the keys, its machines with their
  last use, keys to rotate, its history and key deliveries. Projects lists
  your shared projects; the overview shows keys to rotate or still to send;
  the Admin page lists every shared project. Alerts cover members added and
  removed and machines added and removed.
- User chains now expose each user key version and the chain position that
  introduced it, so signatures by other parties are checked against the
  version current at the position they name.
- A device points out changes your account made to a shared project from
  another device: after revoking a device, that is how a misused old key
  would show.
- The database gains eight tables (`projects`, `project_links`,
  `project_members`, `project_machines`, `project_grants`,
  `project_holdings`, `project_audit`, `account_proofs`). All are additive:
  v0.6.0 still opens the database after a rollback.

# v0.6.0

Security alerts by email and webhook.

- The server alerts on a new device that signed in and waits for approval,
  an approved device (or a new account), a suspended or revoked device, and
  a web sign-in from a browser the account never used.
- **Email** goes through Lettermint's sending API: set `alerts.email_from`
  and `ESEC_SERVER_LETTERMINT_TOKEN`. Each person can enter an address under
  **Alerts** on the overview; it gets alerts only after they open the
  emailed link and press Confirm (mail scanners that open links confirm
  nothing). A changed or removed address is told. `alerts.email_to` sends
  every account's alerts to the operator as well.
- **Webhook**: `ESEC_SERVER_ALERT_WEBHOOK_URL` gets every alert as JSON with
  a Slack-ready `text`, signed with HMAC-SHA256 when
  `ESEC_SERVER_ALERT_WEBHOOK_SECRET` is set (`X-Esec-Vault-Signature`).
- Alerts are queued in the database with the event, so none are lost, and
  are retried for about 11 hours. Email retries reuse an idempotency key.
  Delivery errors never contain the webhook URL or the token.
- The Admin page shows whether each channel is on, the alerts sent, waiting
  and failed in the last 7 days, and the last error.
  `esec-vault-server -test-alert` sends a test alert to the operator's
  channels.
- The database gains an `alert_outbox` table and four `users` columns. Both
  are additive: v0.5.0 still opens the database after a rollback.

# v0.5.0

Web pages for people and for the operator. They still read only metadata:
nothing on them can decrypt anything.

- **Overview** (`/account`) opens with what needs attention, each with the
  command that fixes it: a device waiting for approval (first, since it may
  be a sign-in someone else started), a suspended device to revoke, a device
  unseen for 90 days, an unlock slot about to expire, an account only one
  device can open, an account not yet created. Tiles summarize devices, the
  vault, projects and the last activity. New sections list signed-in
  browsers, with sign-out for one or all other browsers, and the recent
  activity.
- **Device pages** (`/devices/{id}`) show a device's fingerprint, how it was
  added, where it signed in from, its live sessions with when each ends, and
  its activity. A device that was never approved, including one suspended
  while it waited, never shows its words on the web, and is not sent to be
  revoked: it never had access.
- **Activity** (`/activity`) lists the audit log in plain words, with device
  names, filters (sign-ins, devices, vault and keys, slots, or one device)
  and paging.
- **Vault** (`/vault`) lists the stored versions with size, hash and the
  device that pushed each.
- **Projects** has a search, including by public key, to find which project
  and environment an encrypted file belongs to.
- **Admin** (`/admin`), for the new `access.admin_github_ids`
  (`ESEC_SERVER_ADMIN_GITHUB_IDS`): the server's version and settings, totals,
  every allowed GitHub id with its state, and server-wide security events,
  plus a page per account. Read-only, and a 404 for everyone else. It never
  shows keys, fingerprint words or account creation tokens. The design
  document's threat table covers a taken-over admin GitHub account.
- A small first-party script adds copy buttons for commands and keys,
  confirmations before suspending or disabling, times in the viewer's time
  zone, table filters, and code formatting on the code page. The CSP allows
  only this script; every page works without it.
- Session counts now leave out sessions that went idle past
  `sessions.idle`.
- After GitHub sign-in, the browser returns to the page it asked for
  (activity, vault, a device page, admin) instead of always the overview.
- The database gains two columns for the browser list (`user_agent`, `ip` in
  `web_sessions`). They are added on start and have defaults, so v0.4.x
  servers can still open the database after a rollback.

# v0.4.4

- Build with esec v0.10.1, which adds `esec export` (the decrypted
  variables as `NAME=value` lines, without the public key) and keeps the
  public key out of `esec run`.
- Update dependencies (`golang.org/x/crypto` v0.58.0, `x/sys` v0.49.0,
  `x/term` v0.47.0). `modernc.org/libc` stays at v1.77.1, the version
  `modernc.org/sqlite` v1.60.1 requires.
- Update GitHub Actions (checkout v7, setup-go v7, cosign-installer v4,
  goreleaser-action v7.3.0, attest-build-provenance v4.2.2) and pin
  golangci-lint v2.15.0 in CI and `mise.toml`.

# v0.4.3

- Fix every web form failing with "The form expired" in real browsers. The
  pages used `Referrer-Policy: no-referrer`, under which browsers send
  `Origin: null` with same-origin form posts, and the CSRF origin check
  refused them. Pages now use `same-origin`, which still sends no referrer
  to other sites. The test browser now sends `Origin` the way browsers do.

# v0.4.2

Security fixes from an independent review.

- `login --recover` and `login --ssh-agent` now always require the phrase or
  SSH key, even when the server says the device is already trusted. Before,
  a malicious server could skip that check and reduce it to the account-key
  prompt. A machine that holds an identity also refuses an account made with
  a different recovery phrase on this path.
- Requests now declare their body hash in a signed header, and the server
  checks the signature before reading the body. A copied session token could
  otherwise make the server buffer many 16 MiB uploads. Bodies held in memory
  are also capped per account and in total. Devices waiting for approval use
  separate pools, capped per device, and may send only small requests. Clients before v0.4.2
  can still read, but must upgrade to write.
- `client_ip_header` now reads every line of the header, so a proxy that adds
  its own line cannot be bypassed by a client-sent one.
- A pending device learns only whether the account exists, not its chain
  length, from either `/v1/me` or commit errors. Commits with null links are rejected cleanly.

# v0.4.1

- While the server is closed to new devices (`new_devices = "closed"`), no
  new device is created for any account, including through a registration
  that reuses another account's trusted device key.

# v0.4.0

Vault server and device sync. Requires esec v0.9.0 or later.

- Add `esec-vault-server`:
  - GitHub sign-in for an allowlist of numeric GitHub user ids, and a device
    authorization grant for the CLI.
  - Ciphertext-only storage for vaults, device boxes, the master-wrapped
    identity and SSH-agent unlock slots.
  - Pages for code confirmation, devices, slots, the audit log and projects.
  - Every API request is signed with the device key, so a stolen session
    token alone is useless.
- Add `login`, `logout`, `devices` (list, approve, revoke, rename, suspend),
  `agent-unlock`, `sync --server` and `index`. A new machine gets your keys
  by approval from another device, by the recovery phrase, or from a
  forwarded SSH agent.
- Add a signed, hash-linked device chain that every client verifies and pins.
  A server cannot add devices, swap keys, or roll back history unnoticed.
- Vault uploads are signed by the user key, and sync merges three ways
  against the last synced version.
- Revoking a device rotates the user key. `env rotate` replaces an environment
  key and re-encrypts its files, keeping the old key for history.
- Seal keyring files under a per-machine cache key (`keyring seal`/`unseal`;
  default on signed-in machines). Device secrets live in a shared secret
  store: the OS keychain, a TPM, a 0600 file, or the Linux kernel keyring.
- `identity.esec` becomes version 3 with an Ed25519 signing key. The upgrade
  needs no recovery phrase. Older esec-vault versions cannot read version 3
  files.
- The daemon syncs with the server, refreshes an unlocked broker, and
  notifies about pending devices and devices added by phrase or SSH agent.
- Add `deploy/` (Dockerfile, Litestream, Fly.io) and a server runbook.
- The account root is signed by a key derived from the recovery phrase, so
  recovering with the phrase cannot be fooled into a forged account. Identities
  from older versions are asked for the phrase once, when the account is
  created.
- A device joining by approval confirms 8-word account key words before
  installing anything (or checks `--account-key`). Machines that already have
  an identity refuse an account created with another recovery phrase.
- Server-supplied text is sanitized before printing. Device boxes are
  write-once. Unlock slots disabled by a revocation are re-created only after
  an explicit yes.
- The recovery passphrase cannot change while signed in to a vault server.
- Creating an account needs a per-user token derived from the server's
  bootstrap secret (`ESEC_SERVER_BOOTSTRAP_TOKEN`; print one with
  `esec-vault-server -bootstrap-token-for <id>`; the CLI asks for it or reads
  `ESEC_VAULT_BOOTSTRAP_TOKEN`), so a taken-over GitHub account cannot create
  the vault account first.
- `devices approve` requires typing the new device's fingerprint words, which
  are shown only on the new device.
- Devices waiting for approval see nothing of the account until approved or
  until they prove the recovery phrase or an SSH key.
- Device codes are always typed; links never carry them.
- `new_devices = "closed"` (`ESEC_SERVER_NEW_DEVICES`) is an emergency switch
  that refuses brand-new devices and browsers during an attack.
- Trusted devices and browsers that signed in before bypass the server-wide
  sign-in caps, so a flood only delays new ones.

# v0.3.6

- Add `env show-key ENV` to print a named environment's private key after
  confirmation, resolving the nearest project marker or an explicit `--project`.
- Report a clear error when `project init` cannot infer a project because Git
  origin is missing or empty, with a hint to use `--project org/repo`.
- Print the initialized project's absolute directory and whether its ID came
  from the `--project` flag, positional argument, or Git origin.

# v0.3.5

- Never exit on failure without reporting why. `remote test`, `backup --push`,
  `daemon install/start/stop/restart` and `project init` all exited with a
  non-zero status and no output at all when an external tool failed, because the
  error path called `os.Exit` without printing the message. Tool diagnostics that
  embed "exit status" (rclone's 403 AccessDenied, launchctl's load errors) are
  now shown; only `run` stays silent, since the child already wrote its stderr.
- Preserve git's stderr in `project init` errors, so a missing `origin` remote
  explains itself instead of reporting only "exit status 128".
- Fail closed when the audit log cannot be written. A secret is no longer
  decrypted and served if the allow decision could not be recorded.
- Report a failed audit-log `Close` (for example ENOSPC on append) instead of
  returning success for an entry that never reached disk.
- Report plist XML escaping failures instead of writing a malformed unit that
  later surfaces as an opaque launchctl error.
- Reject keyring entries whose names cannot be exported as environment
  variables, rather than silently omitting the secret from the child process.
- Treat an unreadable push marker as pending instead of silently reporting that
  nothing needs uploading.
- Surface `members list` proof-read failures, `doctor` daemon-check failures and
  `daemon logs` errors rather than omitting them silently.

# v0.3.4

- Fix rclone-backed backups failing forever against object stores such as S3,
  R2 and B2. Reading a missing key with `rclone cat` succeeds and prints
  nothing there, because those stores have no directories. The rclone backend
  inferred "absent" from the exit code alone, so every first push reported
  `remote generation already exists with different content` and the daemon
  retried a conflicting generation that never existed. `Get` now probes the key
  with `lsjson` before reading, so a missing object is reported as absent.

# v0.3.3

- Fix the managed-copy comparison so `daemon upgrade` is idempotent and
  `daemon restart` stops rejecting a current daemon. The check rendered the
  unit file before capturing the environment, so it compared a PATH-less plist
  against the installed one and always reported the copy as stale.

# v0.3.2

- Resolve the module version for `go install` builds. The hardcoded `dev`
  placeholder made released binaries report an unknown build over the control
  socket, so the daemon staleness check could never fire.
- Remove the mise `install` task, which wrote dev builds into a `PATH` directory
  and shadowed real releases. Local builds are now injected as `dev` plus the
  commit hash instead of a stale hardcoded version.

# v0.3.1

- Add `daemon upgrade` to replace the managed executable after upgrading the
  CLI. The service runs a private copy, so a new binary on `PATH` never reached
  the running daemon.
- Report the daemon's build over the control socket. `daemon status` shows
  `version`, `cli_version` and `up_to_date`, and `status`/`doctor` warn when the
  managed copy is older than the CLI.
- Refuse `daemon restart` against a stale managed copy instead of silently
  restarting the old build, and point at `daemon upgrade`.
- Make `daemon install` idempotent: an identical managed copy and unit file are
  reused without stopping a healthy daemon, so a live broker session survives.
- Update go-keyring to v0.2.8, with wincred v1.2.3 and dbus v5.2.2.
- Depend on esec v0.8.1.
- Add detailed project, environment, subfolder, teammate-sharing, and broker
  guides in simplified technical English.
- Update CI to checkout v7, setup-go v7, and golangci-lint-action v9.
- Preserve Markdown spacing when extracting release notes.

# v0.3.0

- OS-managed user daemon with launchd/systemd installation, manifest-based
  uninstall and explicit local-data/keychain purge.
- Owner-only control socket, separate broker socket, locked startup and bounded
  unlock sessions independent of backup scheduling.
- Guided setup, backup jobs, CLI change notifications and crash-released locks.

- Self-contained format-2 snapshots with identity and recovery-key encryption;
  cold recovery needs only the backup, phrase and optional passphrase.
- Versioned memory-hard identity derivation, confirmed setup, passphrase changes,
  explicit legacy migration and preserved encrypted identity backups.
- Declarative remote config and setup wizard; file, rclone, restic and exec
  transports with round-trip verification, immutable generations and explicit retention.
- Live-key snapshots, deduplicated unchanged backups, durable pending uploads,
  periodic watch/retry worker and broker integration.
- Project/environment setup, status/doctor, safe restore preflight and default/
  monorepo keyring coverage.

# v0.2.0

Monorepo support (pairs with esec v0.7.0):

- Broker key resolution uses esec's shared chain — environment suffix (dotted envs like
  `registry.production`) then the secrets file's embedded public key — so per-component
  keypairs work through the broker without naming discipline
- `keyring migrate` walks monorepos: every repo-local `.esec-keyring` is migrated, keyed by
  its nearest `.esec-project` (nested subprojects included); `.gitignore` is updated at the
  git root
- New `keyring add` command: generates a component keypair, appends the pubkey-keyed entry
  (`ESEC_PRIVATE_KEY_<pubkey>`) to the project's global keyring, and prints the public key
  for embedding in the new secrets file
- Depends on esec v0.7.0

# v0.1.0

Initial release.

- Identity: BIP39 recovery phrase -> HKDF master key -> wrapped identity keypair
  (`identity init` / `recover` / `rotate` / `show`); identity lives in the OS keyring
- Global keyring store management: `keyring migrate` moves repo-local `.esec-keyring` files
  to `~/.config/esec/keyrings/<org>_<repo>.keyring` (verified copy before optional deletion),
  `keyring list` shows projects and environments
- Backup: `backup` / `restore` / `recover` seal and open the vault blob (NaCl sealed box +
  inner SHA-256 integrity)
- Broker: `agent` daemon holds keys in memory and answers policy-checked decryption requests
  over a unix socket with peer-uid authentication (Linux/macOS), TOML policy with
  allow/ask/deny, JSON-lines audit log, TTL, `agent stop`
- `run <env> -- cmd`: inject broker-decrypted secrets into a child process; also reachable as
  `esec vault run` via esec's subcommand passthrough
- Team sharing (git-native, no server): member proofs signed with GitHub-registered SSH keys
  (`members prove` / `verify` / `trust` / `list`), TOFU fingerprint pinning, `share` writes
  committed per-member sealed blobs under `.esec/vault/`, `sync` opens them
