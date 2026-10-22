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
