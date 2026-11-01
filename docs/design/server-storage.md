# Server storage and recovery

The signed, account-encrypted format-3 manifest is the durable inventory.
Ordinary keyrings are local working caches. Registered project configuration,
encrypted secret files and signed `.esec/` seals are archived as independent
XChaCha20-Poly1305 objects. Their random keys, hashes and relative paths live
inside the encrypted manifest; the server sees opaque object IDs and sizes.
Uploads are scoped to the authenticated account. Objects are immutable and
uploaded before a compare-and-swap manifest commit.

Each checkout has complete revision records, with monotonically increasing
sequence numbers. A restore selects one record, rather than combining the most
recent version of each file. Different devices and checkout locations retain
separate histories. This is encrypted secret-file recovery, not a Git backup.

Before network I/O, changed data is captured in a device-encrypted pending
manifest and encrypted object queue. A failed upload leaves the queue intact.
Acknowledgement installs a device-encrypted merge base and removes queued
objects. Cache eviction first syncs, then omits that project's keys from the
managed working keyring and merge base. Existing snapshots and exports are
independent copies; eviction does not erase them. Cache policies are local.

Key retirement retains public-key-indexed historical entries. Explicit deletion
records permanent tombstones in the current manifest. Alias changes and guard
changes use logical versions, with removal/protection winning equal-version
conflicts. Existing devices with copied keys cannot be made to forget them;
secret rotation is required when that matters. Historical server manifests and
independent exports can still contain deleted or formerly unguarded keys.

Guarded archive records are checked for internal signature and hash consistency.
These repository-controlled records never authorize key deletion or a guard-state
change. An existing clear key with an unknown guard state blocks migration until
an explicit guard-enable action succeeds. Guard changes must open the key and
reseal it for the configured readers before recording the inventory change.
Archiving ciphertext is not proof that a particular reader can open it; use the
existing seal verification and recovery drill for that. The outer vault’s
recovery encryption does not remove the seals’ inner guard.

Device profiles preserve policy and trust configuration, not device credentials,
approval grants, passkeys or live broker sessions. Restore is explicit and
requires reviewing local numeric user IDs. Files are allowlisted, and project
restore confines paths with `os.Root`, validates all ciphertext before writing,
uses a new destination, and creates files exclusively with mode 0600.

## Rollout

1. Back up the existing server database using the server's backup mechanism.
2. Deploy the server that supports format 3 and the encrypted object endpoints.
   The additive `vault_objects` table is in the same SQLite database as the
   manifest, so a consistent database backup includes both.
3. Upgrade clients and run sync. The first successful commit migrates the
   manifest. The server rejects later format downgrades, including old-client
   identity rotations; old clients must upgrade before working with this vault.
4. Confirm the GUI's acknowledged revision and archived projects. Make an
   explicit recovery export and rehearse restoring into a new directory.
5. Only after a successful restore drill, retire old backup jobs separately.
   The client no longer invokes rclone or makes automatic snapshot history.
   It does not delete old remote data, credentials or legacy files.

Server persistence is not proof of operational disaster recovery. The operator
must verify replication, retention and restore of the full SQLite database,
including `vault_objects`. No deployment or remote backup status is inferred
from a successful client sync. The runbook's Litestream/database procedures
remain applicable. A recovery phrase cannot reconstruct missing encrypted data.

## Explicit limits

Archive discovery is strict: recognized secret-file candidates with invalid
public keys, malformed content, plaintext values, unsupported file types or
excessive size fail staging. The last acknowledged revision remains intact.
Nested projects are archived through their own registered checkouts.

Archive files: 4 MiB each. Objects: 50,000 / 1 GiB per account, including orphans.
Project captures: 50,000. Device settings: 1 MiB per file. Portable single-file
exports: 256 MiB of object ciphertext. Manifest requests also obey the existing
server body cap. Limit failures keep local data and are reported to the user.
No automatic archive pruning occurs: historical manifests may reference objects.

The server backup remains necessary beyond the portable-export limit. A future
streaming multi-file export could remove that single-file memory bound without
loading the entire history into RAM.
