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
