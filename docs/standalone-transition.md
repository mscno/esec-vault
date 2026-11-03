# Transition to standalone Esec

The replacement workflow is being implemented in the sibling `esec` repository.
It uses local age identities, public recipient lists and encrypted environment
key generations committed alongside the encrypted files. It needs no EsecVault
account, broker, server, daemon or macOS application for migrated environments.
The standalone changes are not a published release yet.

Machine setup offers a software identity for dev/test/staging and accepts pasted
age/rage YubiKey recipients. Production includes hardware recipients and only
explicitly selected unattended deployment identities. The normal developer
recipient is excluded. A second hardware key or offline recovery identity avoids
relying on one YubiKey. Each recipient can decrypt independently; a deployment
identity must stay off ordinary developer machines.

Use the Esec checkout's `README.md` for the current commands and storage layout.
The migration sequence is:

1. Build and install the standalone CLI; run `esec setup`. Machine configuration
   lives in `age.toml` beside the legacy `config.toml`, allowing coexistence.
2. Migrate one non-production environment with `esec adopt dev`. This rotates its
   environment key; old keys and seals are preserved. Check `esec inspect dev` and
   run the application's tests. Keep local database overrides explicit.
3. Test recovery using a different identity or the hardware key, without the
   original machine's developer identity. Check important historical revisions,
   not only the current file. Git history must include the encrypted key seals.
4. Provision distinct deployment identities in the deployment secret store and
   grant only their public recipients to the appropriate environments. Upgrade
   applications and other Esec readers to understand the new standalone seals.
   Deployment secret changes remain the owner's responsibility.
5. After all active projects, deployments and required history work independently,
   stop the menu bar app/helper and Linux services. Preserve legacy encrypted
   backups and recovery material until their retention requirements are settled.
6. Only then retire server access, scheduled sync/backup jobs and distribution of
   the old app. Do not mistake stopping a service for revoking old copied secrets;
   actual application credentials require separate rotation after exposure.

Do not delete account identities, raw keyrings, device recovery material, server
backups or old seal generations as part of installing the new CLI. Shared-key
files and aliases currently require a coordinated migration, rather than
independent `adopt` calls. Legacy Esec commands remain supported for files that
have not migrated.

There is no automatic backup or rclone dependency in the standalone design.
Back up encrypted Git history and maintain separate protected recovery material.
Hardware PIN/touch verification is local, through `age-plugin-yubikey`; no
production decryption moves to the server.
