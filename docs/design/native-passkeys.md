# Native passkey unlocking on macOS

The Mac app uses AuthenticationServices for passkey enrollment and guarded
reads. Apple Passwords and enabled credential providers (including Strongbox)
participate through the system sheet. A YubiKey uses FIDO2 in this path.
The app never collects its FIDO2 PIN and does not request keyboard OTPs.

Passkey encryption requires the WebAuthn PRF extension. A provider that can
sign in but cannot supply PRF is rejected before a vault reader is registered.
Enrollment creates a credential and then performs one assertion to confirm
that it can unlock; this may show two system sheets. User verification is
required for both platform and security-key assertions. Platform PRF needs
macOS 15; native security-key PRF needs macOS 26.4.

Each enrolled passkey protects a fresh age X25519 identity. HKDF-SHA256
derives a wrapping key from its 32-byte PRF output with a random 32-byte salt
and context `esec/passkey/age-identity/v1`. XChaCha20-Poly1305 encrypts the
identity. Version, relying party, credential ID, salt and X25519 public
recipient are authenticated associated data. Public `age1passkey1…`
recipients contain those fields plus the encrypted identity. Encryption
uses only the public X25519 key; decryption requires a fresh native passkey
ceremony. No plaintext identity or PRF output is persisted.

The age plugin groups this person's matching credentials in one native
chooser. A cancellation is terminal for that operation: it does not reopen
the sheet for every other credential. Authentication occurs in a short-lived
instance of the signed app; requests and secret responses use private pipes,
never command arguments, files, notifications or logs. The helper accepts
only the relying party configured in its signed Info.plist. The Go caller
has a three-minute timeout and bounds the response size.

This is encryption under a passkey, not a software check placed in front of
an unprotected local private key. Software passkeys depend on the selected
password manager's protections. They do not inherit the non-exportability
of a PIV private key stored on a YubiKey.

## Build and activate

Use a paid Apple Developer team that owns `com.mscno.esec-vault` and a domain
you control. The native Xcode wrapper enables Associated Domains and
automatically provisions the app. Xcode's account must be signed in.

```sh
cd macos/EsecVault
ESEC_APPLE_TEAM_ID=YOUR_TEAM_ID ESEC_PASSKEY_RP=sign.vault.example.com ./bundle.sh install
```

The app bundles a matching CLI and `age-plugin-passkey`. CLI/daemon users
must also put this plugin on their PATH, for example by linking
`~/Applications/EsecVault.app/Contents/MacOS/age-plugin-passkey` into
`~/go/bin`. Upgrade the managed daemon from the bundled CLI after installing
the app. A daemon upgrade ends the broker's unlocked session.

Publish `signer/.well-known/apple-app-site-association` on the isolated signer
origin before installing the signed app. Its `webcredentials.apps` must list
the Apple TeamID.BundleID (this deployment uses
`93627F7C77.com.mscno.esec-vault`). The signer is hosted on GitHub Pages,
separately from the vault server; `signer/.nojekyll` preserves static dot paths.
Apple must retrieve this HTTPS file without redirects.

Use the isolated signer domain as the relying party, such as
`sign.vault.parap.ly`. Never use the vault server's own web origin for
decryption passkeys: a compromised vault page must not be able to request
their PRF secret. The signed native helper accepts only its compiled domain.
The CLI defaults to `sign.` plus the vault host; a custom isolated signer
requires `--rp-id`. Native enrollment is separate from the existing passkey
delegates for signing administrative changes.

Upgrade the server and other clients to recognize the passkey security-key
kind before publishing a new passkey reader in an account's signed chain.

## Enroll and migrate

Choose Security Keys → Add Passkey in the app, or:

```sh
esec-vault security-keys passkey --name "Apple Passwords"
esec-vault security-keys passkey --provider security-key --name "YubiKey FIDO2"
```

Enrollment adds a reader for future seals. It does not rewrite old seals or
remove an existing reader. To include it in existing guarded environments,
explicitly reseal with an old reader (`seal sync --all --guarded`) or use
the recovery phrase (`seal recover --all`). Verify the new passkey opens
each relevant seal before considering removal of a previous reader.

Legacy PIV/sealed keys continue to use their existing unlock mechanism until
resealed. New guarded reads prefer the person's registered passkeys, using
the native system sheet for approval without a preceding custom PIN/Allow
dialog. Caller and read attribution remain visible as a notification.
