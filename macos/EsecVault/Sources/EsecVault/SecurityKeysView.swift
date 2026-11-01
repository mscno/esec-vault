import EsecVaultCore
import SwiftUI

/// Your security keys: the YubiKeys guarded environments are sealed to.
/// Plug one in and add it; nobody types a recipient.
struct SecurityKeysView: View {
    @Environment(Store.self) private var store
    @State private var removing: SecurityKey?
    @State private var resealAfterRemove = false

    var body: some View {
        let list = store.securityKeys
        Form {
            Section {
                if let keys = list?.keys, !keys.isEmpty {
                    ForEach(keys) { SecurityKeyRow(key: $0) { removing = $0 } }
                } else {
                    Text("No passkey or security key yet. Add a passkey, or scan connected YubiKeys for legacy PIV keys.").foregroundStyle(.secondary)
                }
            } header: {
                Text("Your security keys")
            } footer: {
                Text(footer(list)).foregroundStyle(.secondary)
            }
            if let detected = list?.unregistered, !detected.isEmpty {
                Section("Plugged in, not added yet") {
                    ForEach(detected) { DetectedKeyRow(key: $0) }
                }
            }
            if let blank = list?.unprovisioned, !blank.isEmpty {
                Section("YubiKeys without a legacy PIV key") {
                    ForEach(blank, id: \.self) { serial in
                        HStack {
                            Image(systemName: "key.horizontal").foregroundStyle(.secondary)
                            Text("YubiKey \(serial)")
                            Spacer()
                            Button("Add as Passkey…") { Task { await store.addPasskey(provider: "security-key") } }
                                .disabled(store.busy != nil || !store.securityKeyPasskeysAvailable)
                        }
                    }
                }
            }
            if let why = list?.detect {
                Section {
                    Label(why, systemImage: "info.circle").foregroundStyle(.secondary)
                }
            }
            Section {
                Menu("Add Passkey…") {
                    Button("Apple Passwords or Password Manager…") { Task { await store.addPasskey(provider: "platform") } }
                    Button("YubiKey / FIDO2 Security Key…") { Task { await store.addPasskey(provider: "security-key") } }
                        .disabled(!store.securityKeyPasskeysAvailable)
                }
                .disabled(store.busy != nil || !store.nativePasskeysAvailable)
                Text("macOS handles passkey selection and approval through Apple Passwords or your enabled password manager. The provider must support passkey encryption (WebAuthn PRF). Existing guarded environments need resealing to include a new passkey.")
                    .font(.caption).foregroundStyle(.secondary)
                if !store.nativePasskeysAvailable {
                    Text("Native passkeys require macOS 15 or later and the signed EsecVault app.").font(.caption).foregroundStyle(.orange)
                } else if !store.securityKeyPasskeysAvailable {
                    Text("Native FIDO2 security-key encryption requires macOS 26.4 or later.").font(.caption).foregroundStyle(.secondary)
                }
                HStack {
                    Button("Scan Connected YubiKeys") { Task { await store.scanSecurityKeys() } }
                        .disabled(store.busy != nil)
                    if let checked = list?.checked {
                        Text("Last scan \(checked.formatted(.relative(presentation: .named)))").font(.caption).foregroundStyle(.secondary)
                    }
                }
                Text("Ordinary refreshes use the background service’s scan cache. Touch a YubiKey only when macOS requests it or its light is blinking for an active operation.")
                    .font(.caption).foregroundStyle(.secondary)
                HStack {
                    Button("Set Up Legacy PIV Key in Terminal…") { store.setUpYubiKey() }
                    Spacer()
                    if !(list?.unregistered.isEmpty ?? true) {
                        Button("Add All Plugged-In Keys") { Task { await store.addSecurityKey(name: nil) } }
                            .disabled(store.busy != nil)
                    }
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Security Keys")
        .confirmationDialog("Remove \(removing?.name ?? "")?", isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } }), presenting: removing) { key in
            Button("Remove \(key.name)", role: .destructive) {
                Task {
                    resealAfterRemove = await store.removeSecurityKey(key.id)
                }
            }
        } message: { _ in
            Text("New seals stop including it. Seals made before, in git history too, still open with it: seal your guarded environments again, and if it was lost with its PIN, rotate them.")
        }
        .alert("Seal guarded environments again?", isPresented: $resealAfterRemove) {
            Button("Seal Again") { Task { await store.sealAgain() } }
            Button("Use Recovery Phrase…") { store.recoverSeals() }
            Button("Later", role: .cancel) {}
        } message: {
            Text("Each guarded environment is sealed again without the removed key, using another passkey or security key, or your recovery phrase. Existing copies in git history remain readable with the old key.")
        }
    }

    private func footer(_ list: SecurityKeyList?) -> String {
        let keys = list?.keys.count ?? 0
        let source = list?.source == "account" ? "Kept in your account: your other Macs and people who share with you see them." : "Kept on this Mac until you sign in to a vault server."
        switch keys {
        case 0: return "Guarded environments require approval through a registered passkey or security key. " + source
        case 1: return "One key: add a spare, or losing it means recovering with your phrase. " + source
        default: return source
        }
    }
}

struct SecurityKeyRow: View {
    @Environment(Store.self) private var store
    let key: SecurityKey
    let remove: (SecurityKey) -> Void

    var body: some View {
        HStack {
            Image(systemName: key.kind == "se" ? "touchid" : "key.horizontal.fill")
                .foregroundStyle(key.pluggedIn ? .green : .secondary)
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                Text(key.name)
                HStack(spacing: 6) {
                    Text(key.kind == "passkey" ? "Passkey" : key.kind == "se" ? "Secure Enclave" : "YubiKey (PIV)")
                    if let serial = key.serial { Text("· \(serial)") }
                    Text(key.kind == "passkey" ? "· unlocks through macOS" : key.pluggedIn ? "· plugged in" : "· not plugged in")
                    if let tested = key.tested {
                        Text("· tested \(tested.formatted(.relative(presentation: .named)))")
                    }
                }
                .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Button("Test") { Task { await store.testSecurityKey(key.id) } }
                .disabled(!key.pluggedIn || store.busy != nil)
                .help("Encrypts a random value to this key and opens it through its passkey or security-key approval flow")
            Button("Remove…", role: .destructive) { remove(key) }
                .disabled(store.busy != nil)
        }
        .buttonStyle(.borderless)
        .contextMenu {
            Button("Copy Recipient") { store.copy(key.recipient) }
        }
    }
}

struct DetectedKeyRow: View {
    @Environment(Store.self) private var store
    let key: DetectedKey
    @State private var name = ""

    var body: some View {
        HStack {
            Image(systemName: "key.horizontal").foregroundStyle(.blue).frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                Text("YubiKey \(key.serial), slot \(key.slot)")
                if !key.touchAlways {
                    Text("Touch policy \(key.touchPolicy ?? "?"): a touch then lets other programs in for a while. Prefer a slot with touch always.")
                        .font(.caption).foregroundStyle(.orange)
                }
            }
            Spacer()
            TextField("Name", text: $name, prompt: Text("blue, on my keychain"))
                .frame(width: 180)
            Button("Add") { Task { await store.addSecurityKey(name: name, detected: key) } }
                .disabled(store.busy != nil || key.touchPolicy?.lowercased() == "never")
        }
    }
}
