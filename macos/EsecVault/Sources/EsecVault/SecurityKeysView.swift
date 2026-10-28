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
                    Text("No security key yet. Plug in your YubiKey: it shows up below.").foregroundStyle(.secondary)
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
                Section("Plugged in, with no age key yet") {
                    ForEach(blank, id: \.self) { serial in
                        HStack {
                            Image(systemName: "key.horizontal").foregroundStyle(.secondary)
                            Text("YubiKey \(serial)")
                            Spacer()
                            Button("Set Up…") { store.setUpYubiKey() }
                                .help("Makes an age key on it (PIN, touch for every read) in Terminal, then adds it")
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
                HStack {
                    Button("Set Up a New YubiKey…") { store.setUpYubiKey() }
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
                    await store.removeSecurityKey(key.id)
                    resealAfterRemove = true
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
            Text("Each guarded environment is sealed again without the removed key: a touch of another key each, or your recovery phrase once.")
        }
    }

    private func footer(_ list: SecurityKeyList?) -> String {
        let keys = list?.keys.count ?? 0
        let source = list?.source == "account" ? "Kept in your account: your other Macs and people who share with you see them." : "Kept on this Mac until you sign in to a vault server."
        switch keys {
        case 0: return "Guarded environments open only with a touch of one of these. " + source
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
                    Text(key.kind == "se" ? "Secure Enclave" : "YubiKey")
                    if let serial = key.serial { Text("· \(serial)") }
                    Text(key.pluggedIn ? "· plugged in" : "· not plugged in")
                    if let tested = key.tested {
                        Text("· tested \(tested.formatted(.relative(presentation: .named)))")
                    }
                }
                .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Button("Test") { Task { await store.testSecurityKey(key.id) } }
                .disabled(!key.pluggedIn || store.busy != nil)
                .help("Seals a random value to it and opens it: one touch")
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
            Button("Add") { Task { await store.addSecurityKey(name: name) } }
                .disabled(store.busy != nil)
        }
    }
}
