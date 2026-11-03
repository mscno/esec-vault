import EsecVaultCore
import SwiftUI

struct ServiceSection: View {
    @Environment(Store.self) private var store
    @State private var ttl = "4h"
    @State private var confirmRestart = false

    var body: some View {
        Section {
            LabeledContent("Local helper", value: store.helper.state)
            if let error = store.helper.error {
                Text(error).font(.caption).foregroundStyle(.orange).textSelection(.enabled)
            }
            if store.helper.customSocket {
                Text("A custom broker socket is configured. Its lifetime is managed outside EsecVault.")
                    .foregroundStyle(.secondary)
            } else {
                HStack {
                    Button("Restart Helper…") { confirmRestart = true }
                    if store.daemonState?.reachable == true {
                        Button("Reload Policy") { Task { await store.serviceAction("reload") } }
                    }
                }
            }
            if let daemon = store.daemonState {
                if let version = daemon.version {
                    LabeledContent("Helper build", value: version).font(.caption)
                }
                if !daemon.upToDate, daemon.reachable {
                    Label("Update and reopen EsecVault so the app and helper use the same build.", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }
                if daemon.reachable {
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        let open = daemon.sessionIsOpen(at: context.date)
                        LabeledContent("Broker session") {
                            if open, let expires = daemon.expires {
                                Text("Unlocked until \(expires.formatted(date: .omitted, time: .shortened))")
                            } else { Text("Locked") }
                        }
                        HStack {
                            if open {
                                Button("Lock Now") { Task { await store.lock() } }
                            } else {
                                Picker("Session duration", selection: $ttl) {
                                    Text("15 minutes").tag("15m")
                                    Text("1 hour").tag("1h")
                                    Text("4 hours").tag("4h")
                                    Text("8 hours").tag("8h")
                                    Text("24 hours").tag("24h")
                                }
                                .fixedSize()
                                Button("Unlock Broker") { Task { await store.unlock(ttl: ttl) } }
                                    .disabled(!daemon.upToDate)
                            }
                        }
                    }
                }
            }
            Toggle("Open EsecVault at Login", isOn: Binding(get: { store.opensAtLogin }, set: { store.opensAtLogin = $0 }))
        } header: {
            Text("Local helper and broker session")
        } footer: {
            Text("EsecVault starts its bundled helper automatically. Closing a window keeps the menu bar, sync and helper running. Quitting the app stops the helper and ends its broker session; reopening starts locked. Decryption and key access happen on this Mac. The server stores encrypted backups. Locking the broker clears session keys while encrypted sync continues. Local keyring access remains available to esec commands independently of the app.")
        }
        .disabled(store.busy != nil)
        .confirmationDialog("Restart local helper?", isPresented: $confirmRestart) {
            Button("Restart Helper") { Task { await store.serviceAction("restart") } }
        } message: {
            Text("This ends the broker session and clears its cached keys. The bundled helper restarts locked.")
        }
    }
}
