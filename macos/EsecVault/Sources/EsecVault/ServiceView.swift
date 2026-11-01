import EsecVaultCore
import SwiftUI

struct ServiceSection: View {
    @Environment(Store.self) private var store
    @State private var ttl = "4h"
    @State private var pendingAction: String?

    var body: some View {
        Section {
            if let daemon = store.daemonState {
                LabeledContent("Background service", value: daemon.serviceDescription)
                if let version = daemon.version {
                    LabeledContent("Service build", value: version).font(.caption)
                }
                if !daemon.upToDate, daemon.installed || daemon.reachable {
                    Label("The service and this app use different builds. Update the service to use this app’s CLI.", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }
                HStack {
                    if daemon.managed {
                        if !daemon.installed {
                            Button("Install and Start") { Task { await store.serviceAction("install") } }
                        } else if !daemon.upToDate {
                            Button("Update Service…") { pendingAction = "upgrade" }
                        } else if !daemon.reachable {
                            Button("Start Service") { Task { await store.serviceAction("start") } }
                        }
                        if daemon.reachable, daemon.installed {
                            Button("Restart…") { pendingAction = "restart" }
                            Button("Stop…") { pendingAction = "stop" }
                            Button("Reload Policy") { Task { await store.serviceAction("reload") } }
                        }
                    } else {
                        Text("A custom broker socket is configured. Manage that broker from Terminal.")
                            .foregroundStyle(.secondary)
                    }
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
            } else {
                Text("Background service status is unavailable.").foregroundStyle(.orange)
                Button("Check Service") { Task { await store.refreshRuntime() } }
            }
            Toggle("Open EsecVault at Login", isOn: Binding(get: { store.opensAtLogin }, set: { store.opensAtLogin = $0 }))
        } header: {
            Text("Service and broker session")
        } footer: {
            Text("The service backs up and syncs keys even while the broker is locked or EsecVault is closed. Unlocking the broker needs no YubiKey touch. Guarded keys ask for approval when first read: every read for touch guards, once per broker session for session guards. Locking clears those session keys. Opening EsecVault at login controls this menu bar app separately.")
        }
        .disabled(store.busy != nil)
        .confirmationDialog("\(actionTitle) background service?", isPresented: Binding(get: { pendingAction != nil }, set: { if !$0 { pendingAction = nil } })) {
            if let action = pendingAction {
                Button(actionTitle) { Task { await store.serviceAction(action) } }
            }
        } message: {
            Text("This ends the broker session and clears its cached keys. Restarting or updating starts the service locked. Stopping also pauses backups and sync until the service starts again; its login startup remains installed.")
        }
    }

    private var actionTitle: String {
        switch pendingAction {
        case "upgrade": "Update"
        case "stop": "Stop"
        default: "Restart"
        }
    }
}
