import AppKit
import EsecVaultCore
import SwiftUI

@main
struct EsecVaultApp: App {
    @State private var store = Store()
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    var body: some Scene {
        Window("esec Vault", id: "main") {
            MainView()
                .environment(store)
                .frame(minWidth: 860, minHeight: 520)
                .task { store.start() }
        }
        .commands {
            CommandGroup(after: .newItem) {
                Button("Find Checkouts…") { NotificationCenter.default.post(name: .scanFolder, object: nil) }
                    .keyboardShortcut("o", modifiers: [.command, .shift])
                Button("Refresh") { Task { await store.refresh() } }
                    .keyboardShortcut("r")
            }
        }

        MenuBarExtra {
            MenuContent().environment(store)
        } label: {
            Image(systemName: store.health.symbol)
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_: Notification) {
        // Run without a Dock icon when started from a plain binary; the
        // bundled app sets LSUIElement for the same effect.
        if Bundle.main.bundleIdentifier == nil {
            NSApp.setActivationPolicy(.accessory)
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_: NSApplication) -> Bool { false }
}

extension Notification.Name {
    static let scanFolder = Notification.Name("EsecVaultScanFolder")
}

extension Health {
    var symbol: String {
        switch self {
        case .good: "lock.shield"
        case .attention: "exclamationmark.shield"
        case .lost: "xmark.shield"
        case .unknown: "shield"
        }
    }

    var color: Color {
        switch self {
        case .good: .green
        case .attention: .orange
        case .lost: .red
        case .unknown: .secondary
        }
    }

    var text: String {
        switch self {
        case .good: "Every key is in two places"
        case let .attention(s), let .lost(s), let .unknown(s): s
        }
    }
}

struct MenuContent: View {
    @Environment(Store.self) private var store
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Text(store.health.text)
        Text("\(store.projects.count) projects · \(store.guardedCount) guarded environments")
        if let at = store.verify?.at, at.timeIntervalSince1970 > 1 {
            Text("Checked \(at.formatted(.relative(presentation: .named)))")
        }
        Divider()
        Button("Open esec Vault") {
            openWindow(id: "main")
            NSApp.activate()
        }
        Button("Check Keys Now") { Task { await store.verifyNow() } }
            .disabled(store.busy != nil)
        Button("Refresh") { Task { await store.refresh() } }
        Divider()
        Button("Quit") { NSApp.terminate(nil) }
    }
}
