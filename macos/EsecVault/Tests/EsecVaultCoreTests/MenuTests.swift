@testable import EsecVaultUI
import AppKit
import EsecVaultCore
import SwiftUI
import Testing

/// Exercise the native menu host: model-only tests cannot catch recursive
/// SwiftUI menu invalidation when the broker changes between locked and open.
@Test @MainActor func brokerMenuRendersAfterUnlockAndExpiry() async throws {
    if #available(macOS 14.4, *) {
        _ = NSApplication.shared
        let store = Store()
        store.cli = nil
        let menu = NSHostingMenu(rootView: MenuContent().environment(store))
        for (unlocked, expiry, expected) in [
            (false, "2099-01-01T00:00:00Z", "Unlock Broker for 4 Hours"),
            (true, "2099-01-01T00:00:00Z", "Lock Broker"),
            (true, "2000-01-01T00:00:00Z", "Unlock Broker for 4 Hours"),
            (false, "2099-01-01T00:00:00Z", "Unlock Broker for 4 Hours"),
        ] {
            let raw = """
            {"installed":true,"reachable":true,"managed":true,"unlocked":\(unlocked),"expires":"\(expiry)","up_to_date":true}
            """
            store.daemonState = try JSON.decoder.decode(DaemonStatus.self, from: Data(raw.utf8))
            // SwiftUI renders native menu items on the next run-loop turn.
            for _ in 0..<100 {
                try await Task.sleep(for: .milliseconds(10))
                menu.update()
                if menu.items.contains(where: { $0.title == expected }) { break }
            }
            #expect(menu.items.filter { $0.title.contains("Broker") }.map(\.title) == [expected])
        }
    }
}
