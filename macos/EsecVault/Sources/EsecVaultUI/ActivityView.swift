import EsecVaultCore
import SwiftUI

/// Which programs and agents asked for keys: the background service's
/// audit log.
struct ActivityView: View {
    @Environment(Store.self) private var store
    @State private var onlyDenied = false

    var body: some View {
        let entries = store.activity.filter { !onlyDenied || $0.decision == "deny" }
        Group {
            if entries.isEmpty {
                ContentUnavailableView("No key requests", systemImage: "list.bullet.rectangle",
                                       description: Text("Requests made through esec vault run in the last week show here."))
            } else {
                List(entries) { ActivityRow(entry: $0, showProject: true) }
            }
        }
        .navigationTitle("Activity")
        .toolbar {
            ToolbarItem {
                Toggle("Refused Only", isOn: $onlyDenied).toggleStyle(.checkbox)
            }
        }
    }
}

struct ActivityRow: View {
    let entry: ActivityEntry
    let showProject: Bool

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Image(systemName: symbol).foregroundStyle(color).frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    if showProject, let p = entry.project { Text(p).bold() }
                    if let e = entry.env { Text(e).bold(showProject == false) }
                    Text(decisionText).foregroundStyle(color)
                }
                HStack(spacing: 6) {
                    if let caller = entry.caller { Text(caller) }
                    if let s = entry.session { Text("· " + s) }
                    if let d = entry.detail, !d.isEmpty { Text("· " + d) }
                }
                .font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            Text(entry.ts.formatted(.relative(presentation: .named)))
                .font(.caption).foregroundStyle(.secondary)
                .help(entry.ts.formatted(date: .abbreviated, time: .standard))
        }
    }

    private var symbol: String {
        switch entry.decision {
        case "allow": "checkmark.circle"
        case "deny": "hand.raised.fill"
        default: "questionmark.circle"
        }
    }

    private var color: Color {
        switch entry.decision {
        case "allow": .green
        case "deny": .red
        default: .orange
        }
    }

    private var decisionText: String {
        switch entry.decision {
        case "allow": "allowed"
        case "deny": "refused"
        case "ask": "asked you"
        default: entry.decision
        }
    }
}
