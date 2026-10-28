import EsecVaultCore
import SwiftUI

struct HealthView: View {
    @Environment(Store.self) private var store

    var body: some View {
        Form {
            Section {
                HStack(spacing: 12) {
                    Image(systemName: store.health.symbol)
                        .font(.system(size: 34))
                        .foregroundStyle(store.health.color)
                    VStack(alignment: .leading) {
                        Text(store.health.text).font(.title3)
                        if let at = store.verify?.at, at.timeIntervalSince1970 > 1 {
                            Text("Checked \(at.formatted(.relative(presentation: .named))); the background service checks daily.")
                                .foregroundStyle(.secondary)
                        }
                    }
                    Spacer()
                    Button("Check Now") { Task { await store.verifyNow() } }
                        .disabled(store.busy != nil)
                }
            }
            let setup = store.setup
            if !setup.isEmpty {
                Section {
                    ForEach(setup) { SetupRow(item: $0) }
                } header: {
                    Text("Set up")
                } footer: {
                    if let problems = store.status?.problems, !problems.isEmpty {
                        VStack(alignment: .leading) {
                            ForEach(problems, id: \.self) { Text("! " + $0) }
                        }
                        .font(.caption).foregroundStyle(.orange)
                    }
                }
            }
            SealsSection()
            if let report = store.verify?.report {
                Section("Where keys are kept") {
                    LabeledContent("Keys", value: "\(report.keys.count), in \(report.files) files across \(report.checkouts) checkouts and their git history")
                    ForEach(report.sources, id: \.name) { s in
                        Label {
                            Text(s.name)
                            if let e = s.error, !s.checked { Text(e).font(.caption).foregroundStyle(.secondary) }
                        } icon: {
                            Image(systemName: s.checked ? "checkmark.circle.fill" : "minus.circle")
                                .foregroundStyle(s.checked ? .green : .secondary)
                        }
                    }
                }
                let problems = report.keys.filter { !($0.problems ?? []).isEmpty && $0.unheld != true }
                if !problems.isEmpty {
                    Section("Needs attention") {
                        ForEach(problems) { k in
                            VStack(alignment: .leading, spacing: 4) {
                                HStack {
                                    Text(k.uses.first.map { "\($0.project) \($0.env)" } ?? k.publicKey).bold()
                                    Text(String(k.publicKey.prefix(12)) + "…").font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                                }
                                ForEach(k.problems ?? [], id: \.self) { p in
                                    Text(p).font(.callout).foregroundStyle(p.hasPrefix("lost") ? .red : .orange)
                                }
                            }
                        }
                    }
                }
            }
            if let g = store.guardStatus, g.projects.contains(where: { !($0.clear ?? []).isEmpty }) {
                Section("Guarded keys still cached on this Mac") {
                    ForEach(g.projects.filter { !($0.clear ?? []).isEmpty }, id: \.project) { p in
                        HStack {
                            Text("\(p.project): \((p.clear ?? []).joined(separator: ", "))").foregroundStyle(.orange)
                            Spacer()
                            Button("Guard It Here") {
                                let checkout = store.projects.first { $0.project == p.project }?.checkouts.first { $0.status == "ok" }?.path
                                Task { await store.perform("Guarding — touch your security key…", ["guard", "enable", "--project", p.project], in: checkout, then: p.project) }
                            }
                            .disabled(store.busy != nil)
                        }
                    }
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Overview")
    }
}

struct SetupRow: View {
    @Environment(Store.self) private var store
    let item: SetupItem

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Image(systemName: symbol).foregroundStyle(color).frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                Text(item.title)
                Text(item.detail).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if item.state == .todo || item.state == .warning, let command = item.command {
                Button(item.args == nil ? "Set Up in Terminal" : item.interactive ? "Open in Terminal" : "Do It") {
                    Task { await store.doSetup(item) }
                }
                .disabled(store.busy != nil)
                .help(command)
            }
        }
    }

    private var symbol: String {
        switch item.state {
        case .done: "checkmark.circle.fill"
        case .warning: "exclamationmark.circle.fill"
        case .todo: "circle"
        case .skipped: "minus.circle"
        }
    }

    private var color: Color {
        switch item.state {
        case .done: .green
        case .warning: .orange
        case .todo, .skipped: .secondary
        }
    }
}

/// Seals across the checkouts here that should be made again, or are
/// broken.
struct SealsSection: View {
    @Environment(Store.self) private var store

    var body: some View {
        let todo = store.sealsToFix
        Section {
            if store.seals.isEmpty {
                Text("No sealed keys found in the checkouts here.").foregroundStyle(.secondary)
            } else if todo.isEmpty {
                Label("Every key of \(Set(store.seals.map(\.project)).count) project(s) is sealed in its repository, signed, with your recovery key.", systemImage: "checkmark.seal.fill")
                    .foregroundStyle(.green)
            }
            ForEach(todo) { s in
                VStack(alignment: .leading, spacing: 2) {
                    HStack {
                        Image(systemName: s.isGuarded ? "lock.fill" : "key").foregroundStyle(.secondary).frame(width: 18)
                        Text("\(s.project) \(s.env)").bold()
                    }
                    if !s.sealed {
                        Text("Not sealed in its repository: it could be lost").font(.caption).foregroundStyle(.red)
                    }
                    ForEach(s.failures, id: \.detail) { p in
                        Text(p.detail + (p.fix.map { " — " + $0 } ?? "")).font(.caption).foregroundStyle(.red)
                    }
                    if !s.resealReasons.isEmpty {
                        Text("Seal again: " + s.resealReasons.joined(separator: "; ")).font(.caption).foregroundStyle(.orange)
                    }
                }
            }
            if !todo.isEmpty {
                HStack {
                    Button("Seal Again") { Task { await store.sealAgain() } }
                        .disabled(store.busy != nil)
                    Button("Use Recovery Phrase…") { store.recoverSeals() }
                        .help("Your phrase opens every guarded seal once: no touch per environment")
                    Spacer()
                }
            }
        } header: {
            Text("Seals")
        } footer: {
            if todo.contains(where: \.isGuarded) {
                Text("Guarded environments need a touch each to be sealed again, or your recovery phrase once.").foregroundStyle(.secondary)
            }
        }
    }
}
