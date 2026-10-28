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
                let problems = report.keys.filter { !($0.problems ?? []).isEmpty }
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
            Section("Recovery") {
                LabeledContent("Last drill") {
                    if let d = store.verify?.drill, d.timeIntervalSince1970 > 1 {
                        Text(d.formatted(date: .abbreviated, time: .omitted))
                    } else {
                        Text("Never — run esec vault drill in Terminal").foregroundStyle(.orange)
                    }
                }
            }
            Section("Hardware guard") {
                if let g = store.guardStatus, g.setUp {
                    ForEach(g.holders, id: \.self) { h in
                        Label(holderName(h), systemImage: h.hasPrefix("age1yubikey") ? "key.horizontal.fill" : "doc.plaintext")
                            .help(h)
                    }
                    if g.holders.count < 2 {
                        Text("One holder: losing it loses the guarded keys. Add a spare YubiKey.").foregroundStyle(.orange)
                    }
                    ForEach(g.projects.filter { !($0.clear ?? []).isEmpty }, id: \.project) { p in
                        Text("\(p.project): guarded keys still in the clear on this Mac").foregroundStyle(.orange)
                    }
                } else {
                    Text("Not set up. In Terminal: esec vault guard init").foregroundStyle(.secondary)
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Key Health")
    }

    private func holderName(_ h: String) -> String {
        if h.hasPrefix("age1yubikey") { return "YubiKey " + h.dropFirst(12).prefix(8) + "…" }
        if h.hasPrefix("age1se") { return "Secure Enclave " + h.dropFirst(7).prefix(8) + "…" }
        return "Recovery key " + h.dropFirst(4).prefix(8) + "…"
    }
}
