import EsecVaultCore
import SwiftUI

struct ProjectDetail: View {
    @Environment(Store.self) private var store
    let id: String
    @State private var addingEnv = false
    @State private var rotating: EnvView?
    @State private var renaming: EnvView?
    @State private var sharing = false
    @State private var addingCI = false

    private var project: Project? { store.details[id] ?? store.projects.first { $0.project == id } }

    var body: some View {
        Group {
            if let project {
                let checkout = project.checkouts.first { $0.status == "ok" }?.path
                Form {
                    Section {
                        LabeledContent("Project", value: project.project)
                        LabeledContent("Local keyring", value: project.keysHere ? "Present" : "None — keys may open from repository seals")
                        if let config = project.config {
                            LabeledContent("Configuration") {
                                HStack {
                                    Text((config.path as NSString).abbreviatingWithTildeInPath)
                                        .textSelection(.enabled)
                                    Button("Open esec.toml") { store.editConfig(config.path) }
                                }
                            }
                            LabeledContent("File format", value: config.format.flatMap { $0.isEmpty ? nil : $0 } ?? "Shared esec default")
                            LabeledContent("Filename pattern", value: config.name.flatMap { $0.isEmpty ? nil : $0 } ?? "Shared esec default")
                            if let unknown = config.unknown, !unknown.isEmpty {
                                Label("Unrecognized esec.toml settings: " + unknown.joined(separator: ", "), systemImage: "exclamationmark.triangle")
                                    .foregroundStyle(.orange)
                            }
                            if project.checkouts.filter({ $0.status == "ok" }).count > 1 {
                                Text("Environments and actions use the configuration shown above. Files below include all valid checkouts.")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                    Section("Checkouts") {
                        if project.checkouts.isEmpty {
                            Text("No checkout on this Mac.").foregroundStyle(.secondary)
                        }
                        ForEach(project.checkouts, id: \.path) { c in
                            CheckoutRow(checkout: c)
                        }
                    }
                    Section {
                        ForEach(project.envs) { env in
                            EnvRow(project: project.project, env: env, checkout: checkout,
                                   seal: store.seals.first { $0.project == project.project && $0.env == env.name && (checkout == nil || $0.root == checkout) },
                                   rotate: { rotating = env }, rename: { renaming = env })
                        }
                    } header: {
                        EnvHeader(checkout: checkout, share: { sharing = true }, addCI: { addingCI = true }, addEnv: { addingEnv = true })
                    } footer: {
                        Text("esec.toml records environment keys, readers and guard policy; .esec/ holds the seals that enforce access. A touch guard requires approval for every read. A session guard keeps an approved key open until the broker locks or expires. Passkeys use the macOS system sheet; legacy PIV keys use their PIN and touch flow. Commit config and seal changes together.")
                            .foregroundStyle(.secondary)
                    }
                    if let files = project.files, !files.isEmpty {
                        Section {
                            ForEach(files) { f in FileRow(file: f) }
                        } header: {
                            HStack {
                                Text("Secrets files")
                                Spacer()
                                Button("Compare Environments", systemImage: "tablecells") { store.openSecretComparison(project) }
                            }
                        }
                    }
                    let recent = store.activity.filter { $0.project == project.project }.prefix(8)
                    if !recent.isEmpty {
                        Section("Recent key requests") {
                            ForEach(Array(recent)) { ActivityRow(entry: $0, showProject: false) }
                        }
                    }
                }
                .formStyle(.grouped)
                .navigationTitle(project.project)
                .sheet(isPresented: $addingEnv) {
                    AddEnvSheet(project: project, checkout: checkout ?? "")
                }
                .sheet(item: $renaming) { env in
                    RenameEnvSheet(project: project, env: env, checkout: checkout ?? "")
                }
                .sheet(isPresented: $sharing) {
                    ShareSheet(project: project, checkout: checkout ?? "")
                }
                .sheet(isPresented: $addingCI) {
                    CIKeySheet(project: project, checkout: checkout ?? "")
                }
                .confirmationDialog("Rotate \(rotating?.name ?? "")?", isPresented: Binding(get: { rotating != nil }, set: { if !$0 { rotating = nil } }), presenting: rotating) { env in
                    Button("Rotate \(env.name)") {
                        if let checkout { Task { await store.rotate(project.project, env, in: checkout) } }
                    }
                } message: { env in
                    Text("\(env.name) gets a new key, sealed for the same readers before its files are re-encrypted to it. The old key stays sealed in git history. Deploys need the new files\(env.isGuarded ? "; opening the old key may require passkey or security-key approval" : "").")
                }
            } else {
                ContentUnavailableView("Not on this Mac", systemImage: "questionmark.folder")
            }
        }
        .task(id: id) { await store.loadDetail(id) }
    }
}

struct EnvHeader: View {
    @Environment(Store.self) private var store
    let checkout: String?
    let share: () -> Void
    let addCI: () -> Void
    let addEnv: () -> Void

    var body: some View {
        HStack {
            Text("Environments")
            Spacer()
            Button("Share…", action: share)
                .help("Share environments with GitHub users: their keys are sealed in, in the repository")
            Button("Add CI Key…", action: addCI)
                .help("A key for a CI job or deploy, which then needs only esec")
            Button("Add Environment…", action: addEnv)
                .help(checkout == nil ? "Needs a checkout on this Mac" : "A new key, sealed for the project's readers")
        }
        .disabled(checkout == nil || store.busy != nil)
    }
}

struct CheckoutRow: View {
    @Environment(Store.self) private var store
    let checkout: Checkout

    var body: some View {
        HStack {
            Image(systemName: checkout.status == "ok" ? "folder" : "folder.badge.questionmark")
            VStack(alignment: .leading) {
                Text((checkout.path as NSString).abbreviatingWithTildeInPath)
                if checkout.status != "ok" {
                    Text(checkout.status == "gone" ? "Directory or esec.toml is missing" : checkout.status == "invalid" ? (checkout.error ?? "esec.toml could not be read") : "Its esec.toml names another project now")
                        .font(.caption).foregroundStyle(.orange)
                }
            }
            Spacer()
            if checkout.status != "gone" {
                if checkout.status == "invalid" {
                    Button("Open esec.toml") { store.editConfig(checkout.path + "/esec.toml") }
                }
                Button("Finder") { store.revealInFinder(checkout.path) }
                Button("Terminal") { store.openTerminal(checkout.path) }
            } else {
                Button("Forget") { Task { await store.forget(checkout.path) } }
            }
        }
        .buttonStyle(.borderless)
    }
}

struct EnvRow: View {
    @Environment(Store.self) private var store
    let project: String
    let env: EnvView
    let checkout: String?
    let seal: SealView?
    let rotate: () -> Void
    let rename: () -> Void
    @State private var stoppingGuard = false
    @State private var unsharing: ReaderRef?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Image(systemName: env.isGuarded ? "lock.fill" : "key")
                    .foregroundStyle(env.isGuarded ? .blue : .secondary)
                    .frame(width: 18)
                VStack(alignment: .leading, spacing: 2) {
                    HStack {
                        Text(env.name).bold()
                        Text(guardText).foregroundStyle(.secondary)
                    }
                    if let action = env.action {
                        Text(action).font(.caption.monospaced()).foregroundStyle(.orange).textSelection(.enabled)
                    }
                }
                Spacer()
                if env.mismatch == true {
                    Label("esec.toml names another key", systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange).labelStyle(.titleAndIcon).font(.caption)
                }
                Text(hereText).font(.caption).foregroundStyle(env.here == "missing" ? .orange : .secondary)
                if let key = env.key {
                    Text(String(key.prefix(12)) + "…").font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                }
            }
            FlowLayout(spacing: 6) {
                ForEach(env.readerRefs) { r in
                    ReaderChip(reader: r, pending: pendingReason(r))
                        .contextMenu {
                            if case .me = r.kind {} else if checkout != nil {
                                Button("Unshare \(r.display)") { Task { await store.unshare(project, env: env.name, who: r.unshareName, rotate: false, in: checkout) } }
                                Button("Unshare and Rotate…") { unsharing = r }
                            }
                        }
                }
            }
            .padding(.leading, 26)
            SealState(seal: seal).padding(.leading, 26)
        }
        .contextMenu {
            if let key = env.key { Button("Copy Public Key") { store.copy(key) } }
            Button("Copy Run Command") { store.copy("esec vault run \(env.name) -- ") }
            if env.here != "missing", checkout != nil {
                Divider()
                if env.isGuarded { Button("Stop Guarding…") { stoppingGuard = true } }
                if store.guardStatus?.setUp == true {
                    if env.guardLevel != "touch" {
                        Button("Guard: Approve Every Read") { Task { await store.guardEnv(project, env.name, level: "touch", in: checkout) } }
                    }
                    if env.guardLevel != "session" {
                        Button("Guard: Approve Once per Broker Session") { Task { await store.guardEnv(project, env.name, level: "session", in: checkout) } }
                    }
                }
            }
            if checkout != nil {
                Button("Rename Environment…", action: rename)
            }
            if env.here != "missing", checkout != nil {
                Divider()
                Button("Rotate Key…", action: rotate)
            }
        }
        .disabled(store.busy != nil)
        .alert("Stop guarding \(env.name)?", isPresented: $stoppingGuard) {
            Button("Stop Guarding", role: .destructive) { Task { await store.unguardEnv(project, env.name, in: checkout) } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The key will be sealed to readers’ user keys and cached locally. Future reads will no longer require passkey or security-key approval. Commit esec.toml and .esec/ together.")
        }
        .confirmationDialog("Unshare \(env.name) with \(unsharing?.display ?? "") and rotate it?", isPresented: Binding(get: { unsharing != nil }, set: { if !$0 { unsharing = nil } }), presenting: unsharing) { r in
            Button("Unshare and Rotate", role: .destructive) {
                Task { await store.unshare(project, env: env.name, who: r.unshareName, rotate: true, in: checkout) }
            }
        } message: { r in
            Text("\(r.display) may have kept the key: a new key is made and the files re-encrypted. Change values they may have read at their providers too.")
        }
    }

    /// Why a reader is not sealed in yet, if they are not.
    private func pendingReason(_ r: ReaderRef) -> String? {
        if let s = seal?.readers.first(where: { $0.reader == r.raw }), let p = s.pending { return p }
        return env.pending?.contains(r.raw) == true ? "not sealed in yet" : nil
    }

    private var guardText: String { env.guardDescription }

    private var hereText: String {
        switch env.here {
        case "guarded": "opens with approval"
        case "clear": "key here"
        case "sealed": "opens on first use"
        default: "not shared with you"
        }
    }
}

/// A reader: a person (GitHub avatar, by id), a group, or a key.
struct ReaderChip: View {
    let reader: ReaderRef
    let pending: String?

    var body: some View {
        HStack(spacing: 4) {
            switch reader.kind {
            case .person:
                AsyncImage(url: reader.avatarURL) { image in
                    image.resizable()
                } placeholder: {
                    Image(systemName: "person.crop.circle.fill").resizable().foregroundStyle(.secondary)
                }
                .frame(width: 16, height: 16)
                .clipShape(Circle())
            case .me:
                Image(systemName: "person.crop.circle").foregroundStyle(.secondary)
            case .group:
                Image(systemName: "person.3").foregroundStyle(.secondary)
            default:
                Image(systemName: "key.horizontal").foregroundStyle(.secondary)
            }
            Text(reader.display).font(.caption)
            if pending != nil {
                Image(systemName: "clock").font(.caption2).foregroundStyle(.orange)
            }
        }
        .padding(.horizontal, 7)
        .padding(.vertical, 3)
        .background(.quaternary, in: Capsule())
        .help(pending.map { "\(reader.raw): \($0)" } ?? reader.raw)
    }
}

/// An environment's seal: current, to be made again, or broken.
struct SealState: View {
    @Environment(Store.self) private var store
    let seal: SealView?

    var body: some View {
        if let seal {
            if !seal.sealed {
                Label("Not sealed in the repository: it could be lost", systemImage: "exclamationmark.octagon.fill")
                    .font(.caption).foregroundStyle(.red)
            }
            ForEach(seal.failures, id: \.detail) { p in
                Label(p.detail, systemImage: "xmark.octagon.fill").font(.caption).foregroundStyle(.red)
                    .help(p.fix ?? "")
            }
            ForEach(seal.uncheckedReasons, id: \.self) { Text($0).font(.caption).foregroundStyle(.orange) }
            ForEach(seal.warnings, id: \.detail) { Text($0.detail).font(.caption).foregroundStyle(.orange) }
            ForEach(seal.pendingReaders, id: \.reader) { Text("\($0.display): \($0.pending ?? "pending")").font(.caption).foregroundStyle(.orange) }
            if !seal.resealReasons.isEmpty {
                HStack {
                    Label("Seal again: " + seal.resealReasons.joined(separator: "; "), systemImage: "arrow.triangle.2.circlepath")
                        .font(.caption).foregroundStyle(.orange)
                    Button("Seal Again") { Task { await store.sealAgain() } }
                        .buttonStyle(.borderless).font(.caption)
                        .disabled(store.busy != nil)
                }
            }
        }
    }
}

/// Lays out views in rows, wrapping.
struct FlowLayout: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache _: inout ()) -> CGSize {
        let rows = arrange(proposal.width ?? .infinity, subviews)
        let width = rows.map(\.width).max() ?? 0
        let height = rows.reduce(0) { $0 + $1.height } + spacing * CGFloat(max(rows.count - 1, 0))
        return CGSize(width: width, height: height)
    }

    func placeSubviews(in bounds: CGRect, proposal _: ProposedViewSize, subviews: Subviews, cache _: inout ()) {
        var y = bounds.minY
        for row in arrange(bounds.width, subviews) {
            var x = bounds.minX
            for i in row.items {
                let size = subviews[i].sizeThatFits(.unspecified)
                subviews[i].place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(size))
                x += size.width + spacing
            }
            y += row.height + spacing
        }
    }

    private struct Row { var items: [Int] = []; var width: CGFloat = 0; var height: CGFloat = 0 }

    private func arrange(_ maxWidth: CGFloat, _ subviews: Subviews) -> [Row] {
        var rows = [Row()]
        for (i, v) in subviews.enumerated() {
            let size = v.sizeThatFits(.unspecified)
            if !rows[rows.count - 1].items.isEmpty, rows[rows.count - 1].width + spacing + size.width > maxWidth {
                rows.append(Row())
            }
            var r = rows[rows.count - 1]
            r.width += (r.items.isEmpty ? 0 : spacing) + size.width
            r.height = max(r.height, size.height)
            r.items.append(i)
            rows[rows.count - 1] = r
        }
        return rows.filter { !$0.items.isEmpty }
    }
}

struct FileRow: View {
    @Environment(Store.self) private var store
    let file: SecretsFile

    var body: some View {
        Button { store.openSecretFile(file.path) } label: {
          HStack {
            Image(systemName: "lock.doc")
            VStack(alignment: .leading) {
                Text((file.path as NSString).abbreviatingWithTildeInPath).lineLimit(1).truncationMode(.middle)
                    .help(file.path)
                if let plain = file.plain, !plain.isEmpty {
                    Text("In the clear: " + plain.joined(separator: ", ")).font(.caption).foregroundStyle(.red)
                }
            }
            Spacer()
            Text(file.env.isEmpty ? "default" : file.env).foregroundStyle(.secondary)
            Text("\(file.keys?.count ?? 0) values").font(.caption).foregroundStyle(.secondary)
            Image(systemName: "arrow.up.forward.app").foregroundStyle(.tint)
          }
          .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help("Decrypt and show values in a new window")
        .contextMenu {
            Button("Open Secrets") { store.openSecretFile(file.path) }
            Button("Reveal in Finder") { store.revealInFinder(file.path) }
        }
    }
}

struct AddEnvSheet: View {
    @Environment(Store.self) private var store
    @Environment(\.dismiss) private var dismiss
    let project: Project
    let checkout: String
    @State private var name = ""
    @State private var level = "none"

    private var valid: Bool {
        EnvironmentName.isValid(name) && !project.envs.contains { $0.name == name }
    }

    var body: some View {
        Form {
            Section {
                TextField("Name", text: $name, prompt: Text("staging or api.prod"))
                Picker("Guard", selection: $level) {
                    Text("None").tag("none")
                    Text("Approve every read").tag("touch")
                    Text("Approve once per broker session").tag("session")
                }
                .disabled(store.guardStatus?.setUp != true)
            } header: {
                Text("New environment for \(project.project)")
            } footer: {
                Text(store.guardStatus?.setUp == true
                     ? "Use dot-separated lowercase letters and digits. Guarded keys require your approval; session guards remain available until the broker locks. It is shared with the project's readers."
                     : "Use dot-separated lowercase letters and digits. Add a passkey or security key first to enable guarding (Security Keys).")
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(width: 420)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            ToolbarItem(placement: .confirmationAction) {
                Button("Add") {
                    Task {
                        if await store.addEnv(project.project, in: checkout, name: name, guardLevel: level) { dismiss() }
                    }
                }
                .disabled(!valid || store.busy != nil)
            }
        }
    }
}

struct RenameEnvSheet: View {
    @Environment(Store.self) private var store
    @Environment(\.dismiss) private var dismiss
    let project: Project
    let env: EnvView
    let checkout: String
    @State private var name = ""

    var body: some View {
        Form {
            TextField("New name", text: $name, prompt: Text("api.prod"))
            Text("Renames \(env.name) in this checkout, its seals and matching files while preserving its key, readers and guard policy. Commit the changes together. Use dot-separated lowercase letters and digits.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .formStyle(.grouped)
        .frame(width: 460)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            ToolbarItem(placement: .confirmationAction) {
                Button("Rename") {
                    Task { if await store.renameEnv(project.project, env: env.name, to: name, in: checkout) { dismiss() } }
                }
                .disabled(store.busy != nil || !EnvironmentName.isValid(name) || name.utf8.count > 64 || project.envs.contains { $0.name == name })
            }
        }
    }
}
