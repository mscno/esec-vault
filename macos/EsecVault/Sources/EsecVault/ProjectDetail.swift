import EsecVaultCore
import SwiftUI

struct ProjectDetail: View {
    @Environment(Store.self) private var store
    let id: String
    @State private var addingEnv = false
    @State private var rotating: EnvView?

    private var project: Project? { store.details[id] ?? store.projects.first { $0.project == id } }

    var body: some View {
        Group {
            if let project {
                let checkout = project.checkouts.first { $0.status == "ok" }?.path
                Form {
                    Section {
                        LabeledContent("Project", value: project.project)
                        LabeledContent("Keys on this Mac", value: project.keysHere ? "Yes" : "No")
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
                            EnvRow(project: project.project, env: env, checkout: checkout) { rotating = env }
                        }
                    } header: {
                        HStack {
                            Text("Environments")
                            Spacer()
                            Button("Add Environment…") { addingEnv = true }
                                .disabled(checkout == nil || store.busy != nil)
                                .help(checkout == nil ? "Needs a checkout on this Mac" : "A new key, stored before anything uses it")
                        }
                    } footer: {
                        Text("A guarded key opens only after you allow it in esec's dialog and touch your security key. Agents cannot touch it. Right-click an environment for more.")
                            .foregroundStyle(.secondary)
                    }
                    if let files = project.files, !files.isEmpty {
                        Section("Secrets files") {
                            ForEach(files) { f in FileRow(file: f) }
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
                .confirmationDialog("Rotate \(rotating?.name ?? "")?", isPresented: Binding(get: { rotating != nil }, set: { if !$0 { rotating = nil } }), presenting: rotating) { env in
                    Button("Rotate \(env.name)") {
                        if let checkout { Task { await store.rotate(project.project, env, in: checkout) } }
                    }
                } message: { env in
                    Text("\(env.name) gets a new key, stored on the vault server or a backup before its files are re-encrypted to it. The old key is kept. Deploys and teammates need the new key\(env.isGuarded ? "; you touch your security key to open the old one" : "").")
                }
            } else {
                ContentUnavailableView("Not on this Mac", systemImage: "questionmark.folder")
            }
        }
        .task(id: id) { await store.loadDetail(id) }
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
                    Text(checkout.status == "gone" ? "No longer there" : "Its esec.toml names another project now")
                        .font(.caption).foregroundStyle(.orange)
                }
            }
            Spacer()
            if checkout.status == "ok" {
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
    let rotate: () -> Void

    var body: some View {
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
        .contextMenu {
            if let key = env.key { Button("Copy Public Key") { store.copy(key) } }
            Button("Copy Run Command") { store.copy("esec vault run \(env.name) -- ") }
            if env.here == "clear", store.guardStatus?.setUp == true {
                Divider()
                Button("Guard: Touch for Every Read") { Task { await store.guardEnv(project, env.name, level: "touch", in: checkout) } }
                Button("Guard: Touch Once per Session") { Task { await store.guardEnv(project, env.name, level: "session", in: checkout) } }
            }
            if env.here != "missing", checkout != nil {
                Divider()
                Button("Rotate Key…", action: rotate)
            }
        }
    }

    private var guardText: String {
        switch env.guardLevel {
        case "touch": "touch for every read"
        case "session": "touch once per session"
        default: "not guarded"
        }
    }

    private var hereText: String {
        switch env.here {
        case "guarded": "guarded here"
        case "clear": "key here"
        default: "no key here"
        }
    }
}

struct FileRow: View {
    let file: SecretsFile

    var body: some View {
        HStack {
            Image(systemName: "doc.text")
            VStack(alignment: .leading) {
                Text((file.path as NSString).lastPathComponent)
                if let plain = file.plain, !plain.isEmpty {
                    Text("In the clear: " + plain.joined(separator: ", ")).font(.caption).foregroundStyle(.red)
                }
            }
            Spacer()
            Text(file.env.isEmpty ? "default" : file.env).foregroundStyle(.secondary)
            Text("\(file.keys?.count ?? 0) values").font(.caption).foregroundStyle(.secondary)
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
        !name.isEmpty && name.allSatisfy { $0.isLowercase || $0.isNumber || $0 == "-" || $0 == "_" }
            && !project.envs.contains { $0.name == name }
    }

    var body: some View {
        Form {
            Section {
                TextField("Name", text: $name, prompt: Text("staging"))
                Picker("Guard", selection: $level) {
                    Text("None").tag("none")
                    Text("Touch for every read").tag("touch")
                    Text("Touch once per session").tag("session")
                }
                .disabled(store.guardStatus?.setUp != true)
            } header: {
                Text("New environment for \(project.project)")
            } footer: {
                Text(store.guardStatus?.setUp == true
                     ? "Guard prod-like environments: agents then cannot read them."
                     : "To guard it, set up the guard first (Overview › YubiKey guard).")
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
