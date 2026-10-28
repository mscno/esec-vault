import EsecVaultCore
import SwiftUI

struct ProjectDetail: View {
    @Environment(Store.self) private var store
    let id: String

    private var project: Project? { store.details[id] ?? store.projects.first { $0.project == id } }

    var body: some View {
        Group {
            if let project {
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
                            EnvRow(project: project.project, env: env)
                        }
                    } header: {
                        Text("Environments")
                    } footer: {
                        Text("A guarded key opens only after you allow it in esec's dialog and touch your security key. Agents cannot touch it.")
                            .foregroundStyle(.secondary)
                    }
                    if let files = project.files, !files.isEmpty {
                        Section("Secrets files") {
                            ForEach(files) { f in FileRow(file: f) }
                        }
                    }
                }
                .formStyle(.grouped)
                .navigationTitle(project.project)
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

    var body: some View {
        HStack {
            Image(systemName: env.isGuarded ? "lock.fill" : "key")
                .foregroundStyle(env.isGuarded ? .blue : .secondary)
                .frame(width: 18)
            Text(env.name).bold()
            Text(guardText).foregroundStyle(.secondary)
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
            if env.here == "clear" {
                Divider()
                Button("Guard: Touch for Every Read") { Task { await store.guardEnv(project, env.name, level: "touch") } }
                Button("Guard: Touch Once per Session") { Task { await store.guardEnv(project, env.name, level: "session") } }
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
