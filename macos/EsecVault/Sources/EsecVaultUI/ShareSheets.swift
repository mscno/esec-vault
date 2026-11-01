import EsecVaultCore
import SwiftUI

/// Shares environments with GitHub users: by login, pinned to their
/// numeric id; their keys are sealed in, in the repository.
struct ShareSheet: View {
    @Environment(Store.self) private var store
    @Environment(\.dismiss) private var dismiss
    let project: Project
    let checkout: String
    @State private var who = ""
    @State private var envs: Set<String> = []

    private var people: [String] {
        who.split(whereSeparator: { $0 == "," || $0 == " " || $0 == "\n" })
            .map { String($0).trimmingCharacters(in: CharacterSet(charactersIn: "@")) }
            .filter { !$0.isEmpty }
    }

    var body: some View {
        Form {
            Section {
                TextField("GitHub users", text: $who, prompt: Text("alice, bob"))
                ForEach(project.envs) { env in
                    Toggle(isOn: Binding(get: { envs.contains(env.name) }, set: { on in
                        if on { envs.insert(env.name) } else { envs.remove(env.name) }
                    })) {
                        HStack {
                            Text(env.name)
                            if env.isGuarded {
                                Text("guarded: sealed to their security keys").font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            } header: {
                Text("Share \(project.project)")
            } footer: {
                Text("Each person is pinned by their GitHub id, so a renamed or re-registered login never gets in. Someone without an esec vault account, or without a security key for a guarded environment, is sealed in once they have one. Commit .esec/ and esec.toml afterwards: sharing is a change reviewed like code.")
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(width: 480)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            ToolbarItem(placement: .confirmationAction) {
                Button("Share") {
                    Task {
                        let ordered = project.envs.map(\.name).filter { envs.contains($0) }
                        if await store.share(project.project, envs: ordered, with: people, in: checkout) { dismiss() }
                    }
                }
                .disabled(people.isEmpty || envs.isEmpty || store.busy != nil)
            }
        }
    }
}

/// Gives a CI job or a deploy its own age key, sealed into environments.
/// The key goes straight into GitHub or Fly, or is shown once; the app never
/// keeps it.
struct CIKeySheet: View {
    @Environment(Store.self) private var store
    @Environment(\.dismiss) private var dismiss
    let project: Project
    let checkout: String
    @State private var name = "deploy"
    @State private var envs: Set<String> = []
    @State private var destination = "github"
    @State private var target = ""
    @State private var shown: String?

    var body: some View {
        Form {
            if let shown {
                Section {
                    Text(shown)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .lineLimit(2)
                    Button("Copy") { store.copy(shown) }
                } header: {
                    Text("The key of \(name), shown once")
                } footer: {
                    Text("Store it as the secret ESEC_AGE_IDENTITY of the CI job now: it is not kept anywhere, and closing this sheet forgets it.")
                        .foregroundStyle(.orange)
                }
            } else {
                Section {
                    TextField("Name", text: $name, prompt: Text("deploy"))
                    ForEach(project.envs) { env in
                        Toggle(env.name, isOn: Binding(get: { envs.contains(env.name) }, set: { on in
                            if on { envs.insert(env.name) } else { envs.remove(env.name) }
                        }))
                    }
                    Picker("Store it in", selection: $destination) {
                        Text("GitHub Actions secret").tag("github")
                        Text("Fly app secret").tag("fly")
                        Text("Show it once").tag("show")
                    }
                    if destination != "show" {
                        TextField(destination == "github" ? "Repository" : "Fly app", text: $target,
                                  prompt: Text(destination == "github" ? "acme/store" : "acme-store"))
                    }
                } header: {
                    Text("A CI key for \(project.project)")
                } footer: {
                    Text("The job then reads these environments with esec alone (ESEC_AGE_IDENTITY), guarded ones too: machines have no fingers. It is stored with gh or fly, never on a command line.")
                        .foregroundStyle(.secondary)
                }
            }
        }
        .formStyle(.grouped)
        .frame(width: 480)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button(shown == nil ? "Cancel" : "Done") { shown = nil; dismiss() } }
            if shown == nil {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Add") {
                        Task {
                            let ordered = project.envs.map(\.name).filter { envs.contains($0) }
                            let key = await store.addCIKey(project.project, name: name, envs: ordered,
                                                           github: destination == "github" ? target : nil,
                                                           fly: destination == "fly" ? target : nil, in: checkout)
                            if destination == "show", let key { shown = key } else if store.lastError == nil { dismiss() }
                        }
                    }
                    .disabled(name.isEmpty || envs.isEmpty || (destination != "show" && target.isEmpty) || store.busy != nil)
                }
            }
        }
    }
}
