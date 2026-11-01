import AppKit
import EsecVaultCore
import SwiftUI

/// Sets up a project in a folder: esec.toml, a key per environment (stored
/// on the vault server or a backup first) and a secrets file for each.
struct NewProjectSheet: View {
    @Environment(Store.self) private var store
    @Environment(\.dismiss) private var dismiss
    @State var draft: ProjectDraft
    @State private var envText = "dev, prod"
    @State private var guarded: Set<String> = ["prod"]

    private var envs: [String] {
        EnvironmentName.parseList(envText)
    }

    private var guardReady: Bool { store.guardStatus?.setUp == true }

    var body: some View {
        Form {
            Section {
                LabeledContent("Folder") {
                    HStack {
                        Text((draft.dir.path as NSString).abbreviatingWithTildeInPath).lineLimit(1).truncationMode(.head)
                        Button("Choose…") { choose() }
                    }
                }
                TextField("Project id", text: $draft.project, prompt: Text("from the git remote, such as acme/store"))
                TextField("Environments", text: $envText, prompt: Text("dev, prod"))
                Picker("Files", selection: $draft.format) {
                    Text("Your default").tag("default")
                    Text(".env").tag("env")
                    Text("JSON (ejson)").tag("ejson")
                    Text("YAML (eyaml)").tag("eyaml")
                    Text("TOML (etoml)").tag("etoml")
                }
                Toggle("Encrypt existing plaintext files", isOn: $draft.encryptExisting)
                    .help("Add public keys where missing and encrypt the existing values in place. Multiline or colon-style dotenv entries are normalized to single lines and their comments are removed.")
                if EnvironmentName.isValidList(envs) {
                    ForEach(envs, id: \.self) { env in
                        Toggle("Require approval for every \(env) read", isOn: Binding(get: { guarded.contains(env) }, set: { on in
                            if on { guarded.insert(env) } else { guarded.remove(env) }
                        }))
                        .disabled(!guardReady)
                    }
                } else {
                    Text("Use unique names with dot-separated lowercase letters and digits, such as dev, api.prod.")
                        .font(.caption).foregroundStyle(.orange)
                }
            } header: {
                Text("New project")
            } footer: {
                Text(footer).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(width: 480)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            ToolbarItem(placement: .confirmationAction) {
                Button("Create") {
                    draft.envs = envs
                    draft.guarded = guardReady ? envs.filter { guarded.contains($0) } : []
                    Task { if await store.newProject(draft) { dismiss() } }
                }
                .disabled(!EnvironmentName.isValidList(envs) || store.busy != nil)
            }
        }
    }

    private var footer: String {
        var text = "Creates esec.toml and missing secrets files containing only their public key. Example files are never copied. Enable the option above to approve encryption of existing plaintext files."
        if !guardReady { text += " To guard environments, add a passkey or security key first (Security Keys)." }
        return text
    }

    private func choose() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.directoryURL = draft.dir
        if panel.runModal() == .OK, let url = panel.url { draft.dir = url }
    }
}
