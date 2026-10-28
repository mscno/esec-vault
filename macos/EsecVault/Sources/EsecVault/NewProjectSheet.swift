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
    @State private var guardProd = true

    private var envs: [String] {
        envText.split(whereSeparator: { $0 == "," || $0 == " " }).map { $0.lowercased() }.filter { !$0.isEmpty }
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
                Toggle("Guard prod with my security key", isOn: $guardProd)
                    .disabled(!guardReady || !envs.contains("prod"))
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
                    draft.guarded = guardProd && guardReady && envs.contains("prod") ? ["prod"] : []
                    Task { if await store.newProject(draft) { dismiss() } }
                }
                .disabled(envs.isEmpty || store.busy != nil)
            }
        }
    }

    private var footer: String {
        var text = "Writes esec.toml and an encrypted secrets file per environment; commit them. Each key is stored on your vault server or backup before a file uses it."
        if !guardReady { text += " To guard prod, set up the guard first (Overview)." }
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
