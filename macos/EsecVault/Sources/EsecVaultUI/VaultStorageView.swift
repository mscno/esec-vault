import AppKit
import EsecVaultCore
import SwiftUI

struct VaultStorageView: View {
    @Environment(Store.self) private var store
    @State private var inventory: VaultStorage?
    @State private var busy = false
    @State private var error: String?
    @State private var notice: String?
    @State private var importing = false
    @State private var importProject = ""
    @State private var importPath = ""
    @State private var moveAfterUpload = false
    @State private var restoreProfile: VaultStorage.Profile?
    @State private var mapUser = false
    @State private var replaceSettings = false
	@State private var restoreProject: VaultStorage.Project?
	@State private var selectedRevision = ""

    var body: some View {
        Form {
            Section {
                HStack {
                    Label("Server vault", systemImage: "externaldrive.badge.icloud")
                        .font(.title2.bold())
                    Spacer()
                    if busy { ProgressView().controlSize(.small) }
                    Button("Sync Now") { run(["sync", "--server"]) }
                    Button("Add to Vault…") { importing = true }
                    Button("Export Recovery File…") { exportRecovery() }
                }
                Text("Keys, device settings, and encrypted project revisions are stored on your vault server. Local keyrings provide optional offline access.")
                    .foregroundStyle(.secondary)
                if let inventory {
                    Label(inventory.pending ? "Saved locally — server upload pending" : "Server revision \(inventory.generation)", systemImage: inventory.pending ? "clock" : "checkmark.icloud")
                        .foregroundStyle(inventory.pending ? .orange : .secondary)
					if inventory.offline { Label("Server unavailable — showing the last verified local inventory", systemImage: "wifi.slash").foregroundStyle(.orange) }
					if inventory.stagingFailed { Label("Some local changes could not be prepared for backup. Sync Now will show the error.", systemImage: "exclamationmark.triangle").foregroundStyle(.orange) }
                }
                if let error { Text(error).foregroundStyle(.red).textSelection(.enabled) }
                if let notice { Text(notice).foregroundStyle(.secondary) }
            }
            Section("Projects") {
                if let inventory, inventory.projects.isEmpty { Text("Add an existing keyring or create a project to start.") }
                ForEach(inventory?.projects ?? []) { project in
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text(project.project).font(.headline)
                            Spacer()
                            Text(project.cached ? "Local keyring available" : "No local keyring").foregroundStyle(.secondary)
                        }
                        Text("\(project.keys) keys · \(project.revisions) encrypted file revisions").font(.caption).foregroundStyle(.secondary)
                        HStack {
                            if !project.cached {
                                Button("Keep Available Offline") { run(["storage", "cache", "--project", project.project, "--mode", "offline"]) }
                            } else {
                                Button("Remove Local Copy") { run(["storage", "cache", "--project", project.project, "--mode", "none"]) }
                            }
                            Button("Export Keyring…") { export(project) }
							if let first = project.history.first {
								Button("Restore Project…") { selectedRevision = first.id; restoreProject = project }
							}
                        }
                    }.padding(.vertical, 4)
                }
            }
            Section("Device settings") {
                ForEach(inventory?.profiles ?? []) { profile in
                    HStack {
                        VStack(alignment: .leading) {
                            Text(profile.name)
                            Text(profile.files.isEmpty ? "No custom broker settings" : profile.files.joined(separator: ", ")).font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("Restore Settings…") { restoreProfile = profile; mapUser = false; replaceSettings = false }
                            .disabled(profile.files.isEmpty)
                    }
                }
            }
            Section {
                Text("Removing a local copy waits for verified server sync and locks the broker. Existing independent exports and old backup files remain yours to manage. Exported keyrings work with standalone esec and are outside broker controls. Guarded keys stay sealed.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Server Vault")
        .disabled(busy)
        .task { await refresh() }
        .sheet(isPresented: $importing) {
            VStack(alignment: .leading, spacing: 16) {
                Text("Add a keyring to your vault").font(.headline)
                TextField("Project, for example acme/api", text: $importProject)
                HStack { Text(importPath.isEmpty ? "Choose an esec keyring" : (importPath as NSString).lastPathComponent); Spacer(); Button("Choose…") { chooseImport() } }
                Toggle("Move to server after verification", isOn: $moveAfterUpload)
                Text("Moving removes the source file and managed local keyring only after the server copy has been verified.").font(.caption).foregroundStyle(.secondary)
                HStack {
                    Button("Cancel") { importing = false }
                    Spacer()
                    Button("Add to Vault") {
                        importing = false
                        var args = ["storage", "add", "--project", importProject, "--file", importPath]
                        if moveAfterUpload { args.append("--move") }
                        run(args)
                    }.disabled(importProject.isEmpty || importPath.isEmpty)
                }
            }.padding(24).frame(width: 480)
        }
        .sheet(item: $restoreProfile) { profile in
            VStack(alignment: .leading, spacing: 16) {
                Text("Restore settings from \(profile.name)").font(.headline)
                Text("Broker policies control access on this device. Review the source device before restoring its settings.")
                Toggle("Map the source device’s owner to my local user", isOn: $mapUser)
                Toggle("Replace existing policy and trust settings", isOn: $replaceSettings)
                HStack {
                    Button("Cancel") { restoreProfile = nil }
                    Spacer()
                    Button("Restore Settings") {
                        restoreProfile = nil
                        var args = ["storage", "restore-settings", "--profile", profile.id]
                        if mapUser { args.append("--map-user") }
                        if replaceSettings { args.append("--replace") }
                        run(args)
                    }
                }
            }.padding(24).frame(width: 480)
        }
		.sheet(item: $restoreProject) { project in
			VStack(alignment: .leading, spacing: 16) {
				Text("Restore \(project.project)").font(.headline)
				Text("Choose a complete revision. Files, project configuration, and key seals are restored together into a new folder.")
				Picker("Revision", selection: $selectedRevision) {
					ForEach(project.history) { revision in
						Text("\(revision.label) · \(revision.at.formatted(date: .abbreviated, time: .shortened)) · \(revision.files) files").tag(revision.id)
					}
				}
				HStack {
					Button("Cancel") { restoreProject = nil }
					Spacer()
					Button("Choose Destination…") {
						guard let revision = project.history.first(where: { $0.id == selectedRevision }) else { return }
						restoreProject = nil
						restore(project, revision: revision)
					}
				}
			}.padding(24).frame(width: 620)
		}
    }

    @MainActor private func refresh() async {
        guard let cli = store.cli else { return }
        do { inventory = try await cli.vaultStorage(); error = nil }
        catch { self.error = error.localizedDescription }
    }
    private func run(_ args: [String]) {
        guard let cli = store.cli else { return }
        busy = true; error = nil; notice = nil
        Task {
            do {
                let result = try await cli.run(args)
                notice = String(decoding: result, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                await refresh()
                await store.refresh(full: true)
            } catch { self.error = error.localizedDescription }
            busy = false
        }
    }
    private func chooseImport() {
        let panel = NSOpenPanel(); panel.showsHiddenFiles = true; panel.canChooseDirectories = false
        if panel.runModal() == .OK, let url = panel.url { importPath = url.path }
    }
    private func export(_ project: VaultStorage.Project) {
        let panel = NSSavePanel(); panel.nameFieldStringValue = project.project.replacingOccurrences(of: "/", with: "_") + ".keyring"
        panel.message = "Creates an independent keyring for standalone esec. Guarded keys stay sealed. Choose a new file."
        if panel.runModal() == .OK, let url = panel.url { run(["storage", "export", "--project", project.project, "--out", url.path]) }
    }
    private func restore(_ project: VaultStorage.Project, revision: VaultStorage.Revision) {
        let panel = NSSavePanel(); panel.nameFieldStringValue = String(project.project.split(separator: "/").last ?? "project") + "-restored"
        panel.message = "Choose a new folder name. Existing directories will not be overwritten."
        panel.prompt = "Restore"
        if panel.runModal() == .OK, let url = panel.url { run(["storage", "restore-project", "--project", project.project, "--checkout", revision.checkout, "--revision", revision.id, "--to", url.path]) }
    }
    private func exportRecovery() {
        let panel = NSSavePanel(); panel.nameFieldStringValue = "esec-recovery.esec"
        panel.message = "An encrypted portable export containing keys, settings, and archived files. Your recovery phrase can open it."
        if panel.runModal() == .OK, let url = panel.url { run(["backup", "--verify", "--out", url.path]) }
    }
}
