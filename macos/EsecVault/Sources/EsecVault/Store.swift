import AppKit
import EsecVaultCore
import Observation

/// The app's state: what esec-vault reports, refreshed on demand and every
/// minute. Actions run esec-vault commands; a guarded action shows esec's own
/// dialog and waits for a touch of the security key, as on the command line.
@MainActor
@Observable
final class Store {
    var cli: CLI? = CLI.locate()
    var projects: [Project] = []
    var details: [String: Project] = [:]
    var guardStatus: GuardStatus?
    var verify: VerifySaved?
    /// What is running now, shown in the toolbar.
    var busy: String?
    var message: String?
    var lastError: String?
    var search = ""

    private var timer: Timer?

    var health: Health { verify?.health ?? .unknown("Keys not checked yet") }

    /// Projects grouped by namespace ("acme" of "acme/store"), filtered by search.
    var namespaces: [(name: String, projects: [Project])] {
        let q = search.lowercased()
        let shown = q.isEmpty ? projects : projects.filter {
            $0.project.lowercased().contains(q) || $0.checkouts.contains { $0.path.lowercased().contains(q) }
        }
        let grouped = Dictionary(grouping: shown, by: \.namespace)
        return grouped.keys.sorted().map { ($0, grouped[$0]!.sorted { $0.project < $1.project }) }
    }

    var guardedCount: Int { projects.reduce(0) { $0 + $1.envs.filter(\.isGuarded).count } }

    func start() {
        Task { await refresh() }
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
            Task { @MainActor in await self?.refresh() }
        }
    }

    func refresh() async {
        guard let cli else {
            lastError = "esec-vault was not found. Install it (go install github.com/mscno/esec-vault/cmd/esec-vault@latest) or set ESEC_VAULT_BIN."
            return
        }
        do {
            async let p = cli.projects()
            async let g = cli.guardStatus()
            async let v = cli.lastVerify()
            projects = try await p
            guardStatus = try? await g
            verify = try? await v
            lastError = nil
        } catch {
            lastError = error.localizedDescription
        }
    }

    func loadDetail(_ id: String) async {
        guard let cli else { return }
        do {
            details[id] = try await cli.project(id)
        } catch {
            lastError = error.localizedDescription
        }
    }

    /// Runs one esec-vault command as an action, then refreshes.
    func perform(_ label: String, _ args: [String], then: String? = nil) async {
        guard let cli, busy == nil else { return }
        busy = label
        defer { busy = nil }
        do {
            let out = try await cli.run(args)
            let text = String(decoding: out, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            message = text.split(separator: "\n").first.map(String.init) ?? label
            lastError = nil
        } catch {
            lastError = error.localizedDescription
        }
        await refresh()
        if let then { await loadDetail(then) }
    }

    func verifyNow() async {
        guard let cli, busy == nil else { return }
        busy = "Checking every key…"
        defer { busy = nil }
        do {
            _ = try await cli.verifyNow()
        } catch {
            lastError = error.localizedDescription
        }
        await refresh()
    }

    func scan(_ url: URL) async { await perform("Finding checkouts…", ["projects", "scan", url.path]) }
    func add(_ url: URL) async { await perform("Adding…", ["projects", "add", url.path]) }
    func forget(_ path: String) async { await perform("Forgetting…", ["projects", "remove", path]) }
    func prune() async { await perform("Pruning…", ["projects", "prune"]) }

    /// Guards an environment: esec shows its dialog, then the key waits for a touch.
    func guardEnv(_ project: String, _ env: String, level: String) async {
        await perform("Guarding \(env) — touch your security key…", ["guard", "enable", "--project", project, "--env", env, "--level", level], then: project)
    }

    func revealInFinder(_ path: String) {
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }

    func openTerminal(_ path: String) {
        guard let terminal = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.Terminal") else { return }
        NSWorkspace.shared.open([URL(fileURLWithPath: path)], withApplicationAt: terminal, configuration: NSWorkspace.OpenConfiguration())
    }

    func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        message = "Copied"
    }
}
