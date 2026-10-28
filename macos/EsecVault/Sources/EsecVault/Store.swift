import AppKit
import EsecVaultCore
import Observation
import ServiceManagement

/// The app's state: what esec-vault reports, refreshed when its files change
/// and every few minutes. Actions run esec-vault commands; a guarded action
/// shows esec's own dialog and waits for a touch of the security key, as on
/// the command line. Commands that ask for a phrase or a PIN open Terminal.
@MainActor
@Observable
final class Store {
    var cli: CLI? = CLI.locate()
    var projects: [Project] = []
    var details: [String: Project] = [:]
    var guardStatus: GuardStatus?
    var verify: VerifySaved?
    var status: Status?
    var activity: [ActivityEntry] = []
    /// Every environment's seal across the checkouts here.
    var seals: [SealView] = []
    var securityKeys: SecurityKeyList?
    /// What is running now, shown in the toolbar.
    var busy: String?
    var message: String?
    var lastError: String?
    var search = ""

    private var timer: Timer?
    private var watchers: [DispatchSourceFileSystemObject] = []
    private var pending: Task<Void, Never>?
    private var needsRewatch = false
    private var lastStatus = Date.distantPast

    var health: Health { verify?.health ?? .unknown("Keys not checked yet") }

    /// What esec-vault setup --check reports.
    var setup: [SetupItem] = []

    /// Seals that should be made again, or are broken, across checkouts.
    var sealsToFix: [SealView] { seals.filter(\.needsAttention) }

    /// Plugged-in YubiKeys not registered yet, for the sidebar badge.
    var unregisteredKeys: Int { (securityKeys?.unregistered.count ?? 0) + (securityKeys?.unprovisioned.count ?? 0) }

    /// Setup steps still to do, for the sidebar badge.
    var setupTodo: Int { setup.filter { $0.state == .todo || $0.state == .warning }.count }

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

    /// Requests for guarded keys in the last day, for the menu.
    var recentGuarded: [ActivityEntry] {
        let guarded = Set(projects.flatMap { p in p.envs.filter(\.isGuarded).map { "\(p.project) \($0.name)" } })
        let since = Date().addingTimeInterval(-86_400)
        return activity.filter { $0.ts > since && guarded.contains("\($0.project ?? "") \($0.env ?? "")") }
    }

    func start() {
        Task { await refresh(full: true) }
        watch()
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: 300, repeats: true) { [weak self] _ in
            Task { @MainActor in await self?.refresh(full: true) }
        }
    }

    /// Refreshes what the app shows. status talks to the vault server, so
    /// it runs only on a full refresh or every few minutes.
    func refresh(full: Bool = false) async {
        guard let cli else {
            lastError = "esec-vault was not found. Install it (go install github.com/mscno/esec-vault/cmd/esec-vault@latest) or set ESEC_VAULT_BIN."
            return
        }
        do {
            async let p = cli.projects()
            async let g = cli.guardStatus()
            async let v = cli.lastVerify()
            async let a = cli.activity()
            async let k = cli.securityKeys()
            projects = try await p
            guardStatus = try? await g
            verify = try? await v
            activity = (try? await a) ?? activity
            securityKeys = (try? await k) ?? securityKeys
            lastError = nil
        } catch {
            lastError = error.localizedDescription
        }
        if full || Date().timeIntervalSince(lastStatus) > 300 {
            lastStatus = Date()
            status = try? await cli.status()
            setup = (try? await cli.setup()) ?? setup
            // seal resolves readers through the vault server: not on every
            // file change.
            seals = (try? await cli.seals()) ?? seals
        }
    }

    /// Watches the vault's home (projects.toml, verify.json, keyrings) and
    /// its audit log, so a command run in a terminal or by an agent shows up
    /// at once.
    private func watch() {
        watchers.forEach { $0.cancel() }
        watchers = []
        for path in [Self.home, Self.home + "/audit.log", Self.home + "/keyrings"] {
            let fd = open(path, O_EVTONLY)
            guard fd >= 0 else { continue }
            let src = DispatchSource.makeFileSystemObjectSource(fileDescriptor: fd, eventMask: [.write, .extend, .rename, .delete], queue: .main)
            src.setEventHandler { [weak self, weak src] in
                // A replaced file (rotated log, atomic save) needs a new watch.
                let replaced = src.map { !$0.data.isDisjoint(with: [.delete, .rename]) } ?? false
                MainActor.assumeIsolated { self?.changed(rewatch: replaced) }
            }
            src.setCancelHandler { close(fd) }
            src.resume()
            watchers.append(src)
        }
    }

    /// Coalesces a burst of file changes into one refresh.
    private func changed(rewatch: Bool) {
        if rewatch { needsRewatch = true }
        pending?.cancel()
        pending = Task {
            try? await Task.sleep(for: .milliseconds(400))
            guard !Task.isCancelled else { return }
            if needsRewatch {
                needsRewatch = false
                watch()
            }
            await refresh()
            for id in details.keys { await loadDetail(id) }
        }
    }

    /// The vault's home directory, as esec-vault resolves it.
    static var home: String {
        let env = ProcessInfo.processInfo.environment
        if let h = env["ESEC_VAULT_HOME"], !h.isEmpty { return h }
        if let x = env["XDG_CONFIG_HOME"], !x.isEmpty { return x + "/esec" }
        return FileManager.default.homeDirectoryForCurrentUser.path + "/.config/esec"
    }

    func loadDetail(_ id: String) async {
        guard let cli else { return }
        do {
            details[id] = try await cli.project(id)
        } catch {
            lastError = error.localizedDescription
        }
    }

    /// Runs one esec-vault command as an action, then refreshes. It returns
    /// whether the command succeeded.
    @discardableResult
    func perform(_ label: String, _ args: [String], in dir: String? = nil, then: String? = nil) async -> Bool {
        guard let cli, busy == nil else { return false }
        busy = label
        defer { busy = nil }
        var ok = false
        do {
            let out = try await cli.run(args, in: dir)
            let text = String(decoding: out, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            message = text.split(separator: "\n").last.map(String.init) ?? label
            lastError = nil
            ok = true
        } catch {
            lastError = error.localizedDescription
        }
        await refresh(full: true)
        if let then { await loadDetail(then) }
        return ok
    }

    /// Runs a command that asks questions (a phrase, a PIN) in Terminal.
    func runInTerminal(_ args: [String], in dir: String? = nil) {
        guard let cli else { return }
        var script = "#!/bin/sh\n"
        if let dir { script += "cd \(CLI.quote(dir)) || exit 1\n" }
        script += "echo '$ esec vault \(args.joined(separator: " ").replacingOccurrences(of: "'", with: ""))'\n"
        script += cli.commandLine(args) + "\n"
        script += "echo; echo 'Done: this window can be closed.'\n"
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("esec-vault-\(UUID().uuidString).command")
        do {
            try script.write(to: url, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
        } catch {
            lastError = error.localizedDescription
            return
        }
        guard let terminal = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.Terminal") else { return }
        NSWorkspace.shared.open([url], withApplicationAt: terminal, configuration: NSWorkspace.OpenConfiguration())
        message = "Opened Terminal: esec vault \(args.joined(separator: " "))"
    }

    /// Does a setup step: in the app when it asks nothing, else in Terminal.
    func doSetup(_ item: SetupItem) async {
        guard let args = item.args else {
            runInTerminal(["setup"])
            return
        }
        if item.interactive {
            runInTerminal(args)
        } else {
            await perform(item.title + "…", args)
        }
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
    func prune() async { await perform("Forgetting missing checkouts…", ["projects", "prune"]) }

    /// Sets up a new project in dir: its esec.toml, a key per environment
    /// and a secrets file for each. Guarded environments need a touch.
    func newProject(_ draft: ProjectDraft) async -> Bool {
        var args = ["project", "init", "--dir", draft.dir.path, "--env", draft.envs.joined(separator: ",")]
        if !draft.project.isEmpty { args += ["--project", draft.project] }
        if !draft.guarded.isEmpty { args += ["--guard", draft.guarded.joined(separator: ",")] }
        if draft.format != "default" { args += ["--format", draft.format] }
        let touch = draft.guarded.isEmpty ? "" : " — touch your security key"
        let ok = await perform("Setting up the project\(touch)…", args, in: draft.dir.path)
        if ok { await add(draft.dir) }
        return ok
    }

    /// Adds an environment to a project, in one of its checkouts.
    func addEnv(_ project: String, in checkout: String, name: String, guardLevel: String) async -> Bool {
        let touch = guardLevel == "none" ? "" : " — touch your security key"
        return await perform("Adding \(name)\(touch)…", ["env", "add", name, "--project", project, "--guard", guardLevel], in: checkout, then: project)
    }

    /// Gives an environment a new key and re-encrypts its files.
    func rotate(_ project: String, _ env: EnvView, in checkout: String) async {
        let touch = env.isGuarded ? " — touch your security key" : ""
        await perform("Rotating \(env.name)\(touch)…", ["env", "rotate", env.name, "--project", project, "--yes"], in: checkout, then: project)
    }

    /// Guards an environment: esec shows its dialog, then the key waits for a touch.
    func guardEnv(_ project: String, _ env: String, level: String, in checkout: String?) async {
        await perform("Guarding \(env) — touch your security key…", ["guard", "enable", "--project", project, "--env", env, "--level", level], in: checkout, then: project)
    }

    /// Stops guarding an environment: sealed to the readers' user keys again.
    func unguardEnv(_ project: String, _ env: String, in checkout: String?) async {
        await perform("Unguarding \(env) — touch your security key…", ["guard", "disable", "--project", project, "--env", env], in: checkout, then: project)
    }

    // MARK: Sharing

    /// Shares environments with GitHub users, groups or keys.
    func share(_ project: String, envs: [String], with who: [String], in checkout: String?) async -> Bool {
        let touch = (details[project] ?? projects.first { $0.project == project })?.envs.contains { envs.contains($0.name) && $0.isGuarded } == true
            ? " — touch your security key" : ""
        return await perform("Sharing\(touch)…", ["share", envs.joined(separator: ","), "--with", who.joined(separator: ","), "--project", project], in: checkout, then: project)
    }

    /// Stops sharing an environment with someone, optionally rotating it.
    func unshare(_ project: String, env: String, who: String, rotate: Bool, in checkout: String?) async {
        var args = ["unshare", env, "--with", who, "--project", project]
        if rotate { args += ["--rotate", "--yes"] }
        await perform("Unsharing \(env)…", args, in: checkout, then: project)
    }

    /// Gives a CI job its own key. Without a destination the key is
    /// returned, to show once; it is never kept.
    func addCIKey(_ project: String, name: String, envs: [String], github: String?, fly: String?, in checkout: String?) async -> String? {
        guard let cli, busy == nil else { return nil }
        var args = ["ci", "add", name, "--env", envs.joined(separator: ","), "--project", project]
        if let github, !github.isEmpty { args += ["--github", github] }
        if let fly, !fly.isEmpty { args += ["--fly", fly] }
        busy = "Adding the CI key \(name)…"
        defer { busy = nil }
        var key: String?
        do {
            let out = String(decoding: try await cli.run(args, in: checkout), as: UTF8.self)
            key = out.split(separator: "\n").first { $0.hasPrefix("AGE-SECRET-KEY-1") }.map(String.init)
            message = out.split(separator: "\n").last.map(String.init)
            lastError = nil
        } catch {
            lastError = error.localizedDescription
        }
        await refresh(full: true)
        await loadDetail(project)
        return key
    }

    // MARK: Seals

    /// Seals again what changed, across checkouts. Guarded ones need a touch each.
    func sealAgain() async {
        await perform("Sealing again — guarded ones need a touch each…", ["seal", "sync", "--all"])
    }

    /// Reseals every guarded environment with the recovery phrase, in Terminal.
    func recoverSeals() { runInTerminal(["seal", "recover", "--all"]) }

    // MARK: Security keys

    func addSecurityKey(name: String?) async {
        var args = ["security-keys", "add"]
        if let name, !name.isEmpty { args += ["--name", name] }
        await perform("Registering the security key…", args)
    }

    func removeSecurityKey(_ id: String) async {
        await perform("Removing the security key…", ["security-keys", "remove", id])
    }

    func testSecurityKey(_ id: String) async {
        await perform("Testing — touch your security key…", ["security-keys", "test", id])
    }

    func setUpYubiKey() { runInTerminal(["security-keys", "setup"]) }

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

    // Opening at login works for the bundled app (bundle.sh) only.
    var opensAtLogin: Bool {
        get { SMAppService.mainApp.status == .enabled }
        set {
            do {
                if newValue { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
            } catch {
                lastError = "Open at login: \(error.localizedDescription)"
            }
        }
    }
}

/// What the New Project sheet collects.
struct ProjectDraft: Identifiable {
    var id: URL { dir }
    var dir: URL
    var project = ""
    var envs = ["dev", "prod"]
    var guarded: [String] = []
    var format = "default"
}
