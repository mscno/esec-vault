import AppKit
import EsecVaultCore
import Observation
import ServiceManagement

/// The app's state: what esec-vault reports, refreshed when its files change
/// and through a lightweight daemon poll. Actions run the same CLI as the
/// Terminal. macOS handles passkey approval; recovery phrases stay in Terminal.
@MainActor
@Observable
final class Store {
    var cli: CLI? = CLI.locate()
    var projects: [Project] = []
    var details: [String: Project] = [:]
    var guardStatus: GuardStatus?
    var verify: VerifySaved?
    var status: Status?
    var daemonState: DaemonStatus?
    var refreshErrors: [String: String] = [:]
    var activity: [ActivityEntry] = []
    /// Every environment's seal across the checkouts here.
    var seals: [SealView] = []
    var securityKeys: SecurityKeyList?
    /// What is running now, shown in the toolbar.
    var busy: String?
    var message: String?
    var lastError: String?
    var search = ""

    @ObservationIgnored private var secretWindows: [String: SecretFileWindow] = [:]
    @ObservationIgnored private var comparisonWindows: [String: SecretComparisonWindow] = [:]

    func openSecretComparison(_ project: Project) {
        guard let cli else {
            lastError = "The esec-vault CLI was not found. Reinstall EsecVault."
            return
        }
        let controller: SecretComparisonWindow
        if let existing = comparisonWindows[project.id] {
            controller = existing
        } else {
            controller = SecretComparisonWindow(project: project, cli: cli) { [weak self] path in self?.openSecretFile(path) }
            controller.onClose = { [weak self] in self?.comparisonWindows[project.id] = nil }
            comparisonWindows[project.id] = controller
        }
        controller.showWindow(nil)
        controller.window?.makeKeyAndOrderFront(nil)
        NSApp.activate()
    }

    private func lockSecretWindows() {
        secretWindows.values.forEach { $0.model.lock() }
        comparisonWindows.values.forEach { $0.model.lock() }
    }

    func openSecretFile(_ path: String) {
        guard let cli else {
            lastError = "The esec-vault CLI was not found. Reinstall EsecVault."
            return
        }
        let path = URL(fileURLWithPath: path).resolvingSymlinksInPath().path
        if let existing = secretWindows[path] {
            existing.showWindow(nil)
            existing.window?.makeKeyAndOrderFront(nil)
        } else {
            let controller = SecretFileWindow(path: path, cli: cli)
            controller.onClose = { [weak self] in self?.secretWindows[path] = nil }
            secretWindows[path] = controller
            controller.showWindow(nil)
            controller.window?.makeKeyAndOrderFront(nil)
        }
        NSApp.activate()
    }

    func chooseSecretFile() {
        let panel = NSOpenPanel()
        panel.title = "Open Secrets File"
        panel.message = "Choose an esec file in a project. Its values will be decrypted in memory."
        panel.showsHiddenFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        if panel.runModal() == .OK, let url = panel.url { openSecretFile(url.path) }
    }

    private var timer: Timer?
    private var runtimeTimer: Timer?
    private var started = false
    private var refreshing = false
    private var runtimeRefreshing = false
    private var refreshAgain = false
    private var fullRefreshAgain = false
    private var watchers: [DispatchSourceFileSystemObject] = []
    private var pending: Task<Void, Never>?
    private var needsRewatch = false
    private var lastStatus = Date.distantPast

    var health: Health {
        let keys = verify?.health ?? .unknown("Keys not checked yet")
        if case .lost = keys { return keys }
        if guardStatus?.projects.contains(where: { !($0.clear ?? []).isEmpty }) == true {
            return .attention("Guarded keys are still cached on this Mac")
        }
        if !refreshErrors.isEmpty { return .attention("Some status checks could not complete") }
        if daemonState?.needsAttention == true { return .attention("Background service needs attention") }
        if !(status?.problems ?? []).isEmpty { return .attention("Vault status needs attention") }
        if !sealsToFix.isEmpty { return .attention("Sealed keys need attention") }
        if projects.contains(where: \.hasProblem) { return .attention("Project configuration needs attention") }
        return keys
    }

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
        guard !started else { return }
        started = true
        Task { await refresh(full: true) }
        watch()
        timer = Timer.scheduledTimer(withTimeInterval: 300, repeats: true) { [weak self] _ in
            Task { @MainActor in await self?.refresh(full: true) }
        }
        runtimeTimer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            Task { @MainActor in await self?.refreshRuntime() }
        }
    }

    /// Failed reads retain their last data but are marked as unavailable;
    /// they can never silently turn into an empty, healthy result.
    private func read<T>(_ source: String, _ operation: () async throws -> T) async -> T? {
        do {
            let value = try await operation()
            refreshErrors[source] = nil
            return value
        } catch {
            refreshErrors[source] = error.localizedDescription
            return nil
        }
    }

    func refreshRuntime() async {
        guard let cli, !runtimeRefreshing else { return }
        runtimeRefreshing = true
        defer { runtimeRefreshing = false }
        let wasOpen = daemonState?.unlocked == true
        daemonState = await read("Background service") { try await cli.daemonStatus() }
        if wasOpen && daemonState?.sessionIsOpen() != true {
            lockSecretWindows()
        }
    }

    /// Metadata refreshes are serialized; file notifications during a read
    /// request one more pass rather than spawning overlapping CLI processes.
    func refresh(full: Bool = false) async {
        guard let cli else {
            lastError = "The bundled esec-vault CLI was not found. Reinstall EsecVault or check ESEC_VAULT_BIN."
            return
        }
        if refreshing {
            refreshAgain = true
            fullRefreshAgain = fullRefreshAgain || full
            return
        }
        refreshing = true
        defer { refreshing = false }
        var full = full
        repeat {
            refreshAgain = false
            fullRefreshAgain = false
            async let p = read("Projects") { try await cli.projects() }
            async let g = read("Guard") { try await cli.guardStatus() }
            async let v = read("Key verification") { try await cli.lastVerify() }
            async let a = read("Activity") { try await cli.activity() }
            if let value = await p { projects = value }
            if let value = await g { guardStatus = value }
            if let value = await v { verify = value }
            if let value = await a { activity = value }
            // The daemon already scans connected cards. A GUI refresh reads
            // its cache; only Scan Connected YubiKeys opens a card explicitly.
            if let value = await read("Security keys", { try await cli.securityKeys() }) { securityKeys = value }
            await refreshRuntime()
            if full || Date().timeIntervalSince(lastStatus) > 300 {
                lastStatus = Date()
                async let st = read("Vault status") { try await cli.status() }
                async let su = read("Setup") { try await cli.setup() }
                async let se = read("Seals") { try await cli.seals() }
                if let value = await st { status = value }
                if let value = await su { setup = value }
                if let value = await se { seals = value }
            }
            for id in Array(details.keys) { await loadDetail(id) }
            if started { watch() }
            full = fullRefreshAgain
        } while refreshAgain
    }

    /// Watch project files as well as vault metadata. Editors and CLI actions
    /// save esec.toml and seals atomically, so their parent directories matter.
    private func watch() {
        watchers.forEach { $0.cancel() }
        watchers = []
        let env = ProcessInfo.processInfo.environment
        var paths = [Self.home, Self.home + "/audit.log", Self.home + "/run",
                     env["ESEC_KEYRING_DIR"] ?? Self.home + "/keyrings"]
        let checkouts = projects.flatMap(\.checkouts).filter { $0.status != "gone" }
        for checkout in checkouts {
            paths += [checkout.path, checkout.path + "/esec.toml", checkout.path + "/.esec"]
        }
        let projectPaths = Set(checkouts.flatMap { [$0.path, $0.path + "/esec.toml", $0.path + "/.esec"] })
        for path in Set(paths) {
            let fd = open(path, O_EVTONLY)
            guard fd >= 0 else { continue }
            let src = DispatchSource.makeFileSystemObjectSource(fileDescriptor: fd, eventMask: [.write, .extend, .rename, .delete], queue: .main)
            let projectChanged = projectPaths.contains(path)
            src.setEventHandler { [weak self, weak src] in
                let replaced = src.map { !$0.data.isDisjoint(with: [.delete, .rename]) } ?? false
                MainActor.assumeIsolated { self?.changed(rewatch: replaced, full: projectChanged) }
            }
            src.setCancelHandler { close(fd) }
            src.resume()
            watchers.append(src)
        }
    }

    private var needsFullRefresh = false

    /// Coalesces a burst of file changes into one refresh.
    private func changed(rewatch: Bool, full: Bool) {
        needsRewatch = needsRewatch || rewatch
        needsFullRefresh = needsFullRefresh || full
        pending?.cancel()
        pending = Task {
            try? await Task.sleep(for: .milliseconds(400))
            guard !Task.isCancelled else { return }
            let full = needsFullRefresh
            needsFullRefresh = false
            if needsRewatch {
                needsRewatch = false
                watch()
            }
            await refresh(full: full)
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
        if let value = await read("Project " + id, { try await cli.project(id) }) { details[id] = value }
    }

    /// Runs one esec-vault command as an action, then refreshes. It returns
    /// whether the command succeeded.
    @discardableResult
    func perform(_ label: String, _ args: [String], in dir: String? = nil, then: String? = nil) async -> Bool {
        await perform(label, commands: [args], in: dir, then: then)
    }

    @discardableResult
    private func perform(_ label: String, commands: [[String]], in dir: String? = nil, then: String? = nil) async -> Bool {
        guard let cli, busy == nil else { return false }
        busy = label
        defer { busy = nil }
        var ok = false
        do {
            for args in commands { _ = try await cli.run(args, in: dir) }
            message = label.trimmingCharacters(in: CharacterSet(charactersIn: "…")) + " — done"
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
        let environment = ProcessInfo.processInfo.environment
        // Preserve the vault/config routing of this GUI when Terminal starts
        // a new login shell. Only public routing paths are written here.
        script += "export ESEC_VAULT_HOME=\(CLI.quote(Self.home))\n"
        for key in ["ESEC_KEYRING_DIR", "ESEC_CONFIG", "ESEC_VAULT_SOCK"] {
            if let value = environment[key], !value.isEmpty { script += "export \(key)=\(CLI.quote(value))\n" }
        }
        let path = cli.binary.deletingLastPathComponent().path + ":" + FileManager.default.homeDirectoryForCurrentUser.path + "/go/bin:/opt/homebrew/bin:/usr/local/bin:" + (environment["PATH"] ?? "/usr/bin:/bin")
        script += "export PATH=\(CLI.quote(path))\n"
        script += "export ESEC_VAULT_SESSION='EsecVault app'\n"
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
        if item.step == "guard", let guarded = guardStatus?.projects.filter({ !($0.clear ?? []).isEmpty }), !guarded.isEmpty {
            for project in guarded { await guardHere(project) }
            return
        }
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
            lastError = nil
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
    /// and a secrets file for each. Sealing a new key uses public recipients.
    func newProject(_ draft: ProjectDraft) async -> Bool {
        var args = ["project", "init", "--dir", draft.dir.path, "--env", draft.envs.joined(separator: ",")]
        if !draft.project.isEmpty { args += ["--project", draft.project] }
        if !draft.guarded.isEmpty { args += ["--guard", draft.guarded.joined(separator: ",")] }
        if draft.format != "default" { args += ["--format", draft.format] }
        let ok = await perform("Setting up the project…", args, in: draft.dir.path)
        if ok { await add(draft.dir) }
        return ok
    }

    /// Adds an environment to a project, in one of its checkouts.
    func addEnv(_ project: String, in checkout: String, name: String, guardLevel: String) async -> Bool {
        return await perform("Adding \(name)…", ["env", "add", name, "--project", project, "--guard", guardLevel], in: checkout, then: project)
    }

    func renameEnv(_ project: String, env: String, to name: String, in checkout: String) async -> Bool {
        await perform("Renaming \(env) to \(name)…", ["env", "rename", env, name, "--dir", checkout, "--yes"], in: checkout, then: project)
    }

    /// Gives an environment a new key and re-encrypts its files.
    func rotate(_ project: String, _ env: EnvView, in checkout: String) async {
        let touch = env.isGuarded ? " — approval may be needed" : ""
        await perform("Rotating \(env.name)\(touch)…", ["env", "rotate", env.name, "--project", project, "--yes"], in: checkout, then: project)
    }

    /// Guard approval follows the credential type and the selected policy.
    func guardEnv(_ project: String, _ env: String, level: String, in checkout: String?) async {
        await perform("Guarding \(env) — approval may be needed…", ["guard", "enable", "--project", project, "--env", env, "--level", level], in: checkout, then: project)
    }

    /// Stops guarding an environment: sealed to the readers' user keys again.
    func unguardEnv(_ project: String, _ env: String, in checkout: String?) async {
        await perform("Unguarding \(env) — approval may be needed…", ["guard", "disable", "--project", project, "--env", env], in: checkout, then: project)
    }

    // MARK: Sharing

    /// Shares environments with GitHub users, groups or keys.
    func share(_ project: String, envs: [String], with who: [String], in checkout: String?) async -> Bool {
        let touch = (details[project] ?? projects.first { $0.project == project })?.envs.contains { envs.contains($0.name) && $0.isGuarded } == true
            ? " — approval may be needed" : ""
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
            message = "CI key \(name) created. Commit esec.toml and .esec/ together."
            lastError = nil
        } catch {
            lastError = error.localizedDescription
        }
        await refresh(full: true)
        await loadDetail(project)
        return key
    }

    // MARK: Seals

    /// Resealing opens existing keys; a guarded key may need approval.
    func sealAgain() async {
        await perform("Resealing keys — approval may be needed…", ["seal", "sync", "--all"])
    }

    /// Remove cached guarded keys without changing session to per-read policy.
    func guardHere(_ guarded: GuardProject) async {
        guard let cli, busy == nil else { return }
        do {
            let project = try await cli.project(guarded.project)
            let names = Set(guarded.clear ?? [])
            let commands = project.envs.filter { names.contains($0.name) && $0.isGuarded }.map {
                ["guard", "enable", "--project", project.project, "--env", $0.name, "--level", $0.guardLevel]
            }
            guard !commands.isEmpty else { await refresh(full: true); return }
            let checkout = project.checkouts.first { $0.status == "ok" }?.path
            await perform("Removing cached guarded keys…", commands: commands, in: checkout, then: project.project)
        } catch { lastError = error.localizedDescription }
    }

    func serviceAction(_ action: String) async {
        await perform("Background service: \(action)…", ["daemon", action] + (action == "install" ? ["--start"] : []))
    }

    func unlock(ttl: String = "4h") async {
        await perform("Opening a broker session…", ["unlock", "--ttl", ttl])
    }

    func lock() async {
        lockSecretWindows()
        await perform("Locking the broker…", ["lock"])
    }

    func scanSecurityKeys() async {
        guard let cli, busy == nil else { return }
        busy = "Scanning connected YubiKeys…"
        defer { busy = nil }
        if let value = await read("Security keys", { try await cli.securityKeys(scan: true) }) { securityKeys = value }
    }

    /// Reseals every guarded environment with the recovery phrase, in Terminal.
    func recoverSeals() { runInTerminal(["seal", "recover", "--all"]) }

    // MARK: Security keys

    func addSecurityKey(name: String?, detected: DetectedKey? = nil) async {
        var args = ["security-keys", "add"]
        if let detected { args += ["--recipient", detected.recipient, "--serial", detected.serial, "--slot", detected.slot] }
        if let name, !name.isEmpty { args += ["--name", name] }
        else if let detected { args += ["--name", detected.name] }
        await perform("Registering the security key…", args)
    }

    func removeSecurityKey(_ id: String) async -> Bool {
        await perform("Removing the security key…", ["security-keys", "remove", id])
    }

    func testSecurityKey(_ id: String) async {
        await perform("Testing security key…", ["security-keys", "test", id])
    }

    func addPasskey(provider: String) async {
        var args = ["security-keys", "passkey", "--provider", provider]
        if let rp = Bundle.main.object(forInfoDictionaryKey: "EsecPasskeyRelyingParty") as? String {
            args += ["--rp-id", rp]
        }
        await perform("Waiting for macOS passkey setup…", args)
    }

    var nativePasskeysAvailable: Bool {
        if #available(macOS 15.0, *) {
            return Bundle.main.object(forInfoDictionaryKey: "EsecPasskeysEnabled") as? Bool == true
        }
        return false
    }

    var securityKeyPasskeysAvailable: Bool {
        if #available(macOS 26.4, *) { return nativePasskeysAvailable }
        return false
    }

    func setUpYubiKey() { runInTerminal(["security-keys", "setup"]) }

    func editConfig(_ path: String) { NSWorkspace.shared.open(URL(fileURLWithPath: path)) }

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
