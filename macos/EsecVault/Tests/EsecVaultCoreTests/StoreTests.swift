@testable import EsecVault
import EsecVaultCore
import Foundation
import Testing

@MainActor
private func fixtureCLI(failSeals: Bool = false) throws -> (CLI, URL) {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("esec-gui-test-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let log = dir.appendingPathComponent("commands")
    let project = #"{"project":"acme/store","keys_here":true,"checkouts":[{"path":"CHECKOUT","status":"ok"}],"envs":[{"name":"prod","guard":"session","here":"guarded"},{"name":"api.prod","guard":"touch","here":"guarded"}]}"#
        .replacingOccurrences(of: "CHECKOUT", with: dir.path)
    let script = """
    #!/bin/sh
    printf '%s\\n' "$*" >> \(CLI.quote(log.path))
    case "$1 $2" in
      'projects show') printf '%s' '\(project)' ;;
      'projects --json') printf '%s' '[\(project)]' ;;
      'guard --json') printf '%s' '{"set_up":true,"holders":[],"projects":[]}' ;;
      'guard enable') exit 0 ;;
      'daemon status') printf '%s' '{"installed":true,"reachable":true,"managed":true,"unlocked":false,"up_to_date":true}' ;;
      'verify --last') printf '%s' '{}' ;;
      'activity --json') printf '%s' '[]' ;;
      'security-keys list') printf '%s' '{"source":"local","keys":[],"unregistered":[],"unprovisioned":[],"cached":true}' ;;
      'status --json') printf '%s' '{"recoverable":true,"push_pending":false}' ;;
      'setup --check') printf '%s' '[]' ;;
      'seal --all') \(failSeals ? "echo 'server unavailable' >&2; exit 1" : "printf '%s' '[]'") ;;
      *) echo 'unexpected fixture command' >&2; exit 1 ;;
    esac
    """
    let executable = dir.appendingPathComponent("esec-vault")
    try script.write(to: executable, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
    return (CLI(binary: executable), log)
}

@Test @MainActor func guardHerePreservesEachEnvironmentPolicy() async throws {
    let (cli, log) = try fixtureCLI()
    defer { try? FileManager.default.removeItem(at: log.deletingLastPathComponent()) }
    let store = Store()
    store.cli = cli
    let guarded = try JSON.decoder.decode(GuardProject.self, from: Data(#"{"project":"acme/store","envs":["prod","api.prod"],"keys":2,"clear":["prod","api.prod"]}"#.utf8))
    await store.guardHere(guarded)
    #expect(store.lastError == nil)
    let commands = try String(contentsOf: log, encoding: .utf8)
    #expect(commands.contains("guard enable --project acme/store --env prod --level session"))
    #expect(commands.contains("guard enable --project acme/store --env api.prod --level touch"))
    #expect(!commands.contains("--env prod --level touch"))
    #expect(commands.contains("security-keys list --json --cached"))
}

@Test @MainActor func failedSealReadIsVisibleWithoutDiscardingOtherStatus() async throws {
    let (cli, log) = try fixtureCLI(failSeals: true)
    defer { try? FileManager.default.removeItem(at: log.deletingLastPathComponent()) }
    let store = Store()
    store.cli = cli
    await store.refresh(full: true)
    #expect(store.projects.count == 1)
    #expect(store.daemonState?.reachable == true)
    #expect(store.refreshErrors["Seals"]?.contains("server unavailable") == true)
    #expect(store.refreshErrors["Projects"] == nil)
    if case .attention = store.health {} else { Issue.record("Failed seal check must not appear healthy") }
}
