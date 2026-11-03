import Darwin
import EsecVaultCore
import Foundation
import Testing

private func helperFixture(_ body: String) throws -> (CLI, URL) {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("esec-helper-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let executable = dir.appendingPathComponent("helper")
    try ("#!/bin/sh\n" + body).write(to: executable, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
    return (CLI(binary: executable), dir)
}

@MainActor private func eventually(_ predicate: () -> Bool) async throws {
    for _ in 0..<300 {
        if predicate() { return }
        try await Task.sleep(for: .milliseconds(30))
    }
    #expect(predicate())
}

@Test @MainActor func helperFollowsParentPipeAndRestartsAfterCrash() async throws {
    // exec keeps the fixture PID stable; cat exits only after all inherited
    // writers close. This tests the actual Foundation Process/pipe wiring.
    let (cli, dir) = try helperFixture("exec /bin/cat\n")
    defer { try? FileManager.default.removeItem(at: dir) }
    let helper = AppHelper()
    defer { helper.stop() }
    helper.start(cli: cli, environment: [:])
    try await eventually { helper.pid != nil }
    let first = try #require(helper.pid)
    #expect(kill(first, SIGKILL) == 0)
    try await eventually { helper.pid != nil && helper.pid != first }
    let second = try #require(helper.pid)
    // Another child of the same app must not inherit the lifetime writer.
    let unrelated = Task { try await CLI(binary: URL(fileURLWithPath: "/bin/sleep")).run(["3"]) }
    try await Task.sleep(for: .milliseconds(100))
    let stoppedAt = Date()
    helper.stop()
    try await eventually { helper.pid == nil }
    #expect(kill(second, 0) == -1 && errno == ESRCH)
    #expect(Date().timeIntervalSince(stoppedAt) < 2)
    #expect(helper.state == "Stopped")
    _ = try await unrelated.value
    try await Task.sleep(for: .milliseconds(200))
    #expect(helper.pid == nil) // stop must cancel retries as well as the child
}

@Test @MainActor func helperFailureIsBoundedAndOutputIsDrained() async throws {
    let (cli, dir) = try helperFixture("head -c 131072 /dev/zero >&2\necho 'synthetic migration refused' >&2\nexit 12\n")
    defer { try? FileManager.default.removeItem(at: dir) }
    let helper = AppHelper()
    defer { helper.stop() }
    helper.start(cli: cli, environment: [:])
    try await eventually { helper.state == "Local helper could not start" }
    #expect(helper.pid == nil)
    #expect(helper.error?.contains("synthetic migration refused") == true)
    #expect((helper.error?.utf8.count ?? 0) <= 8192)
}

@Test @MainActor func customSocketNeverStartsOrMigratesHelper() throws {
    let helper = AppHelper()
    helper.start(cli: CLI(binary: URL(fileURLWithPath: "/nonexistent")), environment: ["ESEC_VAULT_SOCK": "/tmp/custom.sock"])
    #expect(helper.customSocket)
    #expect(helper.pid == nil)
    #expect(helper.error == nil)
}

@Test func appOwnedStatusDoesNotSuggestDaemonInstallation() throws {
    let raw = #"{"installed":true,"reachable":true,"managed":true,"unlocked":false,"up_to_date":true,"owner":"app","app_managed":true,"pid":123}"#
    let running = try JSON.decoder.decode(DaemonStatus.self, from: Data(raw.utf8))
    #expect(running.serviceDescription == "Running in EsecVault")
    #expect(!running.needsAttention)
    let stopped = try JSON.decoder.decode(DaemonStatus.self, from: Data(raw.replacingOccurrences(of: #""reachable":true"#, with: #""reachable":false"#).utf8))
    #expect(stopped.serviceDescription == "Open EsecVault to start the helper")
}
