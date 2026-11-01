@testable import EsecVaultUI
import EsecVaultCore
import Foundation
import Testing

@Test func environmentColumnsUseDeploymentOrder() {
    #expect(SecretEnvironmentOrder.sorted(["qa", "production", "dev", "staging", "test", "development", "prod", "alpha"]) ==
            ["dev", "development", "staging", "prod", "production", "alpha", "qa", "test"])
    #expect(SecretEnvironmentOrder.sorted(["zeta", "api.prod", "api.dev", "api.staging", "alpha"]) ==
            ["api.dev", "api.staging", "api.prod", "alpha", "zeta"])
}

@MainActor
private func comparisonFixture() throws -> (SecretComparisonStore, URL) {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("esec-compare-test-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    var files: [SecretsFile] = []
    let specs: [(String, String, [String: String])] = [
        (".env.prod", "prod", ["API_KEY": "production-only", "PROD_ONLY": "present"]),
        (".env.dev", "dev", ["API_KEY": "development-only", "DEV_ONLY": "present"]),
        ("second.env.dev", "dev", ["API_KEY": "second-development-value"]),
        (".env.staging", "staging", ["API_KEY": "not-returned", "STAGING_ONLY": "not-returned"])
    ]
    for (name, env, values) in specs {
        let path = dir.appendingPathComponent(name).path
        let file: [String: Any] = ["path": path, "env": env, "format": ".env", "project": "demo/app", "keys": Array(values.keys)]
        files.append(try JSON.decoder.decode(SecretsFile.self, from: JSONSerialization.data(withJSONObject: file)))
        let document: [String: Any] = ["file": file, "revision": "test", "values": values.map { ["key": $0.key, "value": $0.value, "editable": true] as [String: Any] }]
        try JSONSerialization.data(withJSONObject: document).write(to: URL(fileURLWithPath: path + ".json"))
    }
    let script = """
    #!/bin/sh
    case "$4" in
      *.env.staging) echo 'approval denied' >&2; exit 1 ;;
      *) cat "$4.json" ;;
    esac
    """
    let executable = dir.appendingPathComponent("esec-vault")
    try script.write(to: executable, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
    // Duplicate discovery must not produce a duplicate read or hide another file.
    let model = SecretComparisonStore(project: "demo/app", files: files + [files[0]], cli: CLI(binary: executable))
    return (model, dir)
}

@Test @MainActor func comparisonPreservesSourcesMissingKeysAndFailures() async throws {
    let (model, dir) = try comparisonFixture()
    defer { try? FileManager.default.removeItem(at: dir) }
    await model.load()
    #expect(model.files.count == 4)
    #expect(model.columns.map(\.env) == ["dev", "staging", "prod"])
    #expect(Set(model.keys) == ["API_KEY", "DEV_ONLY", "PROD_ONLY", "STAGING_ONLY"])
    #expect(model.allRevealed)
    let dev = try #require(model.columns.first)
    #expect(model.values(for: "API_KEY", in: dev).count == 2)
    #expect(model.values(for: "PROD_ONLY", in: dev).isEmpty)
    #expect(model.hasDifferentValues("API_KEY"))
    #expect(model.incomplete(model.columns[1]))
    #expect(model.errors.count == 1)
    #expect(model.readIssues.count == 1)
    #expect(!model.needsUnlock)
    model.hideAll()
    #expect(model.revealed.isEmpty)
    model.toggleAll()
    #expect(model.allRevealed)
    model.search = "production-only"
    #expect(model.keys.isEmpty) // key-name filtering never searches values
    model.lock()
    #expect(model.documents.isEmpty)
    #expect(model.revealed.isEmpty)
}

@Test @MainActor func comparisonDoesNotOfferUnlockForPolicyDenials() async throws {
    let (model, dir) = try comparisonFixture()
    defer { try? FileManager.default.removeItem(at: dir) }
    model.errors[model.files[0].path] = "denied by policy: demo/app env dev"
    #expect(!model.needsUnlock)
    #expect(model.readIssues.first?.kind == .policy)
    model.errors[model.files[0].path] = "vault is locked; run esec vault unlock"
    #expect(model.needsUnlock)
}
