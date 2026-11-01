import Foundation
import Testing
@testable import EsecVaultCore

@Test func vaultInventoryDistinguishesOfflineCacheFromServerStorage() throws {
    let data = Data(#"{"projects":[{"project":"acme/api","keys":2,"cache":"none","cached":false,"revisions":3,"checkouts":["origin"],"history":[{"id":"revision","checkout":"origin","label":"Laptop / api","at":"2026-11-01T10:00:00Z","sequence":2,"files":3}]}],"profiles":[{"id":"device","name":"Laptop","files":["policy.toml"]}],"pending":true,"generation":9,"offline":true,"staging_failed":true}"#.utf8)
    let inventory = try JSON.decoder.decode(VaultStorage.self, from: data)
    #expect(inventory.offline && inventory.pending && inventory.stagingFailed)
    #expect(inventory.projects[0].keys == 2)
    #expect(!inventory.projects[0].cached)
    #expect(inventory.projects[0].history[0].sequence == 2)
    #expect(inventory.profiles[0].files == ["policy.toml"])
}
