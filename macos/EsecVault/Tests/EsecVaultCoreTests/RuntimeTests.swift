import EsecVaultCore
import Foundation
import Testing

@Test func environmentNamesMatchProjectFile() {
    for name in ["dev", "api.prod", "service2.eu1.prod", "9"] { #expect(EnvironmentName.isValid(name)) }
    for name in ["", ".prod", "prod.", "api..prod", "prod-us", "prod_us", "Prod", "prød", "dev/prod", "dev prod"] {
        #expect(!EnvironmentName.isValid(name))
    }
    #expect(EnvironmentName.parseList("dev, api.prod\nworker.prod") == ["dev", "api.prod", "worker.prod"])
    #expect(!EnvironmentName.isValidList(["dev", "dev"]))
    #expect(!EnvironmentName.isValidList([]))
}

@Test func daemonSessionEndsAtExpiryAndWhenServiceStops() throws {
    let raw = #"{"installed":true,"reachable":true,"managed":true,"unlocked":true,"expires":"2026-10-29T16:00:00Z","version":"v2","cli_version":"v2","up_to_date":true}"#
    let daemon = try JSON.decoder.decode(DaemonStatus.self, from: Data(raw.utf8))
    let expiry = try #require(daemon.expires)
    #expect(daemon.sessionIsOpen(at: expiry.addingTimeInterval(-1)))
    #expect(!daemon.sessionIsOpen(at: expiry))
    #expect(!daemon.sessionIsOpen(at: expiry.addingTimeInterval(1)))
    #expect(!daemon.needsAttention)
    let stopped = try JSON.decoder.decode(DaemonStatus.self, from: Data(raw.replacingOccurrences(of: #""reachable":true"#, with: #""reachable":false"#).utf8))
    #expect(stopped.installed && stopped.upToDate && stopped.needsAttention)
    #expect(!stopped.sessionIsOpen(at: expiry.addingTimeInterval(-1)))
    #expect(stopped.serviceDescription == "Stopped or unavailable")
}

@Test func uncheckedAndPendingSealsNeedAttention() throws {
    let raw = #"{"project":"acme/store","root":"/src/store","env":"api.prod","guard":"session","sealed":true,"readers":[{"reader":"alice (gh:2)","display":"alice","keys":0,"pending":"no passkey"}],"stale_error":"server unavailable"}"#
    let seal = try JSON.decoder.decode(SealView.self, from: Data(raw.utf8))
    #expect(seal.needsAttention && seal.failures.isEmpty && seal.resealReasons.isEmpty)
    #expect(seal.uncheckedReasons.count == 1 && seal.pendingReaders.count == 1)
}

@Test func projectConfigurationAndInvalidCheckoutDecode() throws {
    let raw = #"{"project":"acme/mono/api","checkouts":[{"path":"/src/api","status":"invalid","error":"invalid esec.toml"}],"envs":[],"keys_here":false,"config":{"path":"/src/api/esec.toml","format":"etoml","name":"secrets/{env}.etoml","unknown":["env.prod.gaurd"]}}"#
    let project = try JSON.decoder.decode(Project.self, from: Data(raw.utf8))
    #expect(project.hasProblem && project.config?.name == "secrets/{env}.etoml")
    #expect(project.checkouts[0].error == "invalid esec.toml")
}
