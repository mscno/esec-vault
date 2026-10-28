import EsecVaultCore
import Foundation
import Testing

@Test func decodesProjects() throws {
    let json = """
    [{"project":"acme/store","checkouts":[{"path":"/Users/me/src/store","status":"ok","seen":"2026-10-28T10:00:00Z"}],
      "envs":[{"name":"dev","key":"a1b2","guard":"none","here":"clear"},{"name":"prod","key":"c3d4","guard":"touch","here":"guarded","mismatch":true}],
      "keys_here":true}]
    """
    let projects = try JSON.decoder.decode([Project].self, from: Data(json.utf8))
    #expect(projects.count == 1)
    let p = projects[0]
    #expect(p.namespace == "acme" && p.name == "store")
    #expect(p.envs[1].isGuarded && p.envs[1].guardLevel == "touch")
    #expect(p.hasProblem)
}

@Test func decodesVerifyAndHealth() throws {
    let json = """
    {"at":"2026-10-28T10:00:00.123456Z","report":{"checkouts":2,"files":4,
      "sources":[{"name":"this device","checked":true},{"name":"vault server","checked":false,"error":"not signed in"}],
      "keys":[{"public_key":"abcd","uses":[{"project":"acme/a","env":"prod","path":"/x/.env.prod"}],"held":{"this device":["acme/a"]},"places":1,"problems":["in one place only"]}],
      "problems":1,"lost":0},"drill":"0001-01-01T00:00:00Z"}
    """
    let saved = try JSON.decoder.decode(VerifySaved.self, from: Data(json.utf8))
    #expect(saved.report?.keys.first?.places == 1)
    if case .attention = saved.health {} else { Issue.record("health \(saved.health)") }
    #expect((saved.drill?.timeIntervalSince1970 ?? 0) < 1)

    let never = try JSON.decoder.decode(VerifySaved.self, from: Data(#"{"at":"0001-01-01T00:00:00Z"}"#.utf8))
    if case .unknown = never.health {} else { Issue.record("never checked: \(never.health)") }
}

@Test func decodesGuard() throws {
    let json = #"{"set_up":true,"recipient":"age1x","holders":["age1yubikey1q","age1rec"],"projects":[{"project":"acme/a","envs":["prod"],"keys":2,"clear":["abcd"]}]}"#
    let g = try JSON.decoder.decode(GuardStatus.self, from: Data(json.utf8))
    #expect(g.setUp && g.holders.count == 2 && g.projects[0].clear == ["abcd"])
}
