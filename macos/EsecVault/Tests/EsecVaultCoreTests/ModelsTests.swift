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

@Test func decodesStatusAndActivity() throws {
    let status = try JSON.decoder.decode(Status.self, from: Data(#"""
    {"daemon":{"ok":true,"pid":7,"unlocked":true,"version":"v1","up_to_date":false},"identity":"3e8c","recoverable":true,
     "push_pending":false,"destinations":{"last_push":"2026-10-28T08:00:00Z","remote":{"usb":{"last_push":"2026-10-28T08:00:00Z"}}},"problems":["x"]}
    """#.utf8))
    #expect(status.daemon?.upToDate == false && status.destinations?.remote?["usb"] != nil)

    let entries = try JSON.decoder.decode([ActivityEntry].self, from: Data(#"""
    [{"ts":"2026-10-28T08:00:48Z","uid":501,"pid":42,"op":"get","project":"acme/shop","env":"prod","decision":"allow","detail":"guard","caller":"zsh ▸ claude ▸ esec-vault","session":"claude-7"}]
    """#.utf8))
    #expect(entries[0].agent == "claude" && entries[0].env == "prod")
}

@Test func setupChecklist() throws {
    let items = try JSON.decoder.decode([SetupItem].self, from: Data(#"""
    [{"step":"identity","status":"ok","detail":"fingerprint 3e8c…"},
     {"step":"background service","status":"todo","detail":"…","command":"esec vault daemon install --start"},
     {"step":"identity2","status":"todo","detail":"none","command":"esec vault login SERVER (joining your account), or esec vault init"},
     {"step":"guard","status":"failed","detail":"x","command":"esec vault guard enable --project acme/store"}]
    """#.utf8))
    #expect(items[0].state == .done && items[0].args == nil)
    #expect(items[1].args == ["daemon", "install", "--start"] && !items[1].interactive)
    #expect(items[2].args == nil && items[2].interactive)
    #expect(items[3].state == .warning && items[3].args == ["guard", "enable", "--project", "acme/store"] && items[3].interactive)
}

@Test func quotesShellArguments() {
    let cli = CLI(binary: URL(fileURLWithPath: "/usr/local/bin/esec-vault"))
    #expect(cli.commandLine(["guard", "enable", "--project", "acme/store"]) == "/usr/local/bin/esec-vault guard enable --project acme/store")
    #expect(cli.commandLine(["x", "it's here"]) == #"/usr/local/bin/esec-vault x 'it'\''s here'"#)
}
