import EsecVaultCore
import Foundation
import Testing

// Samples captured from esec-vault (seal --all --json, security-keys list
// --json, projects --json).

@Test func decodesSeals() throws {
    let json = #"""
    [{"project":"acme/store","root":"/src/store","env":"dev","guard":"none","sealed":true,
      "readers":[{"reader":"me","display":"me","keys":1},
                 {"reader":"laptop (age1uy5tutml0akptlqdxs6yzkmvtyrr04vuxz7sy5s4f7udrtj8puxqd59sdy)","display":"laptop (a key)","keys":1}],
      "stale":["could not check: sign in to a vault server to seal for alice"],
      "problems":[{"env":"dev","level":"fail","detail":"esec.toml's readers are not the ones it is sealed to","fix":"esec vault seal sync"}]},
     {"project":"acme/store","root":"/src/store","env":"prod","guard":"touch","sealed":true,
      "readers":[{"reader":"alice (gh:2002)","display":"alice","keys":0,"pending":"has no security key yet: sealed in once they add one (esec vault security-keys add)"}],
      "stale":["alice's keys changed"]}]
    """#
    let seals = try JSON.decoder.decode([SealView].self, from: Data(json.utf8))
    #expect(seals.count == 2)
    #expect(seals[0].failures.count == 1 && seals[0].resealReasons.isEmpty && seals[0].needsAttention)
    #expect(seals[1].isGuarded && seals[1].resealReasons == ["alice's keys changed"])
    #expect(seals[1].readers[0].pending?.contains("security key") == true)
    if case let .person(id, login) = seals[1].readers[0].ref.kind {
        #expect(id == 2002 && login == "alice")
    } else {
        Issue.record("alice is not a person: \(seals[1].readers[0].ref.kind)")
    }
}

@Test func parsesReaders() {
    let alice = ReaderRef("alice (gh:2002)")
    #expect(alice.avatarURL?.absoluteString == "https://avatars.githubusercontent.com/u/2002?s=64")
    #expect(alice.display == "alice" && alice.unshareName == "alice" && alice.isPerson)
    let deploy = ReaderRef("deploy (age1pkdakc2keejvckjm6sxvtmzt8entwwel5ewgufuhf6r5vr62tchs5rvmxp)")
    #expect(deploy.display == "deploy" && deploy.avatarURL == nil && !deploy.isPerson)
    #expect(ReaderRef("group acme/backend").kind == .group("acme/backend"))
    #expect(ReaderRef("me").kind == .me && ReaderRef("me").display == "you")
    // A login is never the id: "gh:" must be numeric.
    if case .person = ReaderRef("eve (gh:eve)").kind { Issue.record("a non-numeric id was taken for a person") }
}

@Test func decodesSecurityKeys() throws {
    let json = #"""
    {"source":"local","keys":[{"id":"yubikey:15584441:1","kind":"yubikey","name":"blue keychain","serial":"15584441",
      "recipient":"age1yubikey1qvt52reygts58f5fwksk34g7g60ac7fqdzcwn6ke677q6gr6xrx5un7zvjk","plugged_in":false,"tested":"2026-10-28T10:00:00Z"}],
     "unregistered":[{"serial":"22334455","slot":"1","name":"age identity 1a2b3c4d","recipient":"age1yubikey1qfukrvw4udjxjert8xyx0rfqhegql6n4xxkda70c8d9r9vagz2pq69dvers",
      "pin_policy":"Once","touch_policy":"Cached","command":"esec vault security-keys add"}],
     "unprovisioned":["33445566"]}
    """#
    let list = try JSON.decoder.decode(SecurityKeyList.self, from: Data(json.utf8))
    #expect(list.keys[0].name == "blue keychain" && !list.keys[0].pluggedIn && list.keys[0].tested != nil)
    #expect(list.unregistered[0].slot == "1" && !list.unregistered[0].touchAlways)
    #expect(list.unprovisioned == ["33445566"] && list.detect == nil)
}

@Test func decodesProjectReaders() throws {
    let json = #"""
    [{"project":"acme/store","checkouts":[{"path":"/src/store","status":"ok","seen":"2026-10-28T10:34:58Z"}],
      "envs":[{"name":"prod","key":"23c3","guard":"touch","here":"guarded",
               "readers":["me","deploy (age1pkdakc2keejvckjm6sxvtmzt8entwwel5ewgufuhf6r5vr62tchs5rvmxp)"],"pending":["alice (gh:2002)"]}],
      "keys_here":true}]
    """#
    let p = try JSON.decoder.decode([Project].self, from: Data(json.utf8))[0]
    #expect(p.envs[0].readerRefs.count == 2 && p.envs[0].pending == ["alice (gh:2002)"])
}
