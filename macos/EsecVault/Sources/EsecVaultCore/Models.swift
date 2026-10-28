import Foundation

// These mirror the JSON of `esec-vault projects --json`, `projects show
// --json`, `guard --json` and `verify --last --json`. The app reads metadata
// only: names, paths, public keys, guard levels. It never asks for a value.

public struct Checkout: Codable, Hashable, Sendable {
    public let path: String
    /// ok, gone or moved.
    public let status: String
    public let seen: Date?
}

public struct EnvView: Codable, Hashable, Sendable, Identifiable {
    public let name: String
    public let key: String?
    /// none, session or touch.
    public let guardLevel: String
    /// clear (cached here), sealed (opens on first use), guarded (opens
    /// with a touch) or missing (not shared with this person).
    public let here: String
    public let mismatch: Bool?
    /// The command that fixes what is wrong, if anything.
    public let action: String?
    /// Who the key is sealed to, as esec.toml names them.
    public let readers: [String]?
    /// Readers not sealed in yet (no account, or no security key).
    public let pending: [String]?

    public var id: String { name }

    enum CodingKeys: String, CodingKey {
        case name, key, here, mismatch, action, readers, pending
        case guardLevel = "guard"
    }

    /// The readers, parsed.
    public var readerRefs: [ReaderRef] { (readers ?? []).map(ReaderRef.init) }

    public var isGuarded: Bool { guardLevel != "none" }
}

public struct SecretsFile: Codable, Hashable, Sendable, Identifiable {
    public let path: String
    public let format: String
    public let env: String
    public let project: String?
    public let publicKey: String?
    public let keys: [String]?
    public let plain: [String]?

    public var id: String { path }

    enum CodingKeys: String, CodingKey {
        case path, format, env, project, keys, plain
        case publicKey = "public_key"
    }
}

public struct Project: Codable, Hashable, Sendable, Identifiable {
    public let project: String
    public let checkouts: [Checkout]
    public let envs: [EnvView]
    public let keysHere: Bool
    public let files: [SecretsFile]?

    public var id: String { project }

    enum CodingKeys: String, CodingKey {
        case project, checkouts, envs, files
        case keysHere = "keys_here"
    }

    /// The namespace part of the id: "acme" of "acme/store".
    public var namespace: String {
        String(project.split(separator: "/", maxSplits: 1).first ?? Substring(project))
    }

    /// The rest of the id: "store" of "acme/store".
    public var name: String {
        let parts = project.split(separator: "/", maxSplits: 1)
        return parts.count == 2 ? String(parts[1]) : project
    }

    public var hasProblem: Bool {
        envs.contains { $0.mismatch == true || $0.here == "missing" }
            || checkouts.contains { $0.status != "ok" }
    }
}

public struct GuardProject: Codable, Hashable, Sendable {
    public let project: String
    public let envs: [String]
    public let keys: Int
    public let clear: [String]?
}

public struct GuardStatus: Codable, Hashable, Sendable {
    public let setUp: Bool
    public let recipient: String?
    public let holders: [String]
    public let projects: [GuardProject]

    enum CodingKeys: String, CodingKey {
        case recipient, holders, projects
        case setUp = "set_up"
    }
}

public struct KeyUse: Codable, Hashable, Sendable {
    public let project: String
    public let env: String
    public let path: String
    public let commit: String?
}

public struct KeyReport: Codable, Hashable, Sendable, Identifiable {
    public let publicKey: String
    public let uses: [KeyUse]
    public let held: [String: [String]]
    public let places: Int
    public let problems: [String]?
    /// No place checked holds any key of its projects: usually someone
    /// else's project, not a loss.
    public let unheld: Bool?

    public var id: String { publicKey }

    enum CodingKeys: String, CodingKey {
        case uses, held, places, problems, unheld
        case publicKey = "public_key"
    }
}

public struct SourceStatus: Codable, Hashable, Sendable {
    public let name: String
    public let checked: Bool
    public let error: String?
}

public struct VerifyReport: Codable, Hashable, Sendable {
    public let checkouts: Int
    public let files: Int
    public let sources: [SourceStatus]
    public let keys: [KeyReport]
    public let problems: Int
    public let lost: Int
    public let unheld: Int?

    public var ok: Bool { problems == 0 }
}

public struct VerifySaved: Codable, Hashable, Sendable {
    public let at: Date?
    public let report: VerifyReport?
    public let error: String?
    public let drill: Date?
}

public enum Health: Sendable, Equatable {
    case good, attention(String), lost(String), unknown(String)
}

public extension VerifySaved {
    /// The state the menu bar icon shows.
    var health: Health {
        guard let at, at > Date(timeIntervalSince1970: 1) else { return .unknown("Keys never checked") }
        guard let report else { return .unknown(error ?? "No report") }
        if report.lost > 0 { return .lost("\(report.lost) key(s) lost") }
        if !report.ok { return .attention("\(report.problems) key(s) need attention") }
        if Date().timeIntervalSince(at) > 7 * 86_400 { return .attention("Keys last checked over a week ago") }
        return .good
    }
}

public enum JSON {
    public static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .custom { decoder in
            let s = try decoder.singleValueContainer().decode(String.self)
            for f in [ISO8601DateFormatter.Options.withInternetDateTime, [.withInternetDateTime, .withFractionalSeconds]] {
                let fmt = ISO8601DateFormatter()
                fmt.formatOptions = f
                if let date = fmt.date(from: s) { return date }
            }
            // Go's zero time and other non-dates count as "never".
            return Date(timeIntervalSince1970: 0)
        }
        return d
    }()
}

// `esec-vault status --json`.
public struct Status: Codable, Hashable, Sendable {
    public struct Daemon: Codable, Hashable, Sendable {
        public let pid: Int?
        public let unlocked: Bool
        public let version: String?
        public let upToDate: Bool

        enum CodingKeys: String, CodingKey {
            case pid, unlocked, version
            case upToDate = "up_to_date"
        }
    }

    public struct Push: Codable, Hashable, Sendable {
        public let lastPush: Date?

        enum CodingKeys: String, CodingKey { case lastPush = "last_push" }
    }

    public struct Destinations: Codable, Hashable, Sendable {
        public let remote: [String: Push]?
    }

    public struct Server: Codable, Hashable, Sendable {
        public let server: String
        public let login: String?
    }

    public let daemon: Daemon?
    public let identity: String?
    public let recoverable: Bool
    public let pushPending: Bool
    public let destinations: Destinations?
    public let vaultServer: Server?
    public let problems: [String]?

    enum CodingKeys: String, CodingKey {
        case daemon, identity, recoverable, destinations, problems
        case pushPending = "push_pending"
        case vaultServer = "vault_server"
    }
}

// One line of `esec-vault activity --json`: a request for keys.
public struct ActivityEntry: Codable, Hashable, Sendable, Identifiable {
    public let ts: Date
    public let pid: Int?
    public let op: String
    public let project: String?
    public let env: String?
    /// allow, ask or deny.
    public let decision: String
    public let detail: String?
    /// The asking program and its parents: "zsh ▸ claude ▸ esec-vault".
    public let caller: String?
    /// The agent session label (ESEC_VAULT_SESSION).
    public let session: String?

    public var id: String { "\(ts.timeIntervalSince1970)-\(pid ?? 0)-\(op)-\(project ?? "")-\(env ?? "")-\(decision)" }

    /// The program that asked, without its parents: "esec-vault" of
    /// "zsh ▸ claude ▸ esec-vault", or the agent if one is in the chain.
    public var agent: String? {
        let chain = (caller ?? "").components(separatedBy: " ▸ ")
        let agents = ["claude", "codex", "cursor", "aider", "gemini", "goose", "opencode", "amp"]
        return chain.first { name in agents.contains { name.lowercased().hasPrefix($0) } }
    }
}

/// One step of `esec-vault setup --check --json`: what is set up on this
/// Mac and what is left, with the command that does it.
public struct SetupItem: Codable, Hashable, Sendable, Identifiable {
    public enum State: Sendable { case done, todo, warning, skipped }

    public let step: String
    /// ok, done, todo, skipped or failed.
    public let status: String
    public let detail: String
    public let command: String?

    public var id: String { step }

    public init(step: String, status: String, detail: String, command: String?) {
        self.step = step
        self.status = status
        self.detail = detail
        self.command = command
    }

    public var title: String { step.prefix(1).uppercased() + step.dropFirst() }

    public var state: State {
        switch status {
        case "ok", "done": .done
        case "failed": .warning
        case "skipped": .skipped
        default: .todo
        }
    }

    /// The esec-vault arguments of command, when it is one command to run
    /// as it is (no placeholder such as SERVER, no alternatives).
    public var args: [String]? {
        guard let c = command, c.hasPrefix("esec vault ") else { return nil }
        let rest = c.dropFirst("esec vault ".count)
        if rest.contains("(") || rest.contains(" or ") || rest.contains(",")
            || rest.split(separator: " ").contains(where: { $0.count > 1 && $0 == $0.uppercased() && $0.first!.isLetter }) {
            return nil
        }
        return rest.split(separator: " ").map(String.init)
    }

    /// Whether running it asks for a phrase, a PIN or a touch, so it opens
    /// Terminal; the rest run in the app.
    public var interactive: Bool {
        guard let first = args?.first else { return true }
        return !["daemon", "projects", "verify", "sync"].contains(first)
    }
}

// MARK: - Sealed keys

/// A reader of an environment, parsed from esec.toml's readers: a person by
/// GitHub id ("mads (gh:583231)"), a group ("group acme/backend"), a key
/// ("deploy (age1…)"), or "me" before signing in. The login is for display;
/// the numeric id is what counts.
public struct ReaderRef: Hashable, Sendable, Identifiable {
    public enum Kind: Hashable, Sendable {
        case person(id: Int64, login: String)
        case group(String)
        case key(name: String, recipient: String)
        case me
        case other
    }

    public let raw: String
    public let kind: Kind

    public var id: String { raw }

    public init(_ raw: String) {
        self.raw = raw
        let s = raw.trimmingCharacters(in: .whitespaces)
        if s == "me" {
            kind = .me
        } else if s.hasPrefix("group ") {
            kind = .group(String(s.dropFirst(6)))
        } else if s.hasSuffix(")"), let open = s.range(of: " (", options: .backwards) {
            let label = String(s[..<open.lowerBound])
            let inner = String(s[open.upperBound...].dropLast())
            if inner.hasPrefix("gh:"), let id = Int64(inner.dropFirst(3)), id > 0 {
                kind = .person(id: id, login: label)
            } else {
                kind = .key(name: label, recipient: inner)
            }
        } else if s.hasPrefix("age1") || s.hasPrefix("ssh-") {
            kind = .key(name: "", recipient: s)
        } else {
            kind = .other
        }
    }

    /// What people see.
    public var display: String {
        switch kind {
        case let .person(_, login): login.isEmpty ? raw : login
        case let .group(g): g
        case let .key(name, recipient): name.isEmpty ? String(recipient.prefix(16)) + "…" : name
        case .me: "you"
        case .other: raw
        }
    }

    /// The name to unshare with: a login, a key's name, or the group entry.
    public var unshareName: String {
        switch kind {
        case let .person(_, login): login
        case let .key(name, recipient): name.isEmpty ? recipient : name
        case .group: raw
        default: raw
        }
    }

    /// A person's GitHub avatar, by numeric id, never by login.
    public var avatarURL: URL? {
        guard case let .person(id, _) = kind else { return nil }
        return URL(string: "https://avatars.githubusercontent.com/u/\(id)?s=64")
    }

    public var isPerson: Bool {
        switch kind {
        case .person, .me: true
        default: false
        }
    }
}

/// One environment's seal, from `esec-vault seal --all --json`.
public struct SealView: Codable, Hashable, Sendable, Identifiable {
    public struct Reader: Codable, Hashable, Sendable {
        public let reader: String
        public let display: String
        public let keys: Int
        public let pending: String?

        public var ref: ReaderRef { ReaderRef(reader) }
    }

    public struct Problem: Codable, Hashable, Sendable {
        public let env: String
        /// fail or warn.
        public let level: String
        public let detail: String
        public let fix: String?
    }

    public let project: String
    public let root: String
    public let env: String
    public let guardLevel: String
    public let sealed: Bool
    public let readers: [Reader]
    /// Why it should be sealed again.
    public let stale: [String]?
    public let problems: [Problem]?

    public var id: String { project + " " + env }

    enum CodingKeys: String, CodingKey {
        case project, root, env, sealed, readers, stale, problems
        case guardLevel = "guard"
    }

    public var isGuarded: Bool { guardLevel != "none" }
    public var failures: [Problem] { (problems ?? []).filter { $0.level == "fail" } }
    /// Reasons it should be sealed again that this machine could check.
    public var resealReasons: [String] { (stale ?? []).filter { !$0.hasPrefix("could not check") } }
    public var needsAttention: Bool { !sealed || !resealReasons.isEmpty || !failures.isEmpty }
}

/// `esec-vault security-keys list --json`.
public struct SecurityKeyList: Codable, Hashable, Sendable {
    public let source: String
    public let keys: [SecurityKey]
    public let unregistered: [DetectedKey]
    public let unprovisioned: [String]
    /// Why plugged-in keys could not be listed.
    public let detect: String?
}

/// A registered security key.
public struct SecurityKey: Codable, Hashable, Sendable, Identifiable {
    public let id: String
    /// yubikey or se.
    public let kind: String
    public let name: String
    public let serial: String?
    public let recipient: String
    public let pluggedIn: Bool
    public let tested: Date?

    enum CodingKeys: String, CodingKey {
        case id, kind, name, serial, recipient, tested
        case pluggedIn = "plugged_in"
    }
}

/// A plugged-in YubiKey with an age identity that is not registered.
public struct DetectedKey: Codable, Hashable, Sendable, Identifiable {
    public let serial: String
    public let slot: String
    public let name: String
    public let recipient: String
    public let pinPolicy: String?
    public let touchPolicy: String?
    public let command: String

    public var id: String { recipient }

    enum CodingKeys: String, CodingKey {
        case serial, slot, name, recipient, command
        case pinPolicy = "pin_policy"
        case touchPolicy = "touch_policy"
    }

    /// Whether every decryption needs a touch.
    public var touchAlways: Bool { (touchPolicy ?? "always").lowercased().hasPrefix("always") }
}
