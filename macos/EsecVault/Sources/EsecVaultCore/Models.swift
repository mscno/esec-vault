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
    /// guarded, clear or missing: the key on this device.
    public let here: String
    public let mismatch: Bool?
    /// The command that fixes what is wrong, if anything.
    public let action: String?

    public var id: String { name }

    enum CodingKeys: String, CodingKey {
        case name, key, here, mismatch, action
        case guardLevel = "guard"
    }

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
