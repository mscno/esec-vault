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

    public var id: String { name }

    enum CodingKeys: String, CodingKey {
        case name, key, here, mismatch
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

    public var id: String { publicKey }

    enum CodingKeys: String, CodingKey {
        case uses, held, places, problems
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
