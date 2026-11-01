import Foundation

/// `daemon status`: service installation and broker sessions are independent.
public struct DaemonStatus: Codable, Hashable, Sendable {
    public let installed: Bool
    public let reachable: Bool
    public let managed: Bool
    public let unlocked: Bool
    public let expires: Date?
    public let version: String?
    public let cliVersion: String?
    public let upToDate: Bool
    public let error: String?

    enum CodingKeys: String, CodingKey {
        case installed, reachable, managed, unlocked, expires, version, error
        case cliVersion = "cli_version"
        case upToDate = "up_to_date"
    }

    public func sessionIsOpen(at now: Date = Date()) -> Bool {
        reachable && unlocked && (expires.map { $0 > now } ?? false)
    }

    public var serviceDescription: String {
        if reachable { return installed ? "Running" : "Running outside the managed service" }
        return installed ? "Stopped or unavailable" : "Not installed"
    }

    public var needsAttention: Bool { !reachable || !upToDate }
}

/// Mirrors esec.toml: dot-separated ASCII lowercase letters and digits.
public enum EnvironmentName {
    public static func isValid(_ name: String) -> Bool {
        !name.isEmpty && name.split(separator: ".", omittingEmptySubsequences: false).allSatisfy {
            !$0.isEmpty && $0.utf8.allSatisfy { (97...122).contains($0) || (48...57).contains($0) }
        }
    }

    public static func parseList(_ text: String) -> [String] {
        text.split(whereSeparator: { $0 == "," || $0.isWhitespace }).map(String.init)
    }

    public static func isValidList(_ names: [String]) -> Bool {
        !names.isEmpty && names.allSatisfy(isValid) && Set(names).count == names.count
    }
}
