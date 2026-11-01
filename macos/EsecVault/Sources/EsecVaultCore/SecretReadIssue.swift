import Foundation

/// Read failures must explain whether unlocking can actually resolve them.
public struct SecretReadIssue: Equatable, Sendable {
    public enum Kind: Sendable { case policy, locked, service, other }
    public let kind: Kind
    public let message: String

    public init(_ message: String) {
        self.message = message
        let text = message.lowercased()
        if text.contains("denied by policy") { kind = .policy }
        else if text.contains("vault is locked") { kind = .locked }
        else if text.contains("broker not reachable") || text.contains("background service needs updating") { kind = .service }
        else { kind = .other }
    }

    public var title: String {
        switch kind {
        case .policy: "Blocked by read policy"
        case .locked: "Broker session is locked"
        case .service: "Background service needs attention"
        case .other: "Could not decrypt this file"
        }
    }
    public var guidance: String {
        switch kind {
        case .policy: "An explicit broker policy denies this guarded read. Review the matching rule in policy.toml, then reload the policy. Unlocking alone will not resolve a policy denial. Unguarded local files need no broker rule."
        case .locked: "Unlock the broker session to read this file. Guarded environments still require their normal approval."
        case .service: "Open Overview to start or update the background service, then try again."
        case .other: "Check the error below and try again."
        }
    }
}
