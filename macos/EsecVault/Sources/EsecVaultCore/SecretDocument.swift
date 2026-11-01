import Foundation

public struct SecretValue: Codable, Identifiable, Sendable, Equatable {
    public let key: String
    public var value: String
    public let editable: Bool
    public var id: String { key }

    public init(key: String, value: String, editable: Bool) {
        self.key = key
        self.value = value
        self.editable = editable
    }
}

/// Never persisted: only the selected file's window owns these values.
public struct SecretDocument: Decodable, Sendable {
    public let file: SecretsFile
    public var revision: String
    public var values: [SecretValue]
    public let decryption: SecretDecryption?

    public var canAdd: Bool { [".env", ".eyaml", ".eyml"].contains(file.format) }
}

/// Metadata from the successful read, never inferred from key availability.
public struct SecretDecryption: Decodable, Sendable, Equatable {
    public let source: String
    public let guardLevel: String

    enum CodingKeys: String, CodingKey {
        case source
        case guardLevel = "guard"
    }

    public var title: String {
        switch source {
        case "local_key": "Local key"
        case "sealed_identity": "Sealed key"
        case "broker": "Broker"
        case "forwarded_broker": "Forwarded broker"
        case "workload_key": "Workload key"
        case "workload_identity": "Workload identity"
        default: "Route unavailable"
        }
    }

    public var symbol: String {
        switch source {
        case "local_key", "workload_key": "key"
        case "sealed_identity", "workload_identity": "envelope"
        case "broker": "lock.shield"
        case "forwarded_broker": "network"
        default: "info.circle"
        }
    }

    public var explanation: String {
        let route: String
        switch source {
        case "local_key":
            route = "A local keyring or process credential decrypted this file on this Mac. The broker was not used."
        case "sealed_identity":
            route = "An age identity on this Mac opened the project's sealed key and decrypted the file locally. The broker was not used."
        case "workload_key":
            route = "An explicit process key for this file's public key decrypted the file locally, without the broker."
        case "workload_identity":
            route = "An explicitly configured age identity opened the sealed key and decrypted the file locally, without the broker."
        case "broker":
            route = "The local broker service decrypted this file under its access policy." + protection
        case "forwarded_broker":
            route = "The broker on the connected machine decrypted this file through the configured forwarding connection, under that broker's access policy." + protection
        default:
            return "This read did not report a supported decryption route. Update the app and its CLI to see this information."
        }
        return "Last successful decryption: " + route + "\nValues were opened in memory; the file stayed encrypted."
    }

    private var protection: String {
        switch guardLevel {
        case "session": " Session protection is configured; an existing unlocked session may be reused."
        case "touch": " The environment is configured to require approval for each read."
        case "none": " The environment has no hardware guard; broker policy still applies."
        default: ""
        }
    }
}

extension CLI {
    public func secretDocument(path: String) async throws -> SecretDocument {
        // Unlike status JSON, a failed command must never be decoded as success.
        let data = try await run(["secrets", "show", "--file", path, "--json"])
        return try JSON.decoder.decode(SecretDocument.self, from: data)
    }

    public func updateSecret(path: String, revision: String, key: String, value: String, create: Bool) async throws -> String {
        struct Update: Encodable {
            let revision: String
            let key: String
            let value: String
            let create: Bool
        }
        struct Saved: Decodable { let revision: String }
        let input = try JSONEncoder().encode(Update(revision: revision, key: key, value: value, create: create))
        let output = try await run(["secrets", "update", "--file", path], stdin: String(decoding: input, as: UTF8.self))
        return try JSON.decoder.decode(Saved.self, from: output).revision
    }
}
