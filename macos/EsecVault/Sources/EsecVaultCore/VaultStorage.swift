import Foundation

public struct VaultStorage: Decodable, Sendable {
    public struct Project: Decodable, Identifiable, Sendable {
        public let project: String
        public let keys: Int
        public let cache: String
        public let revisions: Int
        public let checkouts: [String]
		public let cached: Bool
		public let history: [Revision]
        public var id: String { project }
    }
	public struct Revision: Decodable, Identifiable, Sendable {
		public let id: String
		public let checkout: String
		public let label: String
		public let at: Date
		public let sequence: UInt64
		public let files: Int
	}
    public struct Profile: Decodable, Identifiable, Sendable {
        public let id: String
        public let name: String
        public let files: [String]
    }
    public let projects: [Project]
    public let profiles: [Profile]
    public let pending: Bool
    public let generation: UInt64
	public let offline: Bool
	public let stagingFailed: Bool
	private enum CodingKeys: String, CodingKey {
		case projects, profiles, pending, generation, offline
		case stagingFailed = "staging_failed"
	}
}

extension CLI {
    public func vaultStorage() async throws -> VaultStorage {
        let data = try await run(["storage", "list", "--json"])
        return try JSON.decoder.decode(VaultStorage.self, from: data)
    }
}
