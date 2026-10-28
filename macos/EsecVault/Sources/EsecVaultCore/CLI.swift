import Foundation

/// Runs the esec-vault command line. Every action of the app is a command
/// you could type yourself; the app adds nothing the CLI does not do.
public struct CLI: Sendable {
    public let binary: URL

    public init(binary: URL) { self.binary = binary }

    public struct Failure: Error, LocalizedError, Sendable {
        public let command: String
        public let output: String
        public let code: Int32
        public var errorDescription: String? {
            let last = output.split(separator: "\n").last.map(String.init) ?? "exit \(code)"
            return "\(command): \(last)"
        }
    }

    /// Finds esec-vault where installs usually put it, or on PATH.
    public static func locate() -> CLI? {
        let env = ProcessInfo.processInfo.environment
        var candidates: [String] = []
        if let p = env["ESEC_VAULT_BIN"] { candidates.append(p) }
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        candidates += ["\(home)/go/bin/esec-vault", "/opt/homebrew/bin/esec-vault", "/usr/local/bin/esec-vault"]
        for dir in (env["PATH"] ?? "").split(separator: ":") {
            candidates.append("\(dir)/esec-vault")
        }
        for c in candidates where FileManager.default.isExecutableFile(atPath: c) {
            return CLI(binary: URL(fileURLWithPath: c))
        }
        return nil
    }

    /// Runs a command and returns its standard output. Both pipes are read
    /// while it runs, so a large output cannot block it.
    public func run(_ args: [String], stdin: String? = nil) async throws -> Data {
        let binary = self.binary
        return try await Task.detached { try Self.runBlocking(binary, args, stdin) }.value
    }

    private static func runBlocking(_ binary: URL, _ args: [String], _ stdin: String?) throws -> Data {
            let p = Process()
            p.executableURL = binary
            p.arguments = args
            var env = ProcessInfo.processInfo.environment
            env["NO_COLOR"] = "1"
            p.environment = env
            let out = Pipe(), err = Pipe()
            p.standardOutput = out
            p.standardError = err
            let inPipe = Pipe()
            p.standardInput = stdin == nil ? FileHandle.nullDevice : inPipe
            try p.run()
            if let stdin {
                inPipe.fileHandleForWriting.write(Data(stdin.utf8))
                try? inPipe.fileHandleForWriting.close()
            }
            let errBox = DataBox()
            let group = DispatchGroup()
            group.enter()
            DispatchQueue.global().async {
                errBox.data = err.fileHandleForReading.readDataToEndOfFile()
                group.leave()
            }
            let data = out.fileHandleForReading.readDataToEndOfFile()
            group.wait()
            p.waitUntilExit()
            if p.terminationStatus == 0 { return data }
            let text = String(decoding: data + errBox.data, as: UTF8.self)
            throw Failure(command: "esec-vault " + args.prefix(2).joined(separator: " "), output: text, code: p.terminationStatus)
    }

    /// Runs a command that prints JSON and decodes it. A command that fails
    /// but still printed JSON (verify with problems) is decoded too.
    public func json<T: Decodable>(_ type: T.Type, _ args: [String]) async throws -> T {
        do {
            let data = try await run(args)
            return try JSON.decoder.decode(T.self, from: data)
        } catch let f as Failure {
            if let start = f.output.firstIndex(where: { $0 == "{" || $0 == "[" }),
               let value = try? JSON.decoder.decode(T.self, from: Data(f.output[start...].utf8)) {
                return value
            }
            throw f
        }
    }

    public func projects() async throws -> [Project] { try await json([Project].self, ["projects", "--json"]) }
    public func project(_ id: String) async throws -> Project { try await json(Project.self, ["projects", "show", id, "--json"]) }
    public func guardStatus() async throws -> GuardStatus { try await json(GuardStatus.self, ["guard", "--json"]) }
    public func lastVerify() async throws -> VerifySaved { try await json(VerifySaved.self, ["verify", "--last", "--json"]) }
    public func verifyNow() async throws -> VerifyReport { try await json(VerifyReport.self, ["verify", "--json"]) }
}

private final class DataBox: @unchecked Sendable {
    var data = Data()
}
