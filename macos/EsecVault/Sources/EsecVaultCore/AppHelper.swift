import Darwin
import Foundation
import Observation

/// The shared Go helper is a child of the menu-bar app, never a second install.
/// Only the parent owns the pipe writer; EOF also handles SIGKILL/app crashes.
@MainActor @Observable
public final class AppHelper {
    public private(set) var state = "Starting local helper…"
    public private(set) var error: String?
    public private(set) var pid: Int32?
    public private(set) var customSocket = false
    @ObservationIgnored private var child: HelperChild?
    @ObservationIgnored private var task: Task<Void, Never>?
    @ObservationIgnored private var wanted = false

    public init() {}

    public func start(cli: CLI, environment: [String: String] = CLI.environment) {
        guard task == nil else { return }
        // Explicit custom/forwarded brokers retain their separate lifetime.
        if let socket = environment["ESEC_VAULT_SOCK"], !socket.isEmpty {
            customSocket = true
            state = "Using a custom broker socket"
            return
        }
        customSocket = false
        wanted = true
        task = Task { await supervise(cli: cli, environment: environment) }
    }

    public func stop() {
        wanted = false
        task?.cancel()
        child?.closeParent()
        state = "Stopped"
    }

    public func restart(cli: CLI) async {
        stop()
        await task?.value
        start(cli: cli)
    }

    private func supervise(cli: CLI, environment: [String: String]) async {
        defer { task = nil; child = nil; pid = nil }
        var failures = 0
        while wanted && !Task.isCancelled {
            state = failures == 0 ? "Starting local helper…" : "Restarting local helper…"
            let started = Date()
            do {
                let process = try HelperChild(binary: cli.binary, environment: environment)
                child = process
                try process.start()
                pid = process.pid
                error = nil
                let result = await process.wait()
                child = nil
                pid = nil
                if !wanted || Task.isCancelled { break }
                error = result.output.isEmpty ? "Local helper exited (\(result.code))." : result.output
            } catch {
                self.error = error.localizedDescription
            }
            if !wanted || Task.isCancelled { break }
            if Date().timeIntervalSince(started) > 30 { failures = 0 }
            failures += 1
            if failures >= 3 {
                state = "Local helper could not start"
                break
            }
            do { try await Task.sleep(for: .seconds(Double(failures * 2))) }
            catch { break }
        }
    }

    public func observed(_ status: DaemonStatus?) {
        if let pid, status?.owner == "app", status?.pid == pid, status?.reachable == true {
            state = "Running in EsecVault"
            error = nil
        }
    }
}

/// Process waits and pipe reads run outside the cooperative executor. Output
/// is drained continuously into a bounded tail, including during app shutdown.
private final class HelperChild: @unchecked Sendable {
    private let process = Process()
    private let lifetime = Pipe()
    private let output = Pipe()
    private let tail = HelperOutput()
    var pid: Int32 { process.processIdentifier }

    init(binary: URL, environment: [String: String]) throws {
        // Do not let later CLI/plugin children inherit the writer and hold the
        // helper alive after the app exits. Set this before launching anything.
        for handle in [lifetime.fileHandleForReading, lifetime.fileHandleForWriting,
                       output.fileHandleForReading, output.fileHandleForWriting] {
            if fcntl(handle.fileDescriptor, F_SETFD, FD_CLOEXEC) == -1 {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
        }
        process.executableURL = binary
        process.arguments = ["daemon", "run", "--app-owned"]
        process.environment = environment
        process.standardInput = lifetime
        process.standardOutput = output
        process.standardError = output
    }

    func start() throws {
        let tail = self.tail
        output.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            if data.isEmpty { handle.readabilityHandler = nil }
            else { tail.append(data) }
        }
        do { try process.run() }
        catch {
            output.fileHandleForReading.readabilityHandler = nil
            closeParent()
            throw error
        }
        try? lifetime.fileHandleForReading.close()
        try? output.fileHandleForWriting.close()
    }

    func closeParent() { try? lifetime.fileHandleForWriting.close() }

    func wait() async -> (code: Int32, output: String) {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .utility).async { [self] in
                process.waitUntilExit()
                output.fileHandleForReading.readabilityHandler = nil
                closeParent()
                continuation.resume(returning: (process.terminationStatus, tail.text))
            }
        }
    }
}

private final class HelperOutput: @unchecked Sendable {
    private let lock = NSLock()
    private var data = Data()
    func append(_ more: Data) {
        lock.lock()
        defer { lock.unlock() }
        data.append(more)
        if data.count > 8192 { data = Data(data.suffix(8192)) }
    }
    var text: String {
        lock.lock()
        defer { lock.unlock() }
        return String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
