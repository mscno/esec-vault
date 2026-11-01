import EsecVaultCore
import Foundation
import Testing

@Test(.timeLimit(.minutes(1))) func concurrentCommandsDrainAllPipes() async throws {
    let cli = CLI(binary: URL(fileURLWithPath: "/bin/sh"))
    let payload = String(repeating: "test input\n", count: 16_384)
    try await withThrowingTaskGroup(of: Void.self) { group in
        for _ in 0..<32 {
            group.addTask {
                // Fill stderr beyond a pipe buffer before echoing a similarly
                // large stdin. Every stream must make progress concurrently.
                let output = try await cli.run(
                    ["-c", "head -c 131072 /dev/zero >&2; cat"], stdin: payload
                )
                #expect(output == Data(payload.utf8))
            }
        }
        try await group.waitForAll()
    }
}
