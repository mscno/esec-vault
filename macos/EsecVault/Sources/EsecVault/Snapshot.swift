#if DEBUG
import AppKit

/// For development: with ESEC_VAULT_SNAPSHOT=dir the app draws its own
/// window into dir/<name>.png for each screen, then quits. It reads no
/// pixels but its own, so it needs no screen recording permission.
@MainActor
enum Snapshot {
    static var dir: String? { ProcessInfo.processInfo.environment["ESEC_VAULT_SNAPSHOT"] }

    static func run(select: @escaping (String) -> Void, screens: [String]) {
        guard let dir else { return }
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(3))
            for name in screens {
                select(name)
                try? await Task.sleep(for: .seconds(2))
                guard let window = NSApp.windows.first(where: { $0.isVisible && $0.frame.height > 200 }) else { continue }
                // Tall enough to show whole screens.
                window.setContentSize(NSSize(width: 960, height: 1300))
                try? await Task.sleep(for: .milliseconds(500))
                guard
                      let view = window.contentView?.superview ?? window.contentView,
                      let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { continue }
                view.cacheDisplay(in: view.bounds, to: rep)
                try? rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: "\(dir)/\(name.replacingOccurrences(of: "/", with: "_")).png"))
            }
            NSApp.terminate(nil)
        }
    }
}
#endif
