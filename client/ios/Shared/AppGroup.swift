import Foundation

enum AppGroup {
    /// Change to your team App Group if needed. Must match entitlements.
    static let id = ZayBundleID.appGroup

    static var containerURL: URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: id)
    }

    static var defaults: UserDefaults {
        UserDefaults(suiteName: id) ?? .standard
    }

    static var logFileURL: URL? {
        containerURL?.appendingPathComponent("logs/zay-ios.log")
    }

    static func ensureLogDirectory() {
        guard let dir = containerURL?.appendingPathComponent("logs", isDirectory: true) else { return }
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    static var workingDirectory: URL? {
        let url = containerURL?.appendingPathComponent("run", isDirectory: true)
        if let url {
            try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        }
        return url
    }
}
