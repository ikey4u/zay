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

    /// Keep inspectable runtime artifacts below `Library`. CoreDevice only
    /// exposes `Library`, `Documents`, and `tmp` from an App Group container;
    /// files at the container root cannot be collected from a physical device.
    static var applicationSupportDirectory: URL? {
        guard let url = containerURL?
            .appendingPathComponent("Library", isDirectory: true)
            .appendingPathComponent("Application Support", isDirectory: true)
            .appendingPathComponent("Zay", isDirectory: true)
        else { return nil }
        try? FileManager.default.createDirectory(
            at: url,
            withIntermediateDirectories: true
        )
        return url
    }

    static var logFileURL: URL? {
        applicationSupportDirectory?
            .appendingPathComponent("logs", isDirectory: true)
            .appendingPathComponent("zay-ios.log")
    }

    static var lastFailureFileURL: URL? {
        applicationSupportDirectory?.appendingPathComponent("last-failure.txt")
    }

    static var interfaceDebugFileURL: URL? {
        applicationSupportDirectory?.appendingPathComponent("iface-debug.txt")
    }

    static var diagnosticRedactionMarkerURL: URL? {
        applicationSupportDirectory?
            .appendingPathComponent(".diagnostic-log-redaction-v1")
    }

    static func ensureLogDirectory() {
        guard let dir = logFileURL?.deletingLastPathComponent() else { return }
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    static var workingDirectory: URL? {
        let url = applicationSupportDirectory?
            .appendingPathComponent("run", isDirectory: true)
        if let url {
            try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        }
        return url
    }
}
