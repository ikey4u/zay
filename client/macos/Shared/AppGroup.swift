import Foundation

enum ZayMacIdentifiers {
    static let appGroup = "group.dev.zay.macos"
    static let filterExtension = "dev.zay.macos.process-filter"
}

enum ZayMacAppGroup {
    static var containerURL: URL? {
        FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: ZayMacIdentifiers.appGroup
        )
    }

    static var attributionDirectory: URL? {
        guard let directory = containerURL?
            .appendingPathComponent("Library", isDirectory: true)
            .appendingPathComponent("Application Support", isDirectory: true)
            .appendingPathComponent("Zay", isDirectory: true)
            .appendingPathComponent("attribution", isDirectory: true)
        else { return nil }
        try? FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        return directory
    }

    static var flowEventsURL: URL? {
        attributionDirectory?.appendingPathComponent("flows.jsonl")
    }
}
