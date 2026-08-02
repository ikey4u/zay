import Foundation

/// Persist converted custom rule-sets under Libbox `ruleset-custom/`.
enum CustomRulesStore {
    static let directoryName = "ruleset-custom"

    static func customDirectory(workingDir: String) -> URL {
        URL(fileURLWithPath: workingDir, isDirectory: true)
            .appendingPathComponent(directoryName, isDirectory: true)
    }

    /// Write enabled entries as `{id}.json`; remove stale files for disabled/deleted ids.
    static func syncEnabledRulesToDisk(_ rules: [CustomRuleEntry], workingDir: String) throws {
        let dir = customDirectory(workingDir: workingDir)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        var keep = Set<String>()
        for entry in rules where entry.enabled {
            let body = entry.content.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !body.isEmpty else { continue }
            let converted = try ZayNative.convertRuleText(body, hint: entry.format)
            let path = dir.appendingPathComponent("\(entry.id).json")
            try converted.json.write(to: path, atomically: true, encoding: .utf8)
            keep.insert(entry.id)
        }

        if let existing = try? FileManager.default.contentsOfDirectory(
            at: dir,
            includingPropertiesForKeys: nil
        ) {
            for url in existing where url.pathExtension == "json" {
                let id = url.deletingPathExtension().lastPathComponent
                if !keep.contains(id) {
                    try? FileManager.default.removeItem(at: url)
                }
            }
        }
    }

    /// Fetch remote URL body (App-side) then convert.
    static func fetchRemote(_ urlString: String) async throws -> String {
        guard let url = URL(string: urlString.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            throw NSError(domain: "zay", code: 40, userInfo: [NSLocalizedDescriptionKey: "无效的规则 URL"])
        }
        var req = URLRequest(url: url, timeoutInterval: 60)
        req.setValue("clash-verge/v1", forHTTPHeaderField: "User-Agent")
        req.setValue("*/*", forHTTPHeaderField: "Accept")
        let (data, resp) = try await URLSession.shared.data(for: req)
        if let http = resp as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
            throw NSError(
                domain: "zay",
                code: 41,
                userInfo: [NSLocalizedDescriptionKey: "下载失败 HTTP \(http.statusCode)"]
            )
        }
        guard let text = String(data: data, encoding: .utf8), !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw NSError(domain: "zay", code: 42, userInfo: [NSLocalizedDescriptionKey: "规则内容为空"])
        }
        return text
    }
}
