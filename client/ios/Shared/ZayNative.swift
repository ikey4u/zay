import Foundation
import OSLog
#if canImport(UIKit)
import UIKit
#endif

enum ZayLog {
    private static let queue = DispatchQueue(label: "dev.zay.ios.log", qos: .utility)
    private static let lock = NSLock()
    private static var memoryLines: [String] = []
    private static let maxMemoryLines = 400
    private static var resolvedLogURL: URL?
    /// Soft cap for shared log file (bytes). Rotated when exceeded.
    private static let maxLogFileBytes: UInt64 = 1_500_000

    private static var libboxDropCount: Int = 0
    private static var libboxLastEmit = Date.distantPast
    private static let libboxMinInterval: TimeInterval = 0.25

    /// Shows in Xcode console when the corresponding process is being debugged.
    private static let logger = Logger(subsystem: "dev.zay.ios", category: "zay")

    static func setupNativeLogPath() {
        let url = ensureLogFileURL()
        resolvedLogURL = url
        if let path = url?.path {
            path.withCString { zay_ios_set_log_path($0) }
        }
        info("log path ready: \(url?.path ?? "(nil)") appGroup=\(AppGroup.containerURL != nil)")
    }

    static func info(_ message: String) { write(level: "info", message) }
    static func warn(_ message: String) { write(level: "warn", message) }
    static func error(_ message: String) { write(level: "error", message) }
    static func debug(_ message: String) { write(level: "debug", message, console: false) }

    /// High-volume Libbox platform debug sink — file/memory only, heavily rate-limited.
    static func libboxDebug(_ message: String) {
        let trimmed = message.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }

        lock.lock()
        let now = Date()
        let elapsed = now.timeIntervalSince(libboxLastEmit)
        if elapsed < libboxMinInterval {
            libboxDropCount += 1
            lock.unlock()
            return
        }
        let dropped = libboxDropCount
        libboxDropCount = 0
        libboxLastEmit = now
        lock.unlock()

        let body: String
        if dropped > 0 {
            body = "(dropped \(dropped) libbox lines) \(trimmed)"
        } else {
            body = trimmed
        }
        // No NSLog / print — those alone can kill Packet Tunnel under traffic.
        write(level: "debug", body, console: false, rustMirror: false)
    }

    static func write(level: String, _ message: String, console: Bool = true, rustMirror: Bool = true) {
        let line = "[\(timestamp())] [\(level)] \(message)"

        // 1) Memory (sync) — UI can read immediately.
        lock.lock()
        memoryLines.append(line)
        if memoryLines.count > maxMemoryLines {
            memoryLines.removeFirst(memoryLines.count - maxMemoryLines)
        }
        lock.unlock()

        // 2) Console — skip for high-volume debug paths.
        if console {
            print("[zay][\(level)] \(message)")
            switch level {
            case "error":
                logger.error("\(message, privacy: .public)")
            case "warn":
                logger.warning("\(message, privacy: .public)")
            case "debug":
                logger.debug("\(message, privacy: .public)")
            default:
                logger.info("\(message, privacy: .public)")
            }
            // NSLog is expensive; only for warn/error.
            if level == "error" || level == "warn" {
                NSLog("[zay][%@] %@", level, message)
            }
        }

        // 3) File (+ optional Rust) — must not block caller.
        queue.async {
            let dataLine = line + "\n"
            if rustMirror {
                level.withCString { lvl in
                    message.withCString { msg in
                        zay_ios_log(lvl, msg)
                    }
                }
            }
            if let url = ensureLogFileURL(), let data = dataLine.data(using: .utf8) {
                append(data, to: url)
            }
        }
    }

    /// Fast path for UI: memory first, then a small file tail.
    static func readForUI(maxLines: Int = 200, maxFileBytes: Int = 24_000) -> String {
        var header: [String] = []
        if AppGroup.containerURL == nil {
            header.append("⚠️ App Group 不可用，日志写在 App 沙盒（扩展侧日志可能看不到）")
        }
        if let url = ensureLogFileURL() {
            header.append("📄 \(url.path)")
        }

        let fromFile = readTail(maxBytes: maxFileBytes)
        lock.lock()
        let mem = memoryLines.suffix(maxLines).joined(separator: "\n")
        lock.unlock()

        var body = ""
        if !fromFile.isEmpty, fromFile != "(no log file yet)" {
            body = fromFile
        } else if !mem.isEmpty {
            body = mem
        } else {
            body = "暂无日志。启动 VPN 或操作 App 后会出现记录。"
        }

        if header.isEmpty { return body }
        return header.joined(separator: "\n") + "\n\n" + body
    }

    static func readTail(maxBytes: Int = 64_000) -> String {
        guard let url = ensureLogFileURL() else {
            lock.lock()
            let mem = memoryLines.suffix(200).joined(separator: "\n")
            lock.unlock()
            return mem.isEmpty ? "(no log file yet)" : mem
        }
        guard let handle = try? FileHandle(forReadingFrom: url) else {
            lock.lock()
            let mem = memoryLines.suffix(200).joined(separator: "\n")
            lock.unlock()
            return mem.isEmpty ? "(no log file yet)" : mem
        }
        defer { try? handle.close() }
        let size = (try? handle.seekToEnd()) ?? 0
        if size == 0 {
            lock.lock()
            let mem = memoryLines.suffix(200).joined(separator: "\n")
            lock.unlock()
            return mem
        }
        let start = size > UInt64(maxBytes) ? size - UInt64(maxBytes) : 0
        try? handle.seek(toOffset: start)
        let data = (try? handle.readToEnd()) ?? Data()
        return String(data: data, encoding: .utf8) ?? ""
    }

    static func readLastFailure() -> String? {
        let urls: [URL] = [
            AppGroup.containerURL?.appendingPathComponent("last-failure.txt"),
            FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first?
                .appendingPathComponent("zay-last-failure.txt"),
        ].compactMap { $0 }
        for url in urls {
            if let text = try? String(contentsOf: url, encoding: .utf8) {
                let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
                if !trimmed.isEmpty { return trimmed }
            }
        }
        return nil
    }

    static func diagnosticReport(config: ZayRuntimeConfig? = nil) -> String {
        var parts: [String] = []
        parts.append("=== Zay iOS Diagnostic ===")
        parts.append("time: \(ISO8601DateFormatter().string(from: Date()))")
        parts.append("appGroup: \(AppGroup.id)")
        parts.append("container: \(AppGroup.containerURL?.path ?? "(nil)")")
        parts.append("logFile: \(ensureLogFileURL()?.path ?? "(nil)")")
        if let cfg = config ?? Optional(ZayRuntimeConfig.load()) {
            var redacted = cfg
            if !redacted.networkSecret.isEmpty {
                redacted.networkSecret = "<redacted len=\(cfg.networkSecret.count)>"
            }
            if let data = try? JSONEncoder().encode(redacted),
               let json = String(data: data, encoding: .utf8) {
                parts.append("config: \(json)")
            }
        }
        if let fail = readLastFailure() {
            parts.append("lastFailure: \(fail)")
        }
        if let ifaceURL = AppGroup.containerURL?.appendingPathComponent("iface-debug.txt"),
           let iface = try? String(contentsOf: ifaceURL, encoding: .utf8),
           !iface.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            parts.append("=== iface-debug ===")
            parts.append(iface)
        }
        if let cfgURL = AppGroup.workingDirectory?.appendingPathComponent("config.json"),
           let cfgText = try? String(contentsOf: cfgURL, encoding: .utf8) {
            parts.append("=== config.json route snippet ===")
            if let data = cfgText.data(using: .utf8),
               let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let route = obj["route"] {
                if let routeData = try? JSONSerialization.data(withJSONObject: route, options: [.prettyPrinted]),
                   let routeStr = String(data: routeData, encoding: .utf8) {
                    parts.append(routeStr)
                }
            } else {
                parts.append(String(cfgText.prefix(2000)))
            }
        }
        parts.append("=== memory log ===")
        lock.lock()
        parts.append(memoryLines.suffix(200).joined(separator: "\n"))
        lock.unlock()
        parts.append("=== file tail ===")
        parts.append(readTail(maxBytes: 64_000))
        return parts.joined(separator: "\n")
    }

    static func writeDiagnosticFile() -> URL? {
        let report = diagnosticReport()
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("zay-diagnostic-\(Int(Date().timeIntervalSince1970)).txt")
        do {
            try report.write(to: url, atomically: true, encoding: .utf8)
            return url
        } catch {
            return nil
        }
    }

    static func clear() {
        lock.lock()
        memoryLines.removeAll()
        lock.unlock()
        if let url = ensureLogFileURL() {
            try? "".write(to: url, atomically: true, encoding: .utf8)
        }
    }

    // MARK: - Paths

    /// Prefer App Group; fall back to Documents so the app always has a writable log.
    @discardableResult
    static func ensureLogFileURL() -> URL? {
        if let groupURL = AppGroup.containerURL {
            let url = groupURL.appendingPathComponent("logs/zay-ios.log")
            AppGroup.ensureLogDirectory()
            if resolvedLogURL != url {
                resolvedLogURL = url
                url.path.withCString { zay_ios_set_log_path($0) }
            }
            return url
        }
        if let cached = resolvedLogURL { return cached }
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
        let url = docs?.appendingPathComponent("zay-ios.log")
        resolvedLogURL = url
        if let path = url?.path {
            path.withCString { zay_ios_set_log_path($0) }
        }
        return url
    }

    private static func append(_ data: Data, to url: URL) {
        let dir = url.deletingLastPathComponent()
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        rotateIfNeeded(url)
        if FileManager.default.fileExists(atPath: url.path) {
            if let handle = try? FileHandle(forWritingTo: url) {
                defer { try? handle.close() }
                try? handle.seekToEnd()
                try? handle.write(contentsOf: data)
            }
        } else {
            try? data.write(to: url)
        }
    }

    private static func rotateIfNeeded(_ url: URL) {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
              let size = attrs[.size] as? UInt64,
              size > maxLogFileBytes
        else { return }
        let bak = url.deletingLastPathComponent().appendingPathComponent("zay-ios.log.1")
        try? FileManager.default.removeItem(at: bak)
        try? FileManager.default.moveItem(at: url, to: bak)
    }

    private static func timestamp() -> String {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        return f.string(from: Date())
    }
}

enum ZayNative {
    static func lastError() -> String {
        guard let ptr = zay_ios_last_error() else { return "unknown error" }
        defer { zay_ios_free_string(ptr) }
        return String(cString: ptr)
    }

    static func takeCString(_ ptr: UnsafeMutablePointer<CChar>?) -> String? {
        guard let ptr else { return nil }
        defer { zay_ios_free_string(ptr) }
        return String(cString: ptr)
    }

    static func buildEasytierTOML(config: ZayRuntimeConfig) throws -> String {
        var dict: [String: Any] = [
            "network_name": config.networkName,
            "network_secret": config.networkSecret,
            "relay_url": config.relayURL,
            "instance_name": "zay-ios",
            "socks_port": config.socksPort,
        ]
        let ipv4 = config.meshIPv4.trimmingCharacters(in: .whitespacesAndNewlines)
        if !ipv4.isEmpty {
            dict["ipv4"] = ipv4
        }
        let hostname = resolvedHostname(from: config)
        dict["hostname"] = hostname
        let json = try JSONSerialization.data(withJSONObject: dict)
        let jsonStr = String(data: json, encoding: .utf8) ?? "{}"
        let ptr = jsonStr.withCString { zay_ios_build_easytier_toml($0) }
        guard let toml = takeCString(ptr) else {
            throw NSError(domain: "zay", code: 1, userInfo: [NSLocalizedDescriptionKey: lastError()])
        }
        return toml
    }

    /// Peer-visible EasyTier hostname. Prefer user setting, else device name.
    static func resolvedHostname(from config: ZayRuntimeConfig) -> String {
        let custom = config.hostname.trimmingCharacters(in: .whitespacesAndNewlines)
        if !custom.isEmpty { return custom }
#if canImport(UIKit)
        let device = UIDevice.current.name.trimmingCharacters(in: .whitespacesAndNewlines)
        if !device.isEmpty, device.lowercased() != "localhost" {
            return device
        }
#endif
        return "zay-ios"
    }

    static func buildSingboxJSON(
        config: ZayRuntimeConfig,
        meshCIDRs: [String],
        bypassIPs: [String],
        workingDir: String,
        rulesProfile: String = "0",
        preferCache: Bool = false
    ) throws -> String {
        try CustomRulesStore.syncEnabledRulesToDisk(config.customRules, workingDir: workingDir)
        let customPayload: [[String: String]] = config.customRules
            .filter(\.enabled)
            .map { ["id": $0.id, "action": $0.action] }
        let dict: [String: Any] = [
            "proxy_url": config.proxyURL,
            "mesh_cidrs": meshCIDRs,
            "bypass_ips": bypassIPs,
            "socks_port": config.socksPort,
            "log_level": "info",
            "working_dir": workingDir,
            "selected_proxy_tag": config.resolvedSelectedProxyTag,
            "rules_profile": rulesProfile,
            "prefer_cache": preferCache,
            "custom_rules": customPayload,
        ]
        let json = try JSONSerialization.data(withJSONObject: dict)
        let jsonStr = String(data: json, encoding: .utf8) ?? "{}"
        let ptr = jsonStr.withCString { zay_ios_build_singbox_json($0) }
        guard let out = takeCString(ptr) else {
            throw NSError(domain: "zay", code: 2, userInfo: [NSLocalizedDescriptionKey: lastError()])
        }
        return out
    }

    /// Materialize embedded Loyalsoldier rule-sets into Libbox working dir.
    static func ensureEmbeddedRules(workingDir: String) throws {
        let rc = workingDir.withCString { zay_ios_ensure_embedded_rules($0) }
        guard rc == 0 else {
            throw NSError(
                domain: "zay",
                code: 3,
                userInfo: [NSLocalizedDescriptionKey: lastError()]
            )
        }
    }

    static func listProxyNodes(proxyURL: String) throws -> String {
        let ptr = proxyURL.withCString { zay_ios_list_proxy_nodes($0) }
        guard let out = takeCString(ptr) else {
            throw NSError(domain: "zay", code: 5, userInfo: [NSLocalizedDescriptionKey: lastError()])
        }
        return out
    }

    /// Download subscription into App Group cache while the App still has clear network.
    @discardableResult
    static func prefetchProxy(proxyURL: String, workingDir: String) -> Bool {
        let rc = proxyURL.withCString { urlPtr in
            workingDir.withCString { dirPtr in
                zay_ios_prefetch_proxy(urlPtr, dirPtr)
            }
        }
        if rc != 0 {
            ZayLog.warn("prefetchProxy failed: \(lastError())")
            return false
        }
        ZayLog.info("prefetchProxy ok")
        return true
    }

    static func convertRuleText(_ raw: String, hint: String = "auto") throws -> (format: String, ruleCount: Int, json: String) {
        let ptr = raw.withCString { textPtr in
            hint.withCString { hintPtr in
                zay_ios_convert_rule_text(textPtr, hintPtr)
            }
        }
        guard let out = takeCString(ptr),
              let data = out.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let json = obj["json"] as? String
        else {
            throw NSError(domain: "zay", code: 6, userInfo: [NSLocalizedDescriptionKey: lastError()])
        }
        let format = obj["format"] as? String ?? "auto"
        let count = (obj["rule_count"] as? Int) ?? (obj["rule_count"] as? NSNumber)?.intValue ?? 0
        return (format, count, json)
    }

    static func embeddedRulesInfo(workingDir: String?) -> String {
        if let workingDir {
            return takeCString(workingDir.withCString { zay_ios_embedded_rules_info($0) }) ?? "{}"
        }
        return takeCString(zay_ios_embedded_rules_info(nil)) ?? "{}"
    }

    static func startMesh(toml: String) throws {
        let rc = toml.withCString { zay_ios_start_mesh($0) }
        if rc != 0 {
            throw NSError(domain: "zay", code: 3, userInfo: [NSLocalizedDescriptionKey: lastError()])
        }
    }

    static func stopMesh() {
        _ = zay_ios_stop_mesh()
    }

    static func setTunFd(instanceName: String = "zay-ios", fd: Int32) throws {
        let rc = instanceName.withCString { zay_ios_set_tun_fd($0, fd) }
        if rc != 0 {
            throw NSError(domain: "zay", code: 4, userInfo: [NSLocalizedDescriptionKey: lastError()])
        }
    }

    static func meshStatusJSON() -> String {
        takeCString(zay_ios_mesh_status_json()) ?? "[]"
    }

    static func relayHost(from relayURL: String) -> String? {
        takeCString(relayURL.withCString { zay_ios_relay_host($0) })
    }
}
