import Foundation
import Libbox

/// Libbox CommandClient bridge for selector / urltest (Packet Tunnel).
///
/// Kept mostly idle: connect lazily on first UI/control request, and use a long
/// statusInterval so group pushes do not wake the extension every few seconds.
final class ProxyCommandBridge: NSObject, LibboxCommandClientHandlerProtocol {
    /// Nanoseconds. 5s was a major battery drain for always-on VPN.
    private static let statusIntervalNs: Int64 = 120_000_000_000 // 120s

    private let lock = NSLock()
    private var client: LibboxCommandClient?
    private var groupsJSON: String = #"{"groups":[]}"#
    private var isClientConnected = false

    func start() {
        // No-op: connect lazily via ensureClient on first control/UI request.
    }

    @discardableResult
    private func ensureClient() -> LibboxCommandClient? {
        lock.lock()
        if let client {
            lock.unlock()
            return client
        }
        lock.unlock()

        let opts = LibboxCommandClientOptions()
        opts.addCommand(LibboxCommandGroup)
        opts.statusInterval = Self.statusIntervalNs
        guard let client = LibboxNewCommandClient(self, opts) else {
            ZayLog.warn("ProxyCommandBridge: NewCommandClient failed")
            return nil
        }
        do {
            try client.connect()
            lock.lock()
            self.client = client
            lock.unlock()
            ZayLog.info("ProxyCommandBridge connected (groups, interval=120s)")
            return client
        } catch {
            ZayLog.warn("ProxyCommandBridge connect: \(error.localizedDescription)")
            return nil
        }
    }

    func stop() {
        lock.lock()
        let existing = client
        client = nil
        isClientConnected = false
        groupsJSON = #"{"groups":[]}"#
        lock.unlock()
        try? existing?.disconnect()
    }

    func snapshotJSON() -> String {
        _ = ensureClient()
        lock.lock()
        defer { lock.unlock() }
        return groupsJSON
    }

    func selectOutbound(groupTag: String = "Proxy", outboundTag: String) throws {
        guard let client = ensureClient() else {
            throw NSError(domain: "zay", code: 60, userInfo: [NSLocalizedDescriptionKey: "代理控制通道未就绪"])
        }
        try client.selectOutbound(groupTag, outboundTag: outboundTag)
    }

    func urlTest(outboundTag: String = "Auto") throws {
        guard let client = ensureClient() else {
            throw NSError(domain: "zay", code: 60, userInfo: [NSLocalizedDescriptionKey: "代理控制通道未就绪"])
        }
        try client.urlTest(outboundTag)
    }

    func urlTestBestEffort() -> Error? {
        var last: Error?
        for tag in ["Auto", "Proxy"] {
            do {
                try urlTest(outboundTag: tag)
                return nil
            } catch {
                last = error
            }
        }
        if let data = snapshotJSON().data(using: .utf8),
           let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let groups = root["groups"] as? [[String: Any]] {
            for g in groups {
                let items = g["items"] as? [[String: Any]] ?? []
                for item in items {
                    guard let tag = item["tag"] as? String, !tag.isEmpty else { continue }
                    if tag == "Auto" || tag == "Proxy" || tag == "direct" { continue }
                    do {
                        try urlTest(outboundTag: tag)
                        last = nil
                    } catch {
                        last = error
                    }
                }
            }
        }
        return last
    }

    // MARK: - LibboxCommandClientHandlerProtocol

    func clearLogs() {}

    func connected() {
        lock.lock()
        isClientConnected = true
        lock.unlock()
    }

    func disconnected(_ message: String?) {
        lock.lock()
        isClientConnected = false
        lock.unlock()
        ZayLog.warn("ProxyCommandBridge disconnected: \(message ?? "")")
    }

    func initializeClashMode(_ modeList: (any LibboxStringIteratorProtocol)?, currentMode: String?) {}
    func setDefaultLogLevel(_ level: Int32) {}
    func updateClashMode(_ newMode: String?) {}
    func writeLogs(_ messageList: (any LibboxLogIteratorProtocol)?) {}
    func writeOutbounds(_ message: (any LibboxOutboundGroupItemIteratorProtocol)?) {}
    func writeStatus(_ message: LibboxStatusMessage?) {}
    func write(_ events: LibboxConnectionEvents?) {}

    func writeGroups(_ message: (any LibboxOutboundGroupIteratorProtocol)?) {
        var groups: [[String: Any]] = []
        while let g = message?.next() {
            var items: [[String: Any]] = []
            let it = g.getItems()
            while let item = it?.next() {
                items.append([
                    "tag": item.tag,
                    "type": item.type,
                    "url_test_delay": item.urlTestDelay,
                    "url_test_time": item.urlTestTime,
                ])
            }
            groups.append([
                "tag": g.tag,
                "type": g.type,
                "selectable": g.selectable,
                "selected": g.selected,
                "items": items,
            ])
        }
        let payload: [String: Any] = ["groups": groups]
        if let data = try? JSONSerialization.data(withJSONObject: payload),
           let s = String(data: data, encoding: .utf8) {
            lock.lock()
            groupsJSON = s
            lock.unlock()
        }
    }
}
