import Foundation
import Libbox

/// Libbox CommandClient bridge for selector / urltest (Packet Tunnel).
final class ProxyCommandBridge: NSObject, LibboxCommandClientHandlerProtocol {
    private let lock = NSLock()
    private var client: LibboxCommandClient?
    private var groupsJSON: String = #"{"groups":[]}"#
    private var isClientConnected = false

    func start() {
        stop()
        let opts = LibboxCommandClientOptions()
        opts.addCommand(LibboxCommandGroup)
        opts.statusInterval = 5_000_000_000
        guard let client = LibboxNewCommandClient(self, opts) else {
            ZayLog.warn("ProxyCommandBridge: NewCommandClient failed")
            return
        }
        self.client = client
        do {
            try client.connect()
            ZayLog.info("ProxyCommandBridge connected (groups)")
        } catch {
            ZayLog.warn("ProxyCommandBridge connect: \(error.localizedDescription)")
            self.client = nil
        }
    }

    func stop() {
        try? client?.disconnect()
        client = nil
        lock.lock()
        isClientConnected = false
        groupsJSON = #"{"groups":[]}"#
        lock.unlock()
    }

    func snapshotJSON() -> String {
        lock.lock()
        defer { lock.unlock() }
        return groupsJSON
    }

    func selectOutbound(groupTag: String = "Proxy", outboundTag: String) throws {
        guard let client else {
            throw NSError(domain: "zay", code: 60, userInfo: [NSLocalizedDescriptionKey: "代理控制通道未就绪"])
        }
        try client.selectOutbound(groupTag, outboundTag: outboundTag)
    }

    func urlTest(outboundTag: String = "Auto") throws {
        guard let client else {
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
        ZayLog.debug("ProxyCommandBridge handler connected")
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
