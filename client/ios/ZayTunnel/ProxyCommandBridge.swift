import Foundation

/// Thin control bridge to the in-process Rust singbox library.
final class ProxyCommandBridge {

    func start() {
        ZayLog.info("ProxyCommandBridge ready (Rust library)")
    }

    func stop() {
        // Runtime lifetime is owned by PacketTunnelProvider.
    }

    func snapshotJSON() -> String {
        ZayNative.singboxGroupsJSON()
    }

    func selectOutbound(groupTag: String = "Proxy", outboundTag: String) throws {
        try ZayNative.selectSingboxOutbound(group: groupTag, outbound: outboundTag)
    }

    func urlTest(groupTag: String = "Auto") throws {
        try ZayNative.urlTestSingbox(group: groupTag)
    }

    func urlTestBestEffort() -> Error? {
        var last: Error?
        for tag in ["Auto", "Proxy"] {
            do {
                try urlTest(groupTag: tag)
                return nil
            } catch {
                last = error
            }
        }
        if let data = snapshotJSON().data(using: .utf8),
           let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let groups = root["groups"] as? [[String: Any]] {
            for g in groups {
                guard let tag = g["tag"] as? String, !tag.isEmpty else { continue }
                if tag == "Auto" || tag == "Proxy" { continue }
                do {
                    try urlTest(groupTag: tag)
                    return nil
                } catch {
                    last = error
                }
            }
        }
        return last
    }

}
