import Foundation

/// Parsed from tunnel `status` → EasyTier `ui` summary (see mesh.rs `build_ui_summary`).
struct MeshStatusReport: Equatable {
    var overview: MeshOverview
    var nodes: [MeshNodeStatus]
    var rawJSON: String
    var fetchedAt: Date

    static let empty = MeshStatusReport(
        overview: .empty,
        nodes: [],
        rawJSON: "",
        fetchedAt: .distantPast
    )
}

struct MeshOverview: Equatable {
    var running: Bool
    var instanceName: String
    var hostname: String
    var virtualIPv4: String
    var meshCIDR: String
    var networkName: String
    var peerID: String
    var peerCount: Int
    var nodeCount: Int
    var version: String

    static let empty = MeshOverview(
        running: false,
        instanceName: "",
        hostname: "",
        virtualIPv4: "",
        meshCIDR: "",
        networkName: "",
        peerID: "",
        peerCount: 0,
        nodeCount: 0,
        version: ""
    )
}

struct MeshNodeStatus: Identifiable, Equatable {
    var id: String { peerID.isEmpty ? hostname : peerID }
    var peerID: String
    var hostname: String
    var ipv4: String
    var isSelf: Bool
    var cost: Int
    var latencyMs: Int?
    var nextHopPeerID: String
    var version: String
    var proxyCIDRs: [String]
    var natTCP: String
    var natUDP: String
    var rxBytes: UInt64
    var txBytes: UInt64
    var connCount: Int
    var tunnels: [MeshTunnelStatus]
}

struct MeshTunnelStatus: Equatable, Identifiable {
    var id: String { "\(type)|\(local)|\(remote)" }
    var type: String
    var local: String
    var remote: String
}

enum MeshStatusParser {
    static func parse(_ json: String) -> MeshStatusReport? {
        guard let data = json.data(using: .utf8),
              let root = try? JSONSerialization.jsonObject(with: data)
        else { return nil }

        let instances: [[String: Any]]
        if let arr = root as? [[String: Any]] {
            instances = arr
        } else if let dict = root as? [String: Any] {
            instances = [dict]
        } else {
            return nil
        }

        guard let first = instances.first else {
            return MeshStatusReport(
                overview: .empty,
                nodes: [],
                rawJSON: json,
                fetchedAt: Date()
            )
        }

        let ui = first["ui"] as? [String: Any] ?? [:]
        let overview = MeshOverview(
            running: ui["running"] as? Bool ?? false,
            instanceName: string(ui["instance_name"]) ?? string(first["instance_name"]) ?? "",
            hostname: string(ui["hostname"]) ?? "",
            virtualIPv4: string(ui["virtual_ipv4"]) ?? string(first["virtual_ipv4"]) ?? "",
            meshCIDR: string(ui["mesh_cidr"]) ?? string(first["mesh_cidr"]) ?? "",
            networkName: string(ui["network_name"]) ?? "",
            peerID: string(ui["peer_id"]) ?? "",
            peerCount: int(ui["peer_count"]) ?? 0,
            nodeCount: int(ui["node_count"]) ?? 0,
            version: string(ui["version"]) ?? ""
        )

        let nodesRaw = ui["nodes"] as? [[String: Any]] ?? []
        let nodes = nodesRaw.map { n -> MeshNodeStatus in
            let tunnels = (n["tunnels"] as? [[String: Any]] ?? []).map {
                MeshTunnelStatus(
                    type: string($0["type"]) ?? "",
                    local: string($0["local"]) ?? "",
                    remote: string($0["remote"]) ?? ""
                )
            }
            return MeshNodeStatus(
                peerID: string(n["peer_id"]) ?? "",
                hostname: string(n["hostname"]) ?? "(unnamed)",
                ipv4: string(n["ipv4"]) ?? "",
                isSelf: n["is_self"] as? Bool ?? false,
                cost: int(n["cost"]) ?? 0,
                latencyMs: int(n["latency_ms"]),
                nextHopPeerID: string(n["next_hop_peer_id"]) ?? "",
                version: string(n["version"]) ?? "",
                proxyCIDRs: (n["proxy_cidrs"] as? [String]) ?? [],
                natTCP: string(n["nat_tcp"]) ?? "",
                natUDP: string(n["nat_udp"]) ?? "",
                rxBytes: uint64(n["rx_bytes"]) ?? 0,
                txBytes: uint64(n["tx_bytes"]) ?? 0,
                connCount: int(n["conn_count"]) ?? 0,
                tunnels: tunnels
            )
        }

        return MeshStatusReport(
            overview: overview,
            nodes: nodes,
            rawJSON: json,
            fetchedAt: Date()
        )
    }

    private static func string(_ v: Any?) -> String? {
        if let s = v as? String { return s }
        if let n = v as? NSNumber { return n.stringValue }
        return nil
    }

    private static func int(_ v: Any?) -> Int? {
        if let i = v as? Int { return i }
        if let n = v as? NSNumber { return n.intValue }
        if let s = v as? String { return Int(s) }
        return nil
    }

    private static func uint64(_ v: Any?) -> UInt64? {
        if let i = v as? UInt64 { return i }
        if let i = v as? Int { return UInt64(i) }
        if let n = v as? NSNumber { return n.uint64Value }
        if let s = v as? String { return UInt64(s) }
        return nil
    }
}

enum MeshFormat {
    static func bytes(_ n: UInt64) -> String {
        if n < 1024 { return "\(n) B" }
        let kb = Double(n) / 1024
        if kb < 1024 { return String(format: "%.1f KB", kb) }
        let mb = kb / 1024
        if mb < 1024 { return String(format: "%.1f MB", mb) }
        return String(format: "%.2f GB", mb / 1024)
    }

    static func latency(_ ms: Int?) -> String {
        guard let ms else { return "—" }
        return "\(ms) ms"
    }
}
