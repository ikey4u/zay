import Darwin
import Foundation

/// IPv4 CIDR matcher used by the packet dispatcher.
struct IPv4CIDR: Equatable, CustomStringConvertible {
    let network: UInt32
    let mask: UInt32
    let prefix: Int
    let raw: String

    var description: String { raw }

    init?(cidr: String) {
        let trimmed = cidr.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let parts = trimmed.split(separator: "/", maxSplits: 1).map(String.init)
        let addrStr = parts[0]
        let prefix: Int
        if parts.count == 2 {
            guard let p = Int(parts[1]), (0...32).contains(p) else { return nil }
            prefix = p
        } else {
            prefix = 32
        }
        guard let addr = IPv4CIDR.parseIPv4(addrStr) else { return nil }
        let mask: UInt32 = prefix == 0 ? 0 : (prefix >= 32 ? UInt32.max : UInt32.max << (32 - prefix))
        self.network = addr & mask
        self.mask = mask
        self.prefix = prefix
        self.raw = "\(IPv4CIDR.format(addr & mask))/\(prefix)"
    }

    func contains(_ ip: UInt32) -> Bool {
        (ip & mask) == network
    }

    static func parseIPv4(_ s: String) -> UInt32? {
        var addr = in_addr()
        guard s.withCString({ inet_pton(AF_INET, $0, &addr) }) == 1 else { return nil }
        return UInt32(bigEndian: addr.s_addr)
    }

    static func format(_ ip: UInt32) -> String {
        var addr = in_addr(s_addr: ip.bigEndian)
        var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        inet_ntop(AF_INET, &addr, &buf, socklen_t(INET_ADDRSTRLEN))
        return String(cString: buf)
    }
}

enum IPPacket {
    /// Returns IPv4 destination (and optionally source) when the buffer is a plain IPv4 packet.
    static func inspectIPv4(_ data: Data) -> (src: UInt32, dst: UInt32)? {
        guard data.count >= 20 else { return nil }
        let version = data[0] >> 4
        guard version == 4 else { return nil }
        let src = UInt32(data[12]) << 24
            | UInt32(data[13]) << 16
            | UInt32(data[14]) << 8
            | UInt32(data[15])
        let dst = UInt32(data[16]) << 24
            | UInt32(data[17]) << 16
            | UInt32(data[18]) << 8
            | UInt32(data[19])
        return (src, dst)
    }

    static func isMesh(_ data: Data, ranges: [IPv4CIDR]) -> Bool {
        guard let info = inspectIPv4(data), !ranges.isEmpty else { return false }
        // Either destination or source in mesh CIDR → EasyTier plane.
        // Source match covers replies originating from the mesh VIP.
        for r in ranges {
            if r.contains(info.dst) || r.contains(info.src) {
                return true
            }
        }
        return false
    }
}
