import Darwin
import Foundation
import Libbox

/// Underlay NICs for Libbox outbound bind.
///
/// Full-tunnel Packet Tunnel often makes `NWPathMonitor.availableInterfaces` show only
/// our own utun. Libbox then has nothing left to dial after excluding MyInterface.
/// `getifaddrs` still sees Wi-Fi / cellular, so we use that as source of truth.
enum PhysicalNetworkInterfaces {
    struct Entry {
        let name: String
        let index: Int32
        let flags: Int32
        let libboxType: Int32
    }

    /// UP, non-loopback interfaces from getifaddrs.
    static func enumerate(excluding excluded: String? = nil) -> [Entry] {
        var ifaddrPtr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddrPtr) == 0, let first = ifaddrPtr else { return [] }
        defer { freeifaddrs(first) }

        var seen = Set<String>()
        var result: [Entry] = []
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let ifa = cursor {
            defer { cursor = ifa.pointee.ifa_next }
            let name = String(cString: ifa.pointee.ifa_name)
            if let excluded, name == excluded { continue }
            guard !seen.contains(name) else { continue }

            let rawFlags = Int32(ifa.pointee.ifa_flags)
            guard (rawFlags & IFF_UP) != 0 else { continue }
            guard (rawFlags & IFF_LOOPBACK) == 0 else { continue }
            // Skip Apple peer-to-peer / link-local helpers — not useful for WAN dial.
            if name.hasPrefix("awdl") || name.hasPrefix("llw") || name.hasPrefix("ap") {
                continue
            }

            let idx = if_nametoindex(name)
            guard idx > 0 else { continue }
            seen.insert(name)

            let type: Int32
            if name.hasPrefix("en") {
                // en0 is usually Wi-Fi on iPhone; treat as WIFI for Libbox strategy.
                type = LibboxInterfaceTypeWIFI
            } else if name.hasPrefix("pdp_ip") || name.hasPrefix("pdp_") {
                type = LibboxInterfaceTypeCellular
            } else if name.hasPrefix("utun") || name.hasPrefix("ipsec") || name.hasPrefix("ip4") {
                type = LibboxInterfaceTypeOther
            } else {
                type = LibboxInterfaceTypeOther
            }

            // Always advertise UP|RUNNING so Libbox's FlagUp filter keeps us.
            let flags = rawFlags | IFF_UP | IFF_RUNNING
            result.append(Entry(name: name, index: Int32(idx), flags: flags, libboxType: type))
        }
        return result
    }

    /// Prefer Wi-Fi, then cellular; never utun/ipsec.
    static func preferredUnderlay(excluding excluded: String? = nil) -> Entry? {
        let all = enumerate(excluding: excluded)
        let usable = all.filter {
            $0.libboxType == LibboxInterfaceTypeWIFI || $0.libboxType == LibboxInterfaceTypeCellular
        }
        if let wifi = usable.first(where: { $0.libboxType == LibboxInterfaceTypeWIFI }) {
            return wifi
        }
        if let cell = usable.first(where: { $0.libboxType == LibboxInterfaceTypeCellular }) {
            return cell
        }
        // Last resort: any non-utun
        return all.first {
            !$0.name.hasPrefix("utun") && !$0.name.hasPrefix("ipsec")
        }
    }

    static func summary(excluding excluded: String? = nil) -> String {
        enumerate(excluding: excluded)
            .map { "\($0.name)#\($0.index)/t\($0.libboxType)" }
            .joined(separator: ", ")
    }
}
