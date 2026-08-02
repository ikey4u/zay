import Darwin
import Foundation
import NetworkExtension

/// Bridges `NEPacketTunnelFlow` to two userspace TUN ends (EasyTier + sing-box).
///
/// ```
/// packetFlow.readPackets
///   ├─ mesh CIDR  → EasyTier socketpair
///   └─ otherwise  → sing-box socketpair
///
/// EasyTier / sing-box writes → packetFlow.writePackets
/// ```
final class PacketDispatcher {
    private let packetFlow: NEPacketTunnelFlow
    private let meshHostFD: Int32
    private let proxyHostFD: Int32
    let easyTierEngineFD: Int32
    let singboxEngineFD: Int32

    private let queue = DispatchQueue(label: "dev.zay.ios.dispatcher", qos: .userInitiated)
    private var meshSource: DispatchSourceRead?
    private var proxySource: DispatchSourceRead?
    private let lock = NSLock()
    private var meshRanges: [IPv4CIDR] = []
    private var running = false
    private var meshIn: UInt64 = 0
    private var proxyIn: UInt64 = 0
    private var meshOut: UInt64 = 0
    private var proxyOut: UInt64 = 0
    private var lastStatsLog = Date.distantPast

    private init(
        packetFlow: NEPacketTunnelFlow,
        meshHostFD: Int32,
        easyTierEngineFD: Int32,
        proxyHostFD: Int32,
        singboxEngineFD: Int32,
        meshCIDRs: [String]
    ) {
        self.packetFlow = packetFlow
        self.meshHostFD = meshHostFD
        self.easyTierEngineFD = easyTierEngineFD
        self.proxyHostFD = proxyHostFD
        self.singboxEngineFD = singboxEngineFD
        self.meshRanges = meshCIDRs.compactMap { IPv4CIDR(cidr: $0) }
    }

    deinit {
        stop()
    }

    static func create(packetFlow: NEPacketTunnelFlow, meshCIDRs: [String]) throws -> PacketDispatcher {
        var et = [Int32](repeating: -1, count: 2)
        var sb = [Int32](repeating: -1, count: 2)
        guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &et) == 0 else {
            throw NSError(domain: "zay", code: 50, userInfo: [NSLocalizedDescriptionKey: "socketpair EasyTier failed: \(errno)"])
        }
        guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &sb) == 0 else {
            close(et[0]); close(et[1])
            throw NSError(domain: "zay", code: 51, userInfo: [NSLocalizedDescriptionKey: "socketpair sing-box failed: \(errno)"])
        }
        for fd in [et[0], et[1], sb[0], sb[1]] {
            let flags = fcntl(fd, F_GETFL)
            _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
            // Avoid SIGPIPE on send.
            var on: Int32 = 1
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
        }
        // Enlarge buffers for bursty TUN traffic.
        var buf: Int32 = 1024 * 1024
        for fd in [et[0], et[1], sb[0], sb[1]] {
            setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf, socklen_t(MemoryLayout<Int32>.size))
            setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf, socklen_t(MemoryLayout<Int32>.size))
        }

        ZayLog.info(
            "PacketDispatcher socketpairs et=[\(et[0]),\(et[1])] sb=[\(sb[0]),\(sb[1])] mesh=\(meshCIDRs)"
        )
        return PacketDispatcher(
            packetFlow: packetFlow,
            meshHostFD: et[0],
            easyTierEngineFD: et[1],
            proxyHostFD: sb[0],
            singboxEngineFD: sb[1],
            meshCIDRs: meshCIDRs
        )
    }

    func updateMeshCIDRs(_ cidrs: [String]) {
        let parsed = cidrs.compactMap { IPv4CIDR(cidr: $0) }
        lock.lock()
        meshRanges = parsed
        lock.unlock()
        ZayLog.info("PacketDispatcher mesh CIDRs → \(parsed.map(\.raw).joined(separator: ","))")
    }

    func start() {
        lock.lock()
        defer { lock.unlock() }
        guard !running else { return }
        running = true

        // Engine → device
        meshSource = makeReadSource(fd: meshHostFD, label: "mesh") { [weak self] packet in
            self?.writeToFlow(packet, isMesh: true)
        }
        proxySource = makeReadSource(fd: proxyHostFD, label: "proxy") { [weak self] packet in
            self?.writeToFlow(packet, isMesh: false)
        }
        meshSource?.resume()
        proxySource?.resume()

        // Device → engines (async read loop)
        pumpPacketFlow()
        ZayLog.info("PacketDispatcher started")
    }

    func stop() {
        lock.lock()
        running = false
        meshSource?.cancel()
        proxySource?.cancel()
        meshSource = nil
        proxySource = nil
        lock.unlock()

        // Host ends are ours. Engine ends were handed to EasyTier / sing-box;
        // close them after engines stop (caller ordering). Ignore EBADF.
        close(meshHostFD)
        close(proxyHostFD)
        if easyTierEngineFD >= 0 { close(easyTierEngineFD) }
        if singboxEngineFD >= 0 { close(singboxEngineFD) }
        ZayLog.info(
            "PacketDispatcher stopped stats meshIn=\(meshIn) proxyIn=\(proxyIn) meshOut=\(meshOut) proxyOut=\(proxyOut)"
        )
    }

    // MARK: - Private

    private func makeReadSource(fd: Int32, label: String, onPacket: @escaping (Data) -> Void) -> DispatchSourceRead {
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        source.setEventHandler { [weak self] in
            guard let self else { return }
            var buffer = [UInt8](repeating: 0, count: 65535)
            while true {
                let n = recv(fd, &buffer, buffer.count, 0)
                if n > 0 {
                    onPacket(Data(buffer[0..<n]))
                    continue
                }
                if n < 0 && errno == EWOULDBLOCK { break }
                if n < 0 && errno == EAGAIN { break }
                if n == 0 { break }
                if n < 0 {
                    ZayLog.debug("dispatcher recv \(label) errno=\(errno)")
                    break
                }
            }
        }
        source.setCancelHandler {
            // FD ownership stays with PacketDispatcher.stop()
        }
        return source
    }

    private func pumpPacketFlow() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self else { return }
            self.lock.lock()
            let alive = self.running
            let ranges = self.meshRanges
            self.lock.unlock()
            guard alive else { return }

            for packet in packets {
                let toMesh = IPPacket.isMesh(packet, ranges: ranges)
                let fd = toMesh ? self.meshHostFD : self.proxyHostFD
                let ok = self.sendPacket(packet, to: fd)
                if ok {
                    if toMesh { self.meshIn += 1 } else { self.proxyIn += 1 }
                }
            }
            self.maybeLogStats()
            // Re-arm
            self.lock.lock()
            let still = self.running
            self.lock.unlock()
            if still {
                self.pumpPacketFlow()
            }
        }
    }

    private func writeToFlow(_ packet: Data, isMesh: Bool) {
        let proto: NSNumber = NSNumber(value: AF_INET) // IPv4; IPv6 mesh rare for EasyTier VIP
        // Detect v6 for protocol tag.
        let p: NSNumber
        if packet.count >= 1, (packet[0] >> 4) == 6 {
            p = NSNumber(value: AF_INET6)
        } else {
            p = proto
        }
        packetFlow.writePackets([packet], withProtocols: [p])
        if isMesh { meshOut += 1 } else { proxyOut += 1 }
        maybeLogStats()
    }

    private func sendPacket(_ packet: Data, to fd: Int32) -> Bool {
        let result = packet.withUnsafeBytes { raw -> Int in
            guard let base = raw.baseAddress else { return -1 }
            return send(fd, base, packet.count, 0)
        }
        if result < 0 {
            if errno != EWOULDBLOCK && errno != EAGAIN {
                ZayLog.debug("dispatcher send fd=\(fd) errno=\(errno) len=\(packet.count)")
            }
            return false
        }
        return true
    }

    private func maybeLogStats() {
        let now = Date()
        guard now.timeIntervalSince(lastStatsLog) >= 10 else { return }
        lastStatsLog = now
        ZayLog.info(
            "dispatcher stats meshIn=\(meshIn) proxyIn=\(proxyIn) meshOut=\(meshOut) proxyOut=\(proxyOut) cidrs=\(meshRanges.map(\.raw))"
        )
    }
}
