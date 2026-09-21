import Darwin
import Foundation
import Network
import NetworkExtension

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var platform: TunnelPlatformInterface?
    private var config: ZayRuntimeConfig = .empty
    private var proxyBridge: ProxyCommandBridge?
    /// EasyTier currently running in this extension process.
    private var meshRunning = false
    /// Cleared on user stop / teardown so no asynchronous path can resurrect Mesh.
    private var meshAllowed = true
    /// Serializes EasyTier start/stop/status. `mesh-enable` previously used a
    /// concurrent global queue and could overlap with sleep/wake/teardown.
    private static let meshQueueKey = DispatchSpecificKey<UInt8>()
    private let meshQueue: DispatchQueue = {
        let queue = DispatchQueue(label: "zay.mesh")
        queue.setSpecific(key: PacketTunnelProvider.meshQueueKey, value: 1)
        return queue
    }()

    private func withMeshQueue<T>(_ body: () throws -> T) rethrows -> T {
        if DispatchQueue.getSpecific(key: Self.meshQueueKey) != nil {
            return try body()
        }
        return try meshQueue.sync(execute: body)
    }

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        AppGroup.ensureLogDirectory()
        ZayLog.setupNativeLogPath()
        ZayLog.info("PacketTunnelProvider.startTunnel (sing-box TUN + EasyTier SOCKS)")

        guard let cfg = resolveConfig(options: options), cfg.isValid else {
            let err = NSError(
                domain: "zay",
                code: 10,
                userInfo: [NSLocalizedDescriptionKey: "missing or invalid tunnel config"]
            )
            ZayLog.error(err.localizedDescription)
            completionHandler(err)
            return
        }
        config = cfg
        cfg.save()
        meshAllowed = true

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                try self?.bootstrap(config: cfg)
                DispatchQueue.main.async { completionHandler(nil) }
            } catch {
                ZayLog.error("bootstrap failed: \(error.localizedDescription)")
                self?.writeLastFailure(error.localizedDescription)
                self?.teardownRuntime(reason: "bootstrap-failed", finalStop: true)
                DispatchQueue.main.async { completionHandler(error) }
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        let label = Self.stopReasonLabel(reason)
        ZayLog.info("stopTunnel reason=\(reason.rawValue) (\(label))")
        // Persist unexpected exits so the app can show why the tunnel died in background.
        if Self.isUnexpectedStop(reason) {
            writeLastFailure("隧道退出: \(label) (code=\(reason.rawValue))")
        }
        teardownRuntime(reason: "stopTunnel:\(label)", finalStop: true)
        completionHandler()
    }

    /// The packet tunnel owns background connectivity. App/UI suspension must not stop either
    /// sing-box or EasyTier; otherwise locking the device would break proxy and Mesh traffic.
    override func sleep(completionHandler: @escaping () -> Void) {
        ZayLog.info("NE sleep notification — keep sing-box and Mesh running")
        completionHandler()
    }

    /// User disconnect / final teardown: Mesh must not come back via wake.
    private func stopMeshFully(reason: String) {
        withMeshQueue {
            meshAllowed = false
            ZayNative.stopMesh()
            let wasRunning = meshRunning
            meshRunning = false
            ZayLog.info("Mesh fully stopped (\(reason)) wasRunning=\(wasRunning)")
        }
    }

    override func wake() {
        ZayLog.info("NE wake notification — runtimes remained active")
    }

    private static func stopReasonLabel(_ reason: NEProviderStopReason) -> String {
        switch reason {
        case .none: return "none"
        case .userInitiated: return "userInitiated"
        case .providerFailed: return "providerFailed"
        case .noNetworkAvailable: return "noNetworkAvailable"
        case .unrecoverableNetworkChange: return "unrecoverableNetworkChange"
        case .providerDisabled: return "providerDisabled"
        case .authenticationCanceled: return "authenticationCanceled"
        case .configurationFailed: return "configurationFailed"
        case .idleTimeout: return "idleTimeout"
        case .configurationDisabled: return "configurationDisabled"
        case .configurationRemoved: return "configurationRemoved"
        case .superceded: return "superceded"
        case .userLogout: return "userLogout"
        case .userSwitch: return "userSwitch"
        case .connectionFailed: return "connectionFailed"
        case .sleep: return "sleep"
        case .appUpdate: return "appUpdate"
        case .internalError: return "internalError"
        @unknown default: return "unknown(\(reason.rawValue))"
        }
    }

    private static func isUnexpectedStop(_ reason: NEProviderStopReason) -> Bool {
        switch reason {
        case .userInitiated, .providerDisabled, .configurationDisabled,
             .configurationRemoved, .superceded, .userLogout, .userSwitch,
             .appUpdate, .none:
            return false
        default:
            return true
        }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        let req = String(data: messageData, encoding: .utf8) ?? ""
        ZayLog.debug("handleAppMessage: \(req)")
        if req == "status" {
            let json = withMeshQueue { ZayNative.meshStatusJSON() }
            completionHandler?(json.data(using: .utf8))
            return
        }
        if req == "stop-mesh" {
            // App disconnect: kill EasyTier and forbid wake/hot-start until next startTunnel.
            stopMeshFully(reason: "app-stop-mesh")
            completionHandler?(#"{"ok":true}"#.data(using: .utf8))
            return
        }
        if req == "logs" {
            // Keep IPC payload small — large replies can jetsam the extension.
            completionHandler?(ZayLog.readTail(maxBytes: 32_000).data(using: .utf8))
            return
        }
        if req == "diag" {
            completionHandler?(ZayLog.diagnosticReport(config: config).data(using: .utf8))
            return
        }
        if req == "proxy-groups" {
            let live = proxyBridge?.snapshotJSON() ?? #"{"groups":[]}"#
            completionHandler?(live.data(using: .utf8))
            return
        }
        if req == "proxy-urltest" {
            do {
                // Prefer conventional group names, then probe any configured group.
                if let err = proxyBridge?.urlTestBestEffort() {
                    throw err
                }
                completionHandler?(#"{"ok":true}"#.data(using: .utf8))
            } catch {
                let body = #"{"ok":false,"error":"\#(Self.jsonEscape(error.localizedDescription))"}"#
                completionHandler?(body.data(using: .utf8))
            }
            return
        }
        if req.hasPrefix("proxy-select:") {
            let tag = String(req.dropFirst("proxy-select:".count))
            do {
                try proxyBridge?.selectOutbound(outboundTag: tag)
                config.selectedProxyTag = tag
                config.save()
                completionHandler?(#"{"ok":true}"#.data(using: .utf8))
            } catch {
                let body = #"{"ok":false,"error":"\#(Self.jsonEscape(error.localizedDescription))"}"#
                completionHandler?(body.data(using: .utf8))
            }
            return
        }
        completionHandler?(nil)
    }

    private static func jsonEscape(_ s: String) -> String {
        s.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: " ")
    }

    private func resolveConfig(options: [String: NSObject]?) -> ZayRuntimeConfig? {
        if let fromOptions = ZayRuntimeConfig.from(tunnelOptions: options), fromOptions.isValid {
            ZayLog.info("config source=tunnelOptions")
            return fromOptions
        }
        if let proto = protocolConfiguration as? NETunnelProviderProtocol,
           let json = proto.providerConfiguration?["configJSON"] as? String,
           let data = json.data(using: .utf8),
           let cfg = try? JSONDecoder().decode(ZayRuntimeConfig.self, from: data),
           cfg.isValid {
            ZayLog.info("config source=providerConfiguration")
            return cfg
        }
        let loaded = ZayRuntimeConfig.load()
        ZayLog.info("config source=appGroup valid=\(loaded.isValid)")
        return loaded
    }

    private func bootstrap(config: ZayRuntimeConfig) throws {
        // Drop leftovers from a previous failed start in this process.
        teardownRuntime(reason: "bootstrap-reset", finalStop: false)
        clearLastFailure()

        ZayLog.info("bootstrap begin meshEnabled=\(config.meshEnabled)")
        ZayLog.info("proxy=\(ZayLog.redactedEndpoint(config.proxyURL))")
        ZayLog.info("relay=\(ZayLog.redactedEndpoint(config.relayURL))")
        ZayLog.info("network=\(config.networkName)")
        ZayLog.info("socks_port=\(config.socksPort)")
        ZayLog.info("selected_proxy=\(config.resolvedSelectedProxyTag)")

        var meshCIDRs: [String] = []
        var bypass: [String] = []

        if config.meshEnabled {
            meshCIDRs = try startMeshRuntime(config: config)
            bypass = try ZayNative.relayBypassTargets(from: config.relayURL)
            ZayLog.info("bypass relay targets: \(bypass)")
        } else {
            ZayLog.info("Mesh disabled — proxy-only tunnel")
        }

        let workingURL = AppGroup.workingDirectory
            ?? URL(fileURLWithPath: NSTemporaryDirectory())
        let working = workingURL.path
        try? FileManager.default.createDirectory(atPath: working, withIntermediateDirectories: true)

        try ZayNative.ensureEmbeddedRules(workingDir: working)
        ZayLog.info("embedded clash-rules ready under \(working)/ruleset-embedded")

        // Large mobile sets are build-time compiled to SRS, so the complete
        // profile can load once without source-JSON expansion or TUN reloads.
        let initialRulesStage = RulesProgress.maxStage
        RulesProgress.attempting = nil

        // A single cold start preserves the Network Extension's TUN FD and
        // PacketDispatcher for the complete lifetime of this tunnel session.
        let singboxJSON = try ZayNative.buildSingboxJSON(
            config: config,
            meshCIDRs: meshCIDRs,
            bypassIPs: bypass,
            workingDir: working,
            rulesProfile: RulesProgress.profileString(initialRulesStage),
            preferCache: false
        )
        ZayLog.info("sing-box cold-start stage\(initialRulesStage) config \(singboxJSON.count) bytes")

        let url = workingURL.appendingPathComponent("config.json")
        try? singboxJSON.write(to: url, atomically: true, encoding: .utf8)
        ZayLog.info("wrote \(url.path)")

        // Stale cache.db from a previous killed start can stall reload.
        let cacheURL = workingURL.appendingPathComponent("cache.db")
        try? FileManager.default.removeItem(at: cacheURL)

        let platform = TunnelPlatformInterface(provider: self)
        self.platform = platform
        let context = Unmanaged.passUnretained(platform).toOpaque()
        ZayLog.info("Rust singbox start begin stage\(initialRulesStage) (\(singboxJSON.count) bytes)")
        try ZayNative.startSingbox(
            json: singboxJSON,
            basePath: working,
            openTun: zayOpenTunCallback,
            context: context
        )
        ZayLog.info("Rust singbox library started")

        let bridge = ProxyCommandBridge()
        self.proxyBridge = bridge

        // Apply persisted selector preference after groups come up.
        let preferred = config.resolvedSelectedProxyTag
        if preferred != "Auto" {
            DispatchQueue.global().asyncAfter(deadline: .now() + 1.5) {
                try? bridge.selectOutbound(outboundTag: preferred)
            }
        }

        RulesProgress.maxOk = initialRulesStage
        RulesProgress.failed = nil
        clearLastFailure()
        ZayLog.info("bootstrap complete mesh=\(meshRunning) rules maxOk=\(RulesProgress.maxOk) failed=\(RulesProgress.failed.map(String.init) ?? "nil")")
    }

    /// Start EasyTier SOCKS portal; returns mesh CIDRs for sing-box routing.
    @discardableResult
    private func startMeshRuntime(config: ZayRuntimeConfig) throws -> [String] {
        try withMeshQueue {
            guard meshAllowed else {
                ZayLog.warn("startMeshRuntime skipped — mesh not allowed")
                return []
            }
            let toml = try ZayNative.buildEasytierTOML(config: config)
            ZayLog.debug("easytier config generated (\(toml.count) bytes)")
            try ZayNative.startMesh(toml: toml)
            guard meshAllowed else {
                ZayNative.stopMesh()
                meshRunning = false
                ZayLog.warn("Mesh started then immediately stopped (disallowed)")
                return []
            }
            meshRunning = true
            ZayLog.info("EasyTier started (no_tun + SOCKS)")

            var meshCIDRs = [config.meshCIDRHint].filter { !$0.isEmpty }
            let fixedIP = config.meshIPv4.trimmingCharacters(in: .whitespacesAndNewlines)
            if !fixedIP.isEmpty, let cidr = IPv4CIDR(cidr: fixedIP) {
                meshCIDRs = [cidr.raw]
            }
            if fixedIP.isEmpty {
                for attempt in 1...3 {
                    guard meshAllowed else {
                        ZayNative.stopMesh()
                        meshRunning = false
                        ZayLog.warn("Mesh aborted during VIP wait (disallowed)")
                        return []
                    }
                    Thread.sleep(forTimeInterval: 1.0)
                    let status = ZayNative.meshStatusJSON()
                    ZayLog.info("mesh status[\(attempt)]: \(status)")
                    if let cidr = Self.extractMeshCIDR(from: status) {
                        meshCIDRs = [cidr]
                        ZayLog.info("detected mesh CIDR: \(cidr)")
                        break
                    }
                }
            }
            guard meshAllowed else {
                ZayNative.stopMesh()
                meshRunning = false
                ZayLog.warn("Mesh aborted after VIP wait (disallowed)")
                return []
            }
            ZayLog.info("mesh CIDRs for routing=\(meshCIDRs)")
            return meshCIDRs
        }
    }

    /// Stop Rust singbox / EasyTier / monitors. Safe to call repeatedly.
    /// - Parameter finalStop: user/system tear-down; blocks `wake` from resurrecting Mesh.
    ///   Bootstrap reset passes `false` so Mesh can start immediately after.
    private func teardownRuntime(reason: String, finalStop: Bool) {
        ZayLog.info("teardownRuntime (\(reason)) finalStop=\(finalStop)")
        if finalStop {
            meshAllowed = false
        }
        proxyBridge?.stop()
        proxyBridge = nil
        ZayNative.stopSingbox()
        platform?.reset()
        platform = nil
        withMeshQueue {
            if finalStop {
                meshAllowed = false
            }
            ZayNative.stopMesh()
            meshRunning = false
        }
        ZayLog.info("teardownRuntime done")
    }

    private static func extractMeshCIDR(from statusJSON: String) -> String? {
        guard let data = statusJSON.data(using: .utf8),
              let arr = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]]
        else { return nil }
        for item in arr {
            if let cidr = item["mesh_cidr"] as? String, !cidr.isEmpty {
                return IPv4CIDR(cidr: cidr)?.raw ?? cidr
            }
            if let vip = item["virtual_ipv4"] as? String, !vip.isEmpty {
                return IPv4CIDR(cidr: vip)?.raw
            }
        }
        return nil
    }

    private func writeLastFailure(_ message: String) {
        guard let url = AppGroup.lastFailureFileURL else { return }
        let body = "[\(ISO8601DateFormatter().string(from: Date()))] \(message)\n"
        try? body.write(to: url, atomically: true, encoding: .utf8)
    }

    private func clearLastFailure() {
        guard let url = AppGroup.lastFailureFileURL else { return }
        try? FileManager.default.removeItem(at: url)
    }
}

// MARK: - Rust singbox TUN host

private struct RustTunRequest: Decodable {
    let tag: String
    let mtu: UInt16
    let addresses: [String]
    let routes: [String]
    let dnsServers: [String]

    enum CodingKeys: String, CodingKey {
        case tag, mtu, addresses, routes
        case dnsServers = "dns_servers"
    }
}

@_cdecl("zayOpenTunCallback")
private func zayOpenTunCallback(
    context: UnsafeMutableRawPointer?,
    requestJSON: UnsafePointer<CChar>?
) -> Int32 {
    guard let context, let requestJSON else { return -1 }
    let platform = Unmanaged<TunnelPlatformInterface>
        .fromOpaque(context)
        .takeUnretainedValue()
    return platform.openTun(requestJSON: String(cString: requestJSON))
}

/// Applies Network Extension settings requested by the Rust library and
/// transfers a dup(2)'d packet-flow bridge descriptor back to Rust.
final class TunnelPlatformInterface {
    private weak var provider: NEPacketTunnelProvider?
    private var networkSettings: NEPacketTunnelNetworkSettings?
    private var packetDispatcher: PacketDispatcher?

    init(provider: NEPacketTunnelProvider) {
        self.provider = provider
    }

    func reset() {
        packetDispatcher?.stop()
        packetDispatcher = nil
        networkSettings = nil
        provider = nil
    }

    func openTun(requestJSON: String) -> Int32 {
        guard let provider else {
            ZayLog.error("Rust openTun: provider released")
            return -1
        }
        do {
            let request = try JSONDecoder().decode(
                RustTunRequest.self,
                from: Data(requestJSON.utf8)
            )
            try applyTunnelSettings(request: request, provider: provider)
            // Use only NetworkExtension's public packetFlow API. The engine
            // side of this datagram socketpair carries one bare IP packet per
            // datagram; Rust configures rust-tun with packet_information=false.
            // Mesh CIDRs are intentionally empty here because singbox itself
            // routes them to EasyTier's local SOCKS portal.
            packetDispatcher?.stop()
            let dispatcher = try PacketDispatcher.create(
                packetFlow: provider.packetFlow,
                meshCIDRs: []
            )
            dispatcher.start()
            let ownedFD = Darwin.dup(dispatcher.singboxEngineFD)
            guard ownedFD >= 0 else {
                dispatcher.stop()
                throw NSError(
                    domain: NSPOSIXErrorDomain,
                    code: Int(errno),
                    userInfo: [NSLocalizedDescriptionKey: "dup(packetFlow bridge) failed"]
                )
            }
            packetDispatcher = dispatcher
            ZayLog.info(
                "Rust openTun packetFlow bridge tag=\(request.tag) mtu=\(request.mtu) fd=\(ownedFD)"
            )
            return ownedFD
        } catch {
            ZayLog.error("Rust openTun failed: \(error.localizedDescription)")
            return -1
        }
    }

    private func applyTunnelSettings(
        request: RustTunRequest,
        provider: NEPacketTunnelProvider
    ) throws {
        let settings = NEPacketTunnelNetworkSettings(
            tunnelRemoteAddress: "127.0.0.1"
        )
        settings.mtu = NSNumber(value: request.mtu)

        let v4Addresses = request.addresses.compactMap(Self.ipv4Prefix)
        if !v4Addresses.isEmpty {
            let ipv4 = NEIPv4Settings(
                addresses: v4Addresses.map(\.address),
                subnetMasks: v4Addresses.map(\.mask)
            )
            ipv4.includedRoutes = request.routes
                .compactMap(Self.ipv4Prefix)
                .map {
                    NEIPv4Route(
                        destinationAddress: $0.address,
                        subnetMask: $0.mask
                    )
                }
            settings.ipv4Settings = ipv4
        }

        let v6Addresses = request.addresses.compactMap(Self.ipv6Prefix)
        if !v6Addresses.isEmpty {
            let ipv6 = NEIPv6Settings(
                addresses: v6Addresses.map(\.address),
                networkPrefixLengths: v6Addresses.map {
                    NSNumber(value: $0.prefix)
                }
            )
            ipv6.includedRoutes = request.routes
                .compactMap(Self.ipv6Prefix)
                .map {
                    NEIPv6Route(
                        destinationAddress: $0.address,
                        networkPrefixLength: NSNumber(value: $0.prefix)
                    )
                }
            settings.ipv6Settings = ipv6
        }

        if !request.dnsServers.isEmpty {
            let dns = NEDNSSettings(servers: request.dnsServers)
            dns.matchDomains = [""]
            settings.dnsSettings = dns
        }
        networkSettings = settings

        let semaphore = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var applyError: Error?
        provider.setTunnelNetworkSettings(settings) { error in
            lock.lock()
            applyError = error
            lock.unlock()
            semaphore.signal()
        }
        guard semaphore.wait(timeout: .now() + 15) == .success else {
            throw NSError(
                domain: "zay",
                code: 42,
                userInfo: [NSLocalizedDescriptionKey: "Applying tunnel settings timed out"]
            )
        }
        lock.lock()
        let result = applyError
        lock.unlock()
        if let result { throw result }
        ZayLog.info("Rust tunnel network settings applied")
    }

    private static func ipv4Prefix(_ value: String) -> (
        address: String,
        mask: String
    )? {
        let parts = value.split(separator: "/", maxSplits: 1).map(String.init)
        guard parts.count == 2,
              parts[0].contains("."),
              let prefix = Int(parts[1]),
              (0...32).contains(prefix)
        else { return nil }
        let mask = prefix == 0 ? UInt32(0) : UInt32.max << (32 - prefix)
        return (
            parts[0],
            [
                String((mask >> 24) & 0xff),
                String((mask >> 16) & 0xff),
                String((mask >> 8) & 0xff),
                String(mask & 0xff),
            ].joined(separator: ".")
        )
    }

    private static func ipv6Prefix(_ value: String) -> (
        address: String,
        prefix: Int
    )? {
        let parts = value.split(separator: "/", maxSplits: 1).map(String.init)
        guard parts.count == 2,
              parts[0].contains(":"),
              let prefix = Int(parts[1]),
              (0...128).contains(prefix)
        else { return nil }
        return (parts[0], prefix)
    }
}
