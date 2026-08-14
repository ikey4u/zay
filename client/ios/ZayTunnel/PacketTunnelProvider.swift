import Darwin
import Foundation
import Network
import NetworkExtension
import Libbox

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var commandServer: LibboxCommandServer?
    private var platform: TunnelPlatformInterface?
    private var config: ZayRuntimeConfig = .empty
    private var proxyBridge: ProxyCommandBridge?
    /// Progressive rules reload state.
    private var lastMeshCIDRs: [String] = []
    private var lastBypassIPs: [String] = []
    private var workingDirPath: String = ""
    private var currentRulesStage: Int = 0
    private var rulesReloadWorkItem: DispatchWorkItem?
    /// EasyTier currently running in this extension process.
    private var meshRunning = false
    /// Stopped Mesh in `sleep`; restore on `wake` if still enabled.
    private var meshSuspendedBySleep = false
    /// Cleared on user stop / teardown so `wake` cannot resurrect Mesh after disconnect.
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
        // User/config stop: clear in-flight probe so the next start does not treat it as jetsam.
        if Self.clearsRulesProbe(reason) {
            RulesProgress.attempting = nil
        }
        // Persist unexpected exits so the app can show why the tunnel died in background.
        if Self.isUnexpectedStop(reason) {
            writeLastFailure("隧道退出: \(label) (code=\(reason.rawValue))")
        }
        teardownRuntime(reason: "stopTunnel:\(label)", finalStop: true)
        completionHandler()
    }

    /// Required when `disconnectOnSleep = false` so iOS keeps the extension alive across lock/sleep.
    override func sleep(completionHandler: @escaping () -> Void) {
        ZayLog.info("NE sleep (pause Libbox; suspend Mesh)")
        proxyBridge?.stop()
        commandServer?.pause()
        withMeshQueue {
            if meshRunning {
                ZayNative.stopMesh()
                meshRunning = false
                meshSuspendedBySleep = true
                ZayLog.info("Mesh suspended for sleep")
            }
        }
        completionHandler()
    }

    /// User disconnect / final teardown: Mesh must not come back via wake.
    private func stopMeshFully(reason: String) {
        withMeshQueue {
            meshAllowed = false
            meshSuspendedBySleep = false
            ZayNative.stopMesh()
            let wasRunning = meshRunning
            meshRunning = false
            lastMeshCIDRs = []
            ZayLog.info("Mesh fully stopped (\(reason)) wasRunning=\(wasRunning)")
        }
    }

    /// Settings toggle: start/stop EasyTier without tearing down the proxy tunnel.
    private func hotSetMesh(enabled: Bool) -> String {
        withMeshQueue {
            // App already persisted the toggle; reload so relay/secret match the UI.
            config = ZayRuntimeConfig.load()
            config.meshEnabled = enabled
            config.save()

            do {
                if enabled {
                    guard config.meshConfigReady else {
                        return #"{"ok":false,"error":"请填写中继、网络名与密钥"}"#
                    }
                    meshAllowed = true
                    meshSuspendedBySleep = false
                    if meshRunning {
                        ZayNative.stopMesh()
                        meshRunning = false
                    }
                    let cidrs = try startMeshRuntime(config: config, updateRoutes: false)
                    if let host = ZayNative.relayHost(from: config.relayURL),
                       !lastBypassIPs.contains(host) {
                        lastBypassIPs.append(host)
                    }
                    lastMeshCIDRs = cidrs
                    try reloadSingboxMeshRoutes()
                    ZayLog.info("hot mesh-enable ok cidrs=\(cidrs)")
                    return #"{"ok":true,"enabled":true}"#
                } else {
                    ZayNative.stopMesh()
                    meshRunning = false
                    meshSuspendedBySleep = false
                    // Keep meshAllowed — tunnel still up; user may toggle on again.
                    lastMeshCIDRs = []
                    try reloadSingboxMeshRoutes()
                    ZayLog.info("hot mesh-disable ok")
                    return #"{"ok":true,"enabled":false}"#
                }
            } catch {
                ZayLog.error("hotSetMesh enabled=\(enabled): \(error.localizedDescription)")
                let msg = Self.jsonEscape(error.localizedDescription)
                return #"{"ok":false,"error":"\#(msg)"}"#
            }
        }
    }

    /// Reload current rules stage with updated mesh CIDRs (proxy stays up).
    private func reloadSingboxMeshRoutes() throws {
        guard let server = commandServer, !workingDirPath.isEmpty else {
            throw NSError(
                domain: "zay",
                code: 60,
                userInfo: [NSLocalizedDescriptionKey: "代理尚未就绪，无法热更新 Mesh 路由"]
            )
        }
        let stage = max(currentRulesStage, 0)
        let json = try ZayNative.buildSingboxJSON(
            config: config,
            meshCIDRs: lastMeshCIDRs,
            bypassIPs: lastBypassIPs,
            workingDir: workingDirPath,
            rulesProfile: RulesProgress.profileString(stage),
            preferCache: true
        )
        try server.startOrReloadService(json, options: LibboxOverrideOptions())
        ZayLog.info("sing-box mesh routes reloaded stage=\(stage) cidrs=\(lastMeshCIDRs)")
    }

    override func wake() {
        commandServer?.wake()
        withMeshQueue {
            ZayLog.info("NE wake meshAllowed=\(meshAllowed) suspended=\(meshSuspendedBySleep)")
            guard meshAllowed, meshSuspendedBySleep, config.meshEnabled else {
                if meshSuspendedBySleep, !meshAllowed {
                    meshSuspendedBySleep = false
                    ZayLog.info("skip Mesh resume — tunnel is stopping / stopped")
                }
                return
            }
            meshSuspendedBySleep = false
            do {
                try startMeshRuntime(config: config, updateRoutes: false)
                ZayLog.info("Mesh resumed after wake")
            } catch {
                ZayLog.warn("Mesh resume failed: \(error.localizedDescription)")
            }
        }
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

    /// Intentional stops should not convert an in-flight rules probe into a permanent cap.
    private static func clearsRulesProbe(_ reason: NEProviderStopReason) -> Bool {
        switch reason {
        case .userInitiated, .providerDisabled, .configurationDisabled,
             .configurationRemoved, .superceded, .userLogout, .userSwitch,
             .appUpdate:
            return true
        default:
            return false
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
        if req == "mesh-enable" {
            meshQueue.async { [weak self] in
                let result = self?.hotSetMesh(enabled: true) ?? #"{"ok":false,"error":"extension gone"}"#
                completionHandler?(result.data(using: .utf8))
            }
            return
        }
        if req == "mesh-disable" {
            meshQueue.async { [weak self] in
                let result = self?.hotSetMesh(enabled: false) ?? #"{"ok":false,"error":"extension gone"}"#
                completionHandler?(result.data(using: .utf8))
            }
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
                // Prefer Auto urltest group; fall back to Proxy selector / each item.
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
        ZayLog.info("proxy=\(config.proxyURL)")
        ZayLog.info("relay=\(config.relayURL)")
        ZayLog.info("network=\(config.networkName)")
        ZayLog.info("socks_port=\(config.socksPort)")
        ZayLog.info("selected_proxy=\(config.resolvedSelectedProxyTag)")

        meshSuspendedBySleep = false
        var meshCIDRs: [String] = []
        var bypass: [String] = []

        if config.meshEnabled {
            meshCIDRs = try startMeshRuntime(config: config, updateRoutes: false)
            if let host = ZayNative.relayHost(from: config.relayURL) {
                bypass.append(host)
                ZayLog.info("bypass relay host: \(host)")
            }
        } else {
            ZayLog.info("Mesh disabled — proxy-only tunnel")
        }

        let base = AppGroup.containerURL?.path ?? NSTemporaryDirectory()
        let workingURL = AppGroup.workingDirectory ?? URL(fileURLWithPath: base)
        let working = workingURL.path
        let tempURL = AppGroup.containerURL?.appendingPathComponent("tmp", isDirectory: true)
        let temp = tempURL?.path ?? NSTemporaryDirectory()
        try? FileManager.default.createDirectory(atPath: working, withIntermediateDirectories: true)
        try? FileManager.default.createDirectory(atPath: temp, withIntermediateDirectories: true)

        try ZayNative.ensureEmbeddedRules(workingDir: working)
        ZayLog.info("embedded clash-rules ready under \(working)/ruleset-embedded")

        RulesProgress.absorbCrashIfNeeded()
        self.lastMeshCIDRs = meshCIDRs
        self.lastBypassIPs = bypass
        self.workingDirPath = working
        self.currentRulesStage = 0

        // Cold start: stage 0 only. Larger sets load after TUN is up.
        let singboxJSON = try ZayNative.buildSingboxJSON(
            config: config,
            meshCIDRs: meshCIDRs,
            bypassIPs: bypass,
            workingDir: working,
            rulesProfile: RulesProgress.profileString(0),
            preferCache: false
        )
        ZayLog.info("sing-box stage0 config \(singboxJSON.count) bytes")
        ZayLog.debug("sing-box json:\n\(singboxJSON)")

        let url = workingURL.appendingPathComponent("config.json")
        try? singboxJSON.write(to: url, atomically: true, encoding: .utf8)
        ZayLog.info("wrote \(url.path)")

        let setup = LibboxSetupOptions()
        setup.basePath = base
        setup.workingPath = working
        setup.tempPath = temp
        setup.logMaxLines = 5000
        setup.debug = false
        setup.oomKillerEnabled = false
        setup.oomKillerDisabled = true
        var setupError: NSError?
        guard LibboxSetup(setup, &setupError) else {
            throw setupError ?? NSError(domain: "zay", code: 20, userInfo: [NSLocalizedDescriptionKey: "LibboxSetup failed"])
        }
        ZayLog.info("LibboxSetup ok base=\(base) working=\(working)")

        // Stale cache.db from a previous killed start can stall reload.
        let cacheURL = workingURL.appendingPathComponent("cache.db")
        try? FileManager.default.removeItem(at: cacheURL)

        let platform = TunnelPlatformInterface(provider: self)
        self.platform = platform

        var serverError: NSError?
        guard let server = LibboxNewCommandServer(platform, platform, &serverError) else {
            throw serverError ?? NSError(domain: "zay", code: 21, userInfo: [NSLocalizedDescriptionKey: "LibboxNewCommandServer failed"])
        }
        try server.start()
        self.commandServer = server
        ZayLog.info("CommandServer started")

        ZayLog.info("startOrReloadService begin stage0 (\(singboxJSON.count) bytes)")
        do {
            try server.startOrReloadService(singboxJSON, options: LibboxOverrideOptions())
        } catch {
            ZayLog.error("startOrReloadService failed: \(error.localizedDescription)")
            throw error
        }
        ZayLog.info("sing-box service started")

        let bridge = ProxyCommandBridge()
        self.proxyBridge = bridge

        // Apply persisted selector preference after groups come up.
        let preferred = config.resolvedSelectedProxyTag
        if preferred != "Auto" {
            DispatchQueue.global().asyncAfter(deadline: .now() + 1.5) {
                try? bridge.selectOutbound(outboundTag: preferred)
            }
        }

        // Progressive rules; Mesh already started above when enabled.
        scheduleProgressiveRules()
        clearLastFailure()
        ZayLog.info("bootstrap complete mesh=\(meshRunning) rules maxOk=\(RulesProgress.maxOk) failed=\(RulesProgress.failed.map(String.init) ?? "nil")")
    }

    /// Start EasyTier SOCKS portal; returns mesh CIDRs for sing-box routing.
    @discardableResult
    private func startMeshRuntime(config: ZayRuntimeConfig, updateRoutes: Bool) throws -> [String] {
        try withMeshQueue {
            guard meshAllowed else {
                ZayLog.warn("startMeshRuntime skipped — mesh not allowed")
                return []
            }
            let toml = try ZayNative.buildEasytierTOML(config: config)
            ZayLog.debug("easytier toml:\n\(toml)")
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
            lastMeshCIDRs = meshCIDRs
            if updateRoutes {
                try reloadSingboxMeshRoutes()
            }
            return meshCIDRs
        }
    }

    /// Walk rules stages upward: restore known-good, then probe the next set.
    private func scheduleProgressiveRules() {
        rulesReloadWorkItem?.cancel()
        rulesReloadWorkItem = nil

        let target: Int
        if RulesProgress.maxOk > currentRulesStage {
            target = RulesProgress.maxOk
        } else if let next = RulesProgress.nextCandidate(after: currentRulesStage) {
            target = next
        } else {
            ZayLog.info("rules progressive done at stage \(currentRulesStage)")
            return
        }

        let delay: TimeInterval = target <= RulesProgress.maxOk ? 2.0 : 4.0
        ZayLog.info("rules progressive schedule stage \(target) in \(delay)s")
        let work = DispatchWorkItem { [weak self] in
            self?.reloadRules(to: target)
        }
        rulesReloadWorkItem = work
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + delay, execute: work)
    }

    private func reloadRules(to stage: Int) {
        guard let server = commandServer, !workingDirPath.isEmpty else { return }
        let probing = stage > RulesProgress.maxOk
        if probing {
            RulesProgress.attempting = stage
        }
        ZayLog.info("progressive rules reload → stage \(stage) probing=\(probing)")
        do {
            let json = try ZayNative.buildSingboxJSON(
                config: config,
                meshCIDRs: lastMeshCIDRs,
                bypassIPs: lastBypassIPs,
                workingDir: workingDirPath,
                rulesProfile: RulesProgress.profileString(stage),
                preferCache: true
            )
            try server.startOrReloadService(json, options: LibboxOverrideOptions())
            currentRulesStage = stage
            ZayLog.info("rules stage \(stage) reload ok (\(json.count) bytes)")

            // Survival window: if jetsam happens here, absorbCrashIfNeeded caps the stage.
            let commitDelay: TimeInterval = probing ? 8.0 : 1.0
            let commit = DispatchWorkItem { [weak self] in
                guard let self, self.currentRulesStage == stage else { return }
                if probing {
                    RulesProgress.maxOk = stage
                    RulesProgress.attempting = nil
                    ZayLog.info("rules stage \(stage) committed")
                }
                self.scheduleProgressiveRules()
            }
            rulesReloadWorkItem = commit
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + commitDelay, execute: commit)
        } catch {
            ZayLog.error("rules stage \(stage) reload failed: \(error.localizedDescription)")
            if probing {
                RulesProgress.failed = stage
                RulesProgress.attempting = nil
            }
        }
    }

    /// Stop Libbox / EasyTier / monitors. Safe to call repeatedly.
    /// - Parameter finalStop: user/system tear-down; blocks `wake` from resurrecting Mesh.
    ///   Bootstrap reset passes `false` so Mesh can start immediately after.
    private func teardownRuntime(reason: String, finalStop: Bool) {
        ZayLog.info("teardownRuntime (\(reason)) finalStop=\(finalStop)")
        if finalStop {
            meshAllowed = false
        }
        rulesReloadWorkItem?.cancel()
        rulesReloadWorkItem = nil
        proxyBridge?.stop()
        proxyBridge = nil
        do {
            try commandServer?.closeService()
        } catch {
            ZayLog.warn("closeService: \(error.localizedDescription)")
        }
        commandServer?.close()
        commandServer = nil
        platform?.reset()
        platform = nil
        withMeshQueue {
            if finalStop {
                meshAllowed = false
            }
            ZayNative.stopMesh()
            meshRunning = false
            if finalStop {
                meshSuspendedBySleep = false
                lastMeshCIDRs = []
            }
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
        guard let url = AppGroup.containerURL?.appendingPathComponent("last-failure.txt") else { return }
        let body = "[\(ISO8601DateFormatter().string(from: Date()))] \(message)\n"
        try? body.write(to: url, atomically: true, encoding: .utf8)
    }

    private func clearLastFailure() {
        guard let url = AppGroup.containerURL?.appendingPathComponent("last-failure.txt") else { return }
        try? FileManager.default.removeItem(at: url)
    }
}

// MARK: - Libbox platform (aligned with official SFI openTun)

final class TunnelPlatformInterface: NSObject, LibboxPlatformInterfaceProtocol, LibboxCommandServerHandlerProtocol {
    weak var provider: NEPacketTunnelProvider?
    private var networkSettings: NEPacketTunnelNetworkSettings?
    private var defaultInterfaceMonitor: NWPathMonitor?
    private weak var interfaceListener: LibboxInterfaceUpdateListenerProtocol?
    /// Own Packet Tunnel utun name — never report as the default outbound interface.
    private var myTunName: String?
    private var lastDefaultIfaceName: String?
    private var lastGetInterfacesLog = Date.distantPast

    init(provider: NEPacketTunnelProvider) {
        self.provider = provider
        super.init()
    }

    func reset() {
        defaultInterfaceMonitor?.cancel()
        defaultInterfaceMonitor = nil
        interfaceListener = nil
        networkSettings = nil
        myTunName = nil
        lastDefaultIfaceName = nil
    }

    // MARK: CommandServerHandler

    func serviceStop() throws { ZayLog.info("serviceStop") }
    func serviceReload() throws { ZayLog.info("serviceReload") }

    func getSystemProxyStatus() throws -> LibboxSystemProxyStatus {
        let status = LibboxSystemProxyStatus()
        status.available = false
        status.enabled = false
        return status
    }

    func setSystemProxyEnabled(_ enabled: Bool) throws {
        ZayLog.debug("setSystemProxyEnabled=\(enabled)")
    }

    func triggerNativeCrash() throws {
        fatalError("triggerNativeCrash")
    }

    func writeDebugMessage(_ message: String?) {
        // sing-box may still push TRACE/DEBUG here even when log.level=info.
        // Drop entirely inside Packet Tunnel — rate-limited file writes still cost CPU/RAM.
        _ = message
    }

    func connectSSHAgent(_ ret0_: UnsafeMutablePointer<Int32>?) throws {
        throw NSError(domain: "zay", code: 30, userInfo: [NSLocalizedDescriptionKey: "ssh agent unsupported"])
    }

    // MARK: PlatformInterface

    func localDNSTransport() -> (any LibboxLocalDNSTransportProtocol)? { nil }
    func usePlatformAutoDetectControl() -> Bool { false }

    func autoDetectControl(_ fd: Int32) throws {
        ZayLog.debug("autoDetectControl fd=\(fd)")
    }

    func openTun(_ options: (any LibboxTunOptionsProtocol)?, ret0_: UnsafeMutablePointer<Int32>?) throws {
        ZayLog.info("openTun invoked")
        guard let provider, let options, let ret0_ else {
            throw NSError(domain: "zay", code: 40, userInfo: [NSLocalizedDescriptionKey: "openTun missing args"])
        }
        ZayLog.info("openTun begin (real utun FD)")

        try applyTunnelSettings(options: options, provider: provider)

        if let fd = provider.packetFlow.value(forKeyPath: "socket.fileDescriptor") as? Int32, fd >= 0 {
            ret0_.pointee = fd
            ZayLog.info("openTun → packetFlow fd=\(fd)")
            return
        }

        let libboxFd = LibboxGetTunnelFileDescriptor()
        if libboxFd >= 0 {
            ret0_.pointee = libboxFd
            ZayLog.info("openTun → LibboxGetTunnelFileDescriptor=\(libboxFd)")
            return
        }

        throw NSError(domain: "zay", code: 41, userInfo: [NSLocalizedDescriptionKey: "Missing tunnel file descriptor"])
    }

    private func applyTunnelSettings(
        options: any LibboxTunOptionsProtocol,
        provider: NEPacketTunnelProvider
    ) throws {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.mtu = NSNumber(value: options.getMTU())

        var v4Addrs: [String] = []
        var v4Masks: [String] = []
        if let inet4 = options.getInet4Address() {
            while inet4.hasNext() {
                if let p = inet4.next() {
                    v4Addrs.append(p.address())
                    v4Masks.append(p.mask())
                }
            }
        }
        if !v4Addrs.isEmpty {
            let ipv4 = NEIPv4Settings(addresses: v4Addrs, subnetMasks: v4Masks)
            var included: [NEIPv4Route] = []
            if options.getAutoRoute() {
                var hasRange = false
                if let ranges = options.getInet4RouteRange() {
                    while ranges.hasNext() {
                        if let p = ranges.next() {
                            included.append(NEIPv4Route(destinationAddress: p.address(), subnetMask: p.mask()))
                            hasRange = true
                        }
                    }
                }
                if !hasRange { included.append(.default()) }
            }
            ipv4.includedRoutes = included

            var excluded: [NEIPv4Route] = []
            if let excl = options.getInet4RouteExcludeAddress() {
                while excl.hasNext() {
                    if let p = excl.next() {
                        excluded.append(NEIPv4Route(destinationAddress: p.address(), subnetMask: p.mask()))
                    }
                }
            }
            ipv4.excludedRoutes = excluded
            settings.ipv4Settings = ipv4
        }

        var v6Addrs: [String] = []
        var v6Prefixes: [NSNumber] = []
        if let inet6 = options.getInet6Address() {
            while inet6.hasNext() {
                if let p = inet6.next() {
                    v6Addrs.append(p.address())
                    v6Prefixes.append(NSNumber(value: p.prefix()))
                }
            }
        }
        if !v6Addrs.isEmpty {
            let ipv6 = NEIPv6Settings(addresses: v6Addrs, networkPrefixLengths: v6Prefixes)
            if options.getAutoRoute() { ipv6.includedRoutes = [.default()] }
            settings.ipv6Settings = ipv6
        }

        var dnsServers: [String] = []
        if let dnsIt = try? options.getDNSServerAddress() {
            while dnsIt.hasNext() { dnsServers.append(dnsIt.next()) }
        }
        let dns = NEDNSSettings(servers: dnsServers.isEmpty ? ["1.1.1.1", "8.8.8.8"] : dnsServers)
        dns.matchDomains = [""]
        settings.dnsSettings = dns

        networkSettings = settings

        let sema = DispatchSemaphore(value: 0)
        var applyError: Error?
        provider.setTunnelNetworkSettings(settings) { err in
            applyError = err
            sema.signal()
        }
        _ = sema.wait(timeout: .now() + 15)
        if let applyError { throw applyError }
        ZayLog.info("tunnel network settings applied")
    }

    func useProcFS() -> Bool { false }

    func findConnectionOwner(
        _ ipProtocol: Int32,
        sourceAddress: String?,
        sourcePort: Int32,
        destinationAddress: String?,
        destinationPort: Int32
    ) throws -> LibboxConnectionOwner {
        throw NSError(domain: "zay", code: 42, userInfo: [NSLocalizedDescriptionKey: "findConnectionOwner unsupported"])
    }

    func startDefaultInterfaceMonitor(_ listener: (any LibboxInterfaceUpdateListenerProtocol)?) throws {
        ZayLog.info("startDefaultInterfaceMonitor begin")
        interfaceListener = listener
        let monitor = NWPathMonitor()
        let sema = DispatchSemaphore(value: 0)
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self, let listener = self.interfaceListener else { return }
            self.emitDefaultInterface(listener, path: path)
            sema.signal()
            monitor.pathUpdateHandler = { [weak self] path in
                guard let self, let listener = self.interfaceListener else { return }
                self.emitDefaultInterface(listener, path: path)
            }
        }
        monitor.start(queue: DispatchQueue.global(qos: .utility))
        _ = sema.wait(timeout: .now() + 2)
        defaultInterfaceMonitor = monitor
        ZayLog.info("default interface monitor started")
    }

    private func emitDefaultInterface(_ listener: LibboxInterfaceUpdateListenerProtocol, path: Network.NWPath) {
        // Prefer getifaddrs underlay — NWPath often only lists our utun once the
        // full tunnel is up, which Libbox then excludes → empty dial set.
        if let underlay = PhysicalNetworkInterfaces.preferredUnderlay(excluding: myTunName) {
            if lastDefaultIfaceName != underlay.name {
                lastDefaultIfaceName = underlay.name
                ZayLog.info(
                    "default interface: \(underlay.name) idx=\(underlay.index) (getifaddrs) pathStatus=\(path.status)"
                )
            }
            listener.updateDefaultInterface(
                underlay.name,
                interfaceIndex: underlay.index,
                isExpensive: path.isExpensive,
                isConstrained: path.isConstrained
            )
            return
        }

        guard path.status != .unsatisfied, let iface = preferredPhysicalInterface(on: path) else {
            if lastDefaultIfaceName != nil {
                lastDefaultIfaceName = nil
                ZayLog.warn("default interface: none (path=\(path.status))")
            }
            listener.updateDefaultInterface("", interfaceIndex: -1, isExpensive: false, isConstrained: false)
            return
        }
        if lastDefaultIfaceName != iface.name {
            lastDefaultIfaceName = iface.name
            ZayLog.info(
                "default interface: \(iface.name) idx=\(iface.index) type=\(iface.type) (NWPath fallback)"
            )
        }
        listener.updateDefaultInterface(
            iface.name,
            interfaceIndex: Int32(iface.index),
            isExpensive: path.isExpensive,
            isConstrained: path.isConstrained
        )
    }

    /// Physical underlay for outbound sockets; never prefer our own utun.
    private func preferredPhysicalInterface(on path: Network.NWPath) -> NWInterface? {
        let candidates = path.availableInterfaces.filter { iface in
            if let myTunName, iface.name == myTunName { return false }
            return true
        }
        let preferredOrder: [NWInterface.InterfaceType] = [.wifi, .cellular, .wiredEthernet]
        for type in preferredOrder {
            if let iface = candidates.first(where: { $0.type == type }) {
                return iface
            }
        }
        if let iface = candidates.first(where: { $0.type != .other }) {
            return iface
        }
        return candidates.first
    }

    func closeDefaultInterfaceMonitor(_ listener: (any LibboxInterfaceUpdateListenerProtocol)?) throws {
        defaultInterfaceMonitor?.cancel()
        defaultInterfaceMonitor = nil
        interfaceListener = nil
    }

    func getInterfaces() throws -> any LibboxNetworkInterfaceIteratorProtocol {
        // Source of truth: getifaddrs (includes en0/pdp_ip even when NWPath is utun-only).
        var byName: [String: LibboxNetworkInterface] = [:]
        for entry in PhysicalNetworkInterfaces.enumerate() {
            let iface = LibboxNetworkInterface()
            iface.name = entry.name
            iface.index = entry.index
            iface.flags = entry.flags
            iface.type = entry.libboxType
            byName[entry.name] = iface
        }

        // Enrich / merge types from NWPath when available.
        if let monitor = defaultInterfaceMonitor {
            let path = monitor.currentPath
            if path.status != .unsatisfied {
                let upFlags = Int32(IFF_UP | IFF_RUNNING)
                for it in path.availableInterfaces {
                    if byName[it.name] != nil { continue }
                    let iface = LibboxNetworkInterface()
                    iface.name = it.name
                    iface.index = Int32(it.index)
                    iface.flags = upFlags
                    switch it.type {
                    case .wifi: iface.type = LibboxInterfaceTypeWIFI
                    case .cellular: iface.type = LibboxInterfaceTypeCellular
                    case .wiredEthernet: iface.type = LibboxInterfaceTypeEthernet
                    default: iface.type = LibboxInterfaceTypeOther
                    }
                    byName[it.name] = iface
                }
            }
        }

        let interfaces = Array(byName.values)
        let now = Date()
        if now.timeIntervalSince(lastGetInterfacesLog) > 30 {
            lastGetInterfacesLog = now
            let summary = interfaces.map { "\($0.name ?? "?")#\($0.index)" }.joined(separator: ", ")
            ZayLog.debug("getInterfaces: [\(summary)] myTun=\(myTunName ?? "-")")
        }
        return NetworkInterfaceArray(interfaces)
    }

    func underNetworkExtension() -> Bool { true }
    func includeAllNetworks() -> Bool { false }
    func readWIFIState() -> LibboxWIFIState? { nil }
    func clearDNSCache() { ZayLog.debug("clearDNSCache") }

    func send(_ notification: LibboxNotification?) throws {
        ZayLog.info("notification: \(notification?.title ?? "") \(notification?.body ?? "")")
    }

    func startNeighborMonitor(_ listener: (any LibboxNeighborUpdateListenerProtocol)?) throws {}
    func closeNeighborMonitor(_ listener: (any LibboxNeighborUpdateListenerProtocol)?) throws {}
    func registerMyInterface(_ name: String?) {
        myTunName = name
        ZayLog.info("registerMyInterface: \(name ?? "")")
        // Re-emit default interface now that we know which name to exclude.
        if let monitor = defaultInterfaceMonitor, let listener = interfaceListener {
            emitDefaultInterface(listener, path: monitor.currentPath)
        }
    }

    func usePlatformShell() -> Bool { false }
    func checkPlatformShell() throws {}

    func openShellSession(
        _ user: LibboxPlatformUser?,
        command: String?,
        environ: (any LibboxStringIteratorProtocol)?,
        term: String?,
        rows: Int32,
        cols: Int32
    ) throws -> any LibboxShellSessionProtocol {
        throw NSError(domain: "zay", code: 43, userInfo: [NSLocalizedDescriptionKey: "shell unsupported"])
    }

    func lookupUser(_ username: String?) throws -> LibboxPlatformUser {
        throw NSError(domain: "zay", code: 47, userInfo: [NSLocalizedDescriptionKey: "lookupUser unsupported"])
    }

    func lookupSFTPServer(_ error: NSErrorPointer) -> String {
        error?.pointee = NSError(domain: "zay", code: 44, userInfo: [NSLocalizedDescriptionKey: "sftp unsupported"])
        return ""
    }

    func readSystemSSHHostKey(_ error: NSErrorPointer) -> String { "" }
    func tailscaleHostname() -> String { "" }
    func usePlatformBridge() -> Bool { false }

    func createBridge(_ options: LibboxBridgeOptions?) throws -> any LibboxBridgeSessionProtocol {
        throw NSError(domain: "zay", code: 45, userInfo: [NSLocalizedDescriptionKey: "bridge unsupported"])
    }
}

private final class NetworkInterfaceArray: NSObject, LibboxNetworkInterfaceIteratorProtocol {
    private var iterator: IndexingIterator<[LibboxNetworkInterface]>
    private var nextValue: LibboxNetworkInterface?

    init(_ array: [LibboxNetworkInterface]) {
        iterator = array.makeIterator()
    }

    func hasNext() -> Bool {
        nextValue = iterator.next()
        return nextValue != nil
    }

    func next() -> LibboxNetworkInterface? {
        nextValue
    }
}
