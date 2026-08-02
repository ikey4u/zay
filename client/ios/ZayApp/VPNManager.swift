import Foundation
import NetworkExtension

@MainActor
final class VPNManager: ObservableObject {
    static let shared = VPNManager()

    @Published var status: NEVPNStatus = .invalid
    @Published var lastError: String?
    @Published var isBusy = false
    /// True after our Packet Tunnel preference exists in system VPN settings.
    @Published var isInstalled = false
    @Published var statusDetail: String = ""

    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?

    private init() {
        observer = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] note in
            Task { @MainActor in
                guard let self else { return }
                if let session = note.object as? NEVPNConnection {
                    let previous = self.status
                    self.status = session.status
                    if previous == .connecting || previous == .connected || previous == .reasserting,
                       session.status == .disconnected {
                        if let fail = ZayLog.readLastFailure() {
                            self.lastError = fail
                        } else {
                            self.lastError = "隧道已断开，请到设置 → 运行日志复制诊断信息"
                        }
                        ZayLog.warn("VPN disconnected after \(previous.rawValue)")
                    }
                    if session.status == .connected {
                        self.lastError = nil
                    }
                }
            }
        }
    }

    deinit {
        if let observer {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    var statusText: String {
        switch status {
        case .invalid: return isInstalled ? "已断开" : "未安装 VPN"
        case .disconnected: return "已断开"
        case .connecting: return "连接中…"
        case .connected: return "已连接"
        case .reasserting: return "重连中…"
        case .disconnecting: return "断开中…"
        @unknown default: return "未知"
        }
    }

    /// Probe whether our preference already exists (no install / no dialog).
    func refreshInstallState() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            if let existing = managers.first(where: { managerMatches($0) }) {
                manager = existing
                status = existing.connection.status
                isInstalled = true
                statusDetail = "系统已有 Zay VPN 配置"
                ZayLog.info("VPN already present, status=\(status.rawValue)")
            } else {
                manager = nil
                status = .invalid
                isInstalled = false
                statusDetail = "尚未安装，点启动会弹出系统授权"
                ZayLog.info("VPN not installed (managers=\(managers.count))")
            }
        } catch {
            ZayLog.error("refreshInstallState: \(describe(error))")
        }
    }

    /// Create / update the system VPN preference.
    /// First successful `saveToPreferences()` shows the system “Add VPN Configurations” alert.
    /// Does **not** require proxy/mesh fields to be filled.
    @discardableResult
    func installVPNConfiguration(reinstall: Bool = false) async -> Bool {
        lastError = nil
        isBusy = true
        defer { isBusy = false }
        statusDetail = "正在请求系统安装 VPN 配置…"
        ZayLog.info("installVPNConfiguration reinstall=\(reinstall) bundle=\(ZayBundleID.tunnel)")

        do {
            var managers = try await NETunnelProviderManager.loadAllFromPreferences()
            ZayLog.info("loadAllFromPreferences count=\(managers.count)")

            if reinstall {
                for m in managers where managerMatches(m) {
                    ZayLog.info("removing existing Zay VPN preference")
                    try await m.removeFromPreferences()
                }
                managers = try await NETunnelProviderManager.loadAllFromPreferences()
            }

            let target = managers.first(where: { managerMatches($0) }) ?? NETunnelProviderManager()
            applyProtocol(to: target, config: nil)
            target.isEnabled = true

            ZayLog.info("calling saveToPreferences (permission dialog should appear now)…")
            // Must run on main; we are @MainActor.
            try await target.saveToPreferences()
            ZayLog.info("saveToPreferences returned OK — reload")
            try await target.loadFromPreferences()

            let reloaded = try await NETunnelProviderManager.loadAllFromPreferences()
            guard let live = reloaded.first(where: { managerMatches($0) }) else {
                manager = nil
                isInstalled = false
                status = .invalid
                lastError = "系统未保存 Zay VPN 配置。请确认 Xcode 已为 App/Tunnel 打开 Network Extension（Packet Tunnel）能力并重新安装 App"
                statusDetail = lastError ?? ""
                ZayLog.error(lastError!)
                return false
            }

            manager = live
            status = live.connection.status
            isInstalled = true
            statusDetail = "VPN 配置已安装，可在「设置 → VPN」中看到 Zay"
            ZayLog.info("VPN installed OK status=\(status.rawValue)")
            return true
        } catch {
            manager = nil
            isInstalled = false
            status = .invalid
            lastError = permissionHint(for: error)
            statusDetail = lastError ?? ""
            ZayLog.error("installVPNConfiguration failed: \(describe(error))")
            return false
        }
    }

    func start(config: ZayRuntimeConfig) async {
        lastError = nil
        isBusy = true
        defer { isBusy = false }

        // 1) Install VPN preference FIRST — this is what shows the system popup.
        //    Previously we required config.isValid before install, so many users never saw the dialog.
        if !isInstalled || manager == nil {
            let ok = await installVPNConfiguration(reinstall: false)
            if !ok { return }
        }

        // 2) Then require config to actually start the tunnel.
        guard config.isValid else {
            lastError = "VPN 配置已安装。请到设置填写代理 URL、中继、网络名与密钥后再启动"
            statusDetail = lastError ?? ""
            return
        }
        config.save()

        guard let manager else {
            lastError = "VPN 配置不可用"
            return
        }

        do {
            applyProtocol(to: manager, config: config)
            manager.isEnabled = true
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()

            let reloaded = try await NETunnelProviderManager.loadAllFromPreferences()
            let live = reloaded.first(where: { managerMatches($0) }) ?? manager
            self.manager = live

            // Warm subscription cache on App network before the Packet Tunnel starts.
            // Tunnel start often fails DNS/HTTPS while underlay is still settling.
            if let working = AppGroup.workingDirectory?.path {
                statusDetail = "正在拉取订阅…"
                let url = config.proxyURL
                let ok = await Task.detached(priority: .userInitiated) {
                    ZayNative.prefetchProxy(proxyURL: url, workingDir: working)
                }.value
                if !ok {
                    ZayLog.warn("prefetch missed — tunnel will try cache / live fetch")
                }
            }

            ZayLog.info("starting tunnel…")
            try live.connection.startVPNTunnel(options: config.tunnelOptions())
            status = live.connection.status
            statusDetail = "已请求连接"
            ZayLog.info("startVPNTunnel requested, status=\(statusText)")
        } catch {
            lastError = permissionHint(for: error)
            statusDetail = lastError ?? ""
            ZayLog.error("startVPNTunnel failed: \(describe(error))")
        }
    }

    func stop() async {
        guard let manager else {
            ZayLog.info("stopVPNTunnel skipped (no manager)")
            return
        }
        do {
            // Disable on-demand first, otherwise iOS may immediately restart the tunnel.
            manager.isOnDemandEnabled = false
            manager.onDemandRules = []
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
        } catch {
            ZayLog.warn("disable on-demand before stop: \(describe(error))")
        }
        manager.connection.stopVPNTunnel()
        status = manager.connection.status
        ZayLog.info("stopVPNTunnel requested")
    }

    /// Ask the Packet Tunnel for EasyTier mesh status JSON.
    func fetchMeshStatusJSON() async throws -> String? {
        try await sendTunnelMessage("status")
    }

    /// Send a UTF-8 provider message; returns response body (if any).
    func sendTunnelMessage(_ request: String) async throws -> String? {
        if manager == nil {
            await refreshInstallState()
        }
        guard status == .connected else { return nil }
        guard let session = manager?.connection as? NETunnelProviderSession else {
            throw NSError(
                domain: "zay",
                code: 50,
                userInfo: [NSLocalizedDescriptionKey: "无有效隧道会话"]
            )
        }
        return try await withCheckedThrowingContinuation { cont in
            do {
                try session.sendProviderMessage(Data(request.utf8)) { data in
                    guard let data, !data.isEmpty else {
                        cont.resume(returning: nil)
                        return
                    }
                    cont.resume(returning: String(data: data, encoding: .utf8))
                }
            } catch {
                cont.resume(throwing: error)
            }
        }
    }

    private func applyProtocol(to manager: NETunnelProviderManager, config: ZayRuntimeConfig?) {
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = ZayBundleID.tunnel
        proto.serverAddress = "Zay Mesh+Proxy"
        // Keep tunnel alive when screen locks / device sleeps.
        proto.disconnectOnSleep = false
        if let config, let data = try? JSONEncoder().encode(config) {
            proto.providerConfiguration = ["configJSON": String(data: data, encoding: .utf8) ?? "{}"]
        } else if let existing = (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration {
            proto.providerConfiguration = existing
        }
        manager.protocolConfiguration = proto
        manager.localizedDescription = "Zay"

        // If the extension is jetsam'd / fails, reconnect when network is available.
        // Stop path clears these so the user can truly disconnect.
        if config != nil {
            let rule = NEOnDemandRuleConnect()
            rule.interfaceTypeMatch = .any
            manager.onDemandRules = [rule]
            manager.isOnDemandEnabled = true
        }
    }

    private func managerMatches(_ manager: NETunnelProviderManager) -> Bool {
        if let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
           proto.providerBundleIdentifier == ZayBundleID.tunnel {
            return true
        }
        // Fallback for partially loaded preferences.
        return manager.localizedDescription == "Zay"
    }

    private func permissionHint(for error: Error) -> String {
        let ns = error as NSError
        let text = describe(error)
        ZayLog.error("VPN NSError domain=\(ns.domain) code=\(ns.code) userInfo=\(ns.userInfo)")

        if ns.domain == NEVPNErrorDomain {
            switch ns.code {
            case NEVPNError.configurationReadWriteFailed.rawValue:
                return "无法写入 VPN 配置（可能点了不允许，或缺少 Network Extension 签名）。请再点启动；若无弹窗，到 Xcode → Signing & Capabilities 为 App 与 Tunnel 勾选 Packet Tunnel Provider，删掉 App 重装后再试"
            case NEVPNError.configurationInvalid.rawValue:
                return "VPN 配置无效：请确认扩展 Bundle ID 为 \(ZayBundleID.tunnel)，且已嵌入 App"
            case NEVPNError.configurationStale.rawValue:
                return "VPN 配置已过期，正在尝试重新安装…"
            default:
                break
            }
        }
        if text.localizedCaseInsensitiveContains("permission")
            || text.localizedCaseInsensitiveContains("denied")
            || text.localizedCaseInsensitiveContains("cancel") {
            return "未获得 VPN 权限。请再次点击启动，并在系统弹窗中点「允许」"
        }
        return text
    }

    private func describe(_ error: Error) -> String {
        let ns = error as NSError
        var parts = [ns.localizedDescription]
        if let reason = ns.localizedFailureReason, !reason.isEmpty {
            parts.append(reason)
        }
        if let underlying = ns.userInfo[NSUnderlyingErrorKey] as? NSError {
            parts.append("underlying=\(underlying.localizedDescription)")
        }
        parts.append("domain=\(ns.domain) code=\(ns.code)")
        return parts.joined(separator: " · ")
    }
}
