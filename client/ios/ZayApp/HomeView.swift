import SwiftUI

struct HomeView: View {
    @EnvironmentObject private var configStore: ConfigStore
    @EnvironmentObject private var navigator: AppNavigator
    @EnvironmentObject private var powerPolicy: PowerPolicy
    @StateObject private var vpn = VPNManager.shared
    @State private var didRunLaunchProbe = false
    @State private var meshReport: MeshStatusReport = .empty
    @State private var meshStatusError: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                proxyCard
                meshCard

                if let error = vpn.lastError, !error.isEmpty {
                    errorCard(error)
                }
            }
            .padding(.horizontal, 18)
            .padding(.top, 12)
            .padding(.bottom, 28)
        }
        .background(ZayTheme.canvas.ignoresSafeArea())
        .navigationBarHidden(true)
        .task { await refreshAndMaybeStartLaunchProbe() }
        .task(id: homeMeshRefreshID) {
            guard configStore.config.meshEnabled, vpn.status == .connected else {
                meshReport = .empty
                meshStatusError = nil
                return
            }
            await refreshMeshStatus()
            guard let interval = powerPolicy.meshRefreshInterval else { return }
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
                guard !Task.isCancelled else { return }
                await refreshMeshStatus()
            }
        }
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 12) {
            ZayLogoMark(size: 44)
            VStack(alignment: .leading, spacing: 1) {
                Text("主页")
                    .font(.custom(ZayTheme.titleFont, size: 28))
                    .foregroundStyle(ZayTheme.ink)
                Text("代理与 Mesh")
                    .font(.custom(ZayTheme.captionFont, size: 12))
                    .foregroundStyle(ZayTheme.inkTertiary)
            }
            Spacer()
            ZayStatusPill(title: vpn.statusText, color: statusColor)
        }
    }

    private var proxyCard: some View {
        ZayCard {
            VStack(alignment: .leading, spacing: 18) {
                HStack(spacing: 14) {
                    featureIcon(
                        "point.3.connected.trianglepath.dotted",
                        color: isActive ? ZayTheme.accent : ZayTheme.inkTertiary
                    )
                    VStack(alignment: .leading, spacing: 5) {
                        Text("代理")
                            .font(.custom(ZayTheme.titleFont, size: 20))
                            .foregroundStyle(ZayTheme.ink)
                        Text(proxyStatusDetail)
                            .font(.custom(ZayTheme.captionFont, size: 12))
                            .foregroundStyle(statusColor)
                    }
                    Spacer()
                    Toggle("", isOn: proxyEnabledBinding)
                        .labelsHidden()
                        .tint(ZayTheme.accent)
                        .disabled(connectionToggleDisabled)
                }

                HStack(spacing: 0) {
                    dashboardValue(title: "代理模式", value: "规则分流 · 国内直连")
                    Rectangle()
                        .fill(ZayTheme.hairline.opacity(0.7))
                        .frame(width: 0.5, height: 42)
                        .padding(.horizontal, 14)
                    dashboardValue(title: "当前节点", value: selectedNode)
                }

                if !vpn.isInstalled || configStore.config.proxyURL.isEmpty {
                    Text(proxyConfigurationHint)
                        .font(.custom(ZayTheme.captionFont, size: 12))
                        .foregroundStyle(ZayTheme.inkSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    private var meshCard: some View {
        ZayCard {
            VStack(alignment: .leading, spacing: 18) {
                HStack(spacing: 14) {
                    featureIcon(
                        "circle.grid.3x3.fill",
                        color: meshIsRunning ? ZayTheme.accent : ZayTheme.inkTertiary
                    )
                    VStack(alignment: .leading, spacing: 5) {
                        Text("Mesh")
                            .font(.custom(ZayTheme.titleFont, size: 20))
                            .foregroundStyle(ZayTheme.ink)
                        Text(meshStatusDetail)
                            .font(.custom(ZayTheme.captionFont, size: 12))
                            .foregroundStyle(meshStatusColor)
                    }
                    Spacer()
                    Toggle("", isOn: meshEnabledBinding)
                        .labelsHidden()
                        .tint(ZayTheme.accent)
                        .disabled(vpn.isBusy)
                }

                HStack(spacing: 0) {
                    dashboardValue(title: "网络", value: meshNetworkName)
                    Rectangle()
                        .fill(ZayTheme.hairline.opacity(0.7))
                        .frame(width: 0.5, height: 42)
                        .padding(.horizontal, 14)
                    dashboardValue(title: "节点 / 虚拟地址", value: meshNodeSummary)
                }

                if configStore.config.meshEnabled {
                    Button { navigator.open(.meshStatus) } label: {
                        HStack {
                            Text("查看 Mesh 节点")
                                .font(.custom(ZayTheme.bodyFont, size: 13))
                            Spacer()
                            Image(systemName: "chevron.right")
                                .font(.system(size: 11, weight: .semibold))
                        }
                        .foregroundStyle(ZayTheme.accent)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    private func featureIcon(_ systemName: String, color: Color) -> some View {
        Image(systemName: systemName)
            .font(.system(size: 20, weight: .semibold))
            .foregroundStyle(color)
            .frame(width: 44, height: 44)
            .background(color.opacity(0.12))
            .clipShape(RoundedRectangle(cornerRadius: 13, style: .continuous))
    }

    private func dashboardValue(title: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.custom(ZayTheme.captionFont, size: 10))
                .foregroundStyle(ZayTheme.inkTertiary)
            Text(value)
                .font(.custom(ZayTheme.bodyFont, size: 13))
                .foregroundStyle(ZayTheme.ink)
                .lineLimit(2)
                .minimumScaleFactor(0.78)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func errorCard(_ error: String) -> some View {
        ZayCard {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(ZayTheme.danger)
                VStack(alignment: .leading, spacing: 4) {
                    Text("连接失败")
                        .font(.custom(ZayTheme.bodyFont, size: 15))
                        .foregroundStyle(ZayTheme.ink)
                    Text(error)
                        .font(.custom(ZayTheme.captionFont, size: 12))
                        .foregroundStyle(ZayTheme.inkSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Button("查看日志") { navigator.open(.logs) }
                        .font(.custom(ZayTheme.bodyFont, size: 13))
                        .padding(.top, 2)
                }
            }
        }
    }

    private var proxyEnabledBinding: Binding<Bool> {
        Binding(
            get: { isActive },
            set: { enabled in
                guard enabled != isActive else { return }
                Task { await setProxyEnabled(enabled) }
            }
        )
    }

    private var meshEnabledBinding: Binding<Bool> {
        Binding(
            get: { configStore.config.meshEnabled },
            set: { enabled in
                guard enabled != configStore.config.meshEnabled else { return }
                configStore.update { $0.meshEnabled = enabled }
                configStore.saveNow()
                Task {
                    await vpn.applyMeshSettingChange(config: configStore.config)
                    if enabled {
                        try? await Task.sleep(nanoseconds: 800_000_000)
                        await refreshMeshStatus()
                    } else {
                        meshReport = .empty
                        meshStatusError = nil
                    }
                }
            }
        )
    }

    private func setProxyEnabled(_ enabled: Bool) async {
        if enabled {
            configStore.saveNow()
            await vpn.start(config: configStore.config)
        } else {
            await vpn.stop()
        }
    }

    private func refreshMeshStatus() async {
        guard configStore.config.meshEnabled, vpn.status == .connected else { return }
        do {
            guard let json = try await vpn.fetchMeshStatusJSON(),
                  let report = MeshStatusParser.parse(json)
            else {
                meshStatusError = "状态不可用"
                return
            }
            meshReport = report
            meshStatusError = nil
        } catch {
            meshStatusError = error.localizedDescription
        }
    }

    @MainActor
    private func refreshAndMaybeStartLaunchProbe() async {
        await vpn.refreshInstallState()
#if targetEnvironment(simulator)
        guard !didRunLaunchProbe,
              ProcessInfo.processInfo.arguments.contains("--zay-network-probe")
        else { return }
        didRunLaunchProbe = true
        ZayLog.info("simulator network probe: auto-start requested")
        configStore.saveNow()
        await vpn.start(config: configStore.config)
        let result = await Task.detached(priority: .userInitiated) {
            Result { try ZayNative.runSimulatorTunProbe(socksPort: 19_080) }
        }.value
        switch result {
        case .success(let json):
            ZayLog.info("simulator TUN probe passed: \(json)")
        case .failure(let error):
            ZayLog.error("simulator TUN probe failed: \(error.localizedDescription)")
        }
#else
        let arguments = ProcessInfo.processInfo.arguments
        let shouldStart = arguments.contains("--zay-device-start-probe")
        let shouldEnableMesh = arguments.contains("--zay-device-mesh-probe")
        let shouldToggleMesh = arguments.contains("--zay-device-mesh-toggle-probe")
        guard !didRunLaunchProbe,
              arguments.contains("--zay-device-network-probe") || shouldStart
        else { return }
        didRunLaunchProbe = true

        if shouldEnableMesh && !configStore.config.meshEnabled {
            configStore.update { $0.meshEnabled = true }
            configStore.saveNow()
            ZayLog.info("device network probe: enabled Mesh for QA")
        }
        if shouldStart && vpn.status != .connected {
            ZayLog.info("device network probe: starting tunnel for QA")
            await vpn.start(config: configStore.config)
            for _ in 0..<60 where vpn.status != .connected {
                try? await Task.sleep(nanoseconds: 500_000_000)
            }
        }
        guard vpn.status == .connected else {
            ZayLog.error("device network probe failed: tunnel is not connected")
            return
        }
        if shouldToggleMesh {
            configStore.update { $0.meshEnabled = false }
            configStore.saveNow()
            await vpn.applyMeshSettingChange(config: configStore.config)
            for _ in 0..<60 where vpn.status != .connected {
                try? await Task.sleep(nanoseconds: 500_000_000)
            }
            guard vpn.status == .connected else {
                ZayLog.error("device Mesh toggle probe failed: proxy-only restart did not connect")
                return
            }
            ZayLog.info("device Mesh toggle probe: proxy-only restart passed")

            configStore.update { $0.meshEnabled = true }
            configStore.saveNow()
            await vpn.applyMeshSettingChange(config: configStore.config)
            for _ in 0..<60 where vpn.status != .connected {
                try? await Task.sleep(nanoseconds: 500_000_000)
            }
            guard vpn.status == .connected else {
                ZayLog.error("device Mesh toggle probe failed: Proxy+Mesh restart did not connect")
                return
            }
            ZayLog.info("device Mesh toggle probe: Proxy+Mesh restart passed")
        }
        do {
            guard var components = URLComponents(string: "https://example.com/") else { return }
            components.queryItems = [URLQueryItem(name: "zayprobe", value: UUID().uuidString)]
            guard let url = components.url else { return }
            var request = URLRequest(url: url)
            request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
            request.timeoutInterval = 15
            let configuration = URLSessionConfiguration.ephemeral
            configuration.timeoutIntervalForRequest = 15
            let session = URLSession(configuration: configuration)
            defer { session.invalidateAndCancel() }
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse,
                  http.statusCode == 200,
                  String(decoding: data, as: UTF8.self).contains("Example Domain")
            else {
                throw NSError(
                    domain: "zay.device-probe",
                    code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "unexpected HTTPS response"]
                )
            }
            ZayLog.info("device network probe passed: status=\(http.statusCode) bytes=\(data.count)")
            if configStore.config.meshEnabled {
                let meshJSON = try await vpn.fetchMeshStatusJSON() ?? "[]"
                if let mesh = MeshStatusParser.parse(meshJSON), mesh.overview.running {
                    ZayLog.info(
                        "device mesh probe passed: nodes=\(mesh.overview.nodeCount) peers=\(mesh.overview.peerCount) vip=\(mesh.overview.virtualIPv4)"
                    )
                } else {
                    ZayLog.error("device mesh probe failed: no running Mesh status")
                }
            }
        } catch {
            ZayLog.error("device network probe failed: \(error.localizedDescription)")
        }
#endif
    }

    private var isActive: Bool {
        switch vpn.status {
        case .connected, .connecting, .reasserting: return true
        default: return false
        }
    }

    private var connectionToggleDisabled: Bool {
        vpn.isBusy || vpn.status == .connecting || vpn.status == .disconnecting
    }

    private var proxyStatusDetail: String {
        if vpn.isBusy { return "正在处理…" }
        return vpn.statusText
    }

    private var proxyConfigurationHint: String {
        if !vpn.isInstalled { return "首次开启时，iOS 会请求添加 VPN 配置。" }
        return "尚未配置代理订阅，请先到代理页完成配置。"
    }

    private var selectedNode: String {
        let tag = configStore.config.resolvedSelectedProxyTag
        return tag == "Auto" ? "自动选择" : tag
    }

    private var meshIsRunning: Bool {
        configStore.config.meshEnabled && vpn.status == .connected && meshReport.overview.running
    }

    private var meshStatusDetail: String {
        guard configStore.config.meshEnabled else { return "已关闭" }
        if !configStore.config.meshConfigReady { return "配置不完整" }
        if vpn.status != .connected { return "等待隧道连接" }
        if let meshStatusError, !meshStatusError.isEmpty { return meshStatusError }
        return meshReport.overview.running ? "运行中" : "正在连接…"
    }

    private var meshStatusColor: Color {
        if meshIsRunning { return ZayTheme.connected }
        if configStore.config.meshEnabled { return ZayTheme.pending }
        return ZayTheme.inkTertiary
    }

    private var meshNetworkName: String {
        let value = configStore.config.networkName.trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? "未配置" : value
    }

    private var meshNodeSummary: String {
        if meshReport.overview.running {
            let address = meshReport.overview.virtualIPv4.isEmpty ? "无地址" : meshReport.overview.virtualIPv4
            return "\(meshReport.overview.nodeCount) 个 · \(address)"
        }
        return configStore.config.meshEnabled ? "等待连接" : "—"
    }

    private var homeMeshRefreshID: Int {
        var value = vpn.status.rawValue << 4
        if powerPolicy.scenePhase == .active { value |= 1 }
        if powerPolicy.isLowPowerModeEnabled { value |= 2 }
        if configStore.config.meshEnabled { value |= 4 }
        return value
    }

    private var statusColor: Color {
        switch vpn.status {
        case .connected: return ZayTheme.connected
        case .connecting, .reasserting: return ZayTheme.pending
        default: return ZayTheme.inkTertiary
        }
    }
}
