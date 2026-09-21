import SwiftUI

struct MeshDashboardView: View {
    @EnvironmentObject private var configStore: ConfigStore
    @EnvironmentObject private var navigator: AppNavigator
    @EnvironmentObject private var powerPolicy: PowerPolicy
    @StateObject private var vpn = VPNManager.shared
    let isVisible: Bool

    @State private var report: MeshStatusReport = .empty
    @State private var statusError: String?
    @State private var isLoadingStatus = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                ZayPageHeader(
                    eyebrow: "Mesh",
                    title: "组网",
                    detail: "按需加入私有网络，并在 App 进入后台后保持连接。"
                )

                ZayCard {
                    VStack(spacing: 14) {
                        HStack(spacing: 14) {
                            Image(systemName: "circle.grid.3x3.fill")
                                .font(.system(size: 22, weight: .semibold))
                                .foregroundStyle(configStore.config.meshEnabled ? ZayTheme.accent : ZayTheme.inkTertiary)
                                .frame(width: 46, height: 46)
                                .background((configStore.config.meshEnabled ? ZayTheme.accent : ZayTheme.inkTertiary).opacity(0.12))
                                .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                            VStack(alignment: .leading, spacing: 3) {
                                Text(configStore.config.meshEnabled ? "Mesh 已启用" : "Mesh 已关闭")
                                    .font(.custom(ZayTheme.titleFont, size: 18))
                                    .foregroundStyle(ZayTheme.ink)
                                Text(meshDetail)
                                    .font(.custom(ZayTheme.captionFont, size: 12))
                                    .foregroundStyle(ZayTheme.inkSecondary)
                            }
                            Spacer()
                            Toggle("", isOn: meshEnabledBinding)
                                .labelsHidden()
                                .tint(ZayTheme.accent)
                        }

                        if configStore.config.meshEnabled {
                            Button { navigator.open(.meshStatus) } label: {
                                Label("查看节点与实时状态", systemImage: "waveform.path.ecg")
                                    .font(.custom(ZayTheme.bodyFont, size: 14))
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 11)
                                    .background(ZayTheme.accent.opacity(0.12))
                                    .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }

                ZaySectionTitle(
                    title: "节点状态",
                    detail: report.overview.running ? "\(report.overview.nodeCount) 个节点" : nil
                )
                ZayCard {
                    VStack(spacing: 0) {
                        meshNodeContent

                        if configStore.config.meshEnabled && vpn.status == .connected {
                            SettingsDivider()
                            Button { navigator.open(.meshStatus) } label: {
                                HStack {
                                    Text("查看完整状态")
                                        .font(.custom(ZayTheme.bodyFont, size: 14))
                                    Spacer()
                                    Image(systemName: "chevron.right")
                                        .font(.system(size: 12, weight: .semibold))
                                }
                                .padding(.top, 13)
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }

                ZaySectionTitle(title: "网络配置")
                ZayCard {
                    VStack(spacing: 0) {
                        fieldRow(.relayURL, value: summary(\.relayURL, empty: "未设置"))
                        SettingsDivider()
                        fieldRow(.networkName, value: summary(\.networkName, empty: "未设置"))
                        SettingsDivider()
                        fieldRow(.networkSecret, value: configStore.config.networkSecret.isEmpty ? "未设置" : "已设置")
                        SettingsDivider()
                        fieldRow(.hostname, value: summary(\.hostname, empty: "设备名"))
                        SettingsDivider()
                        fieldRow(.meshIPv4, value: summary(\.meshIPv4, empty: "自动分配"))
                        SettingsDivider()
                        fieldRow(.meshCIDRHint, value: summary(\.meshCIDRHint, empty: "未设置"))
                    }
                }

            }
            .padding(.horizontal, 18)
            .padding(.top, 12)
            .padding(.bottom, 28)
        }
        .background(ZayTheme.canvas.ignoresSafeArea())
        .navigationBarHidden(true)
        .task(id: refreshTaskID) {
            guard isVisible,
                  configStore.config.meshEnabled,
                  vpn.status == .connected
            else { return }
            await refreshMeshStatus()
            guard let interval = powerPolicy.meshRefreshInterval else { return }
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
                guard !Task.isCancelled else { return }
                await refreshMeshStatus(silent: true)
            }
        }
    }

    @ViewBuilder
    private var meshNodeContent: some View {
        if !configStore.config.meshEnabled {
            emptyState(icon: "circle.grid.3x3", text: "启用 Mesh 后显示本机与对端节点")
        } else if vpn.status != .connected {
            emptyState(icon: "bolt.horizontal.circle", text: "连接 VPN 后读取 Mesh 节点")
        } else if isLoadingStatus && report.nodes.isEmpty {
            HStack(spacing: 10) {
                ProgressView()
                Text("正在读取节点…")
                    .font(.custom(ZayTheme.captionFont, size: 13))
                    .foregroundStyle(ZayTheme.inkSecondary)
            }
            .padding(.vertical, 8)
        } else if let statusError, !statusError.isEmpty {
            emptyState(icon: "exclamationmark.triangle", text: statusError, color: ZayTheme.danger)
        } else if report.nodes.isEmpty {
            emptyState(icon: "antenna.radiowaves.left.and.right.slash", text: "尚未发现 Mesh 节点")
        } else {
            ForEach(Array(report.nodes.prefix(4)).indices, id: \.self) { index in
                if index > 0 { SettingsDivider() }
                nodeRow(report.nodes[index])
            }
        }
    }

    private func nodeRow(_ node: MeshNodeStatus) -> some View {
        HStack(spacing: 12) {
            Image(systemName: node.isSelf ? "iphone" : "desktopcomputer")
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(node.isSelf ? ZayTheme.accent : ZayTheme.inkSecondary)
                .frame(width: 34, height: 34)
                .background((node.isSelf ? ZayTheme.accent : ZayTheme.inkSecondary).opacity(0.10))
                .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(node.hostname)
                        .font(.custom(ZayTheme.bodyFont, size: 15))
                        .foregroundStyle(ZayTheme.ink)
                        .lineLimit(1)
                    if node.isSelf {
                        Text("本机")
                            .font(.custom(ZayTheme.captionFont, size: 10))
                            .foregroundStyle(ZayTheme.accent)
                    }
                }
                Text(node.ipv4.isEmpty ? "无虚拟 IP" : node.ipv4)
                    .font(.custom(ZayTheme.monoFont, size: 11))
                    .foregroundStyle(ZayTheme.inkTertiary)
            }
            Spacer(minLength: 8)
            VStack(alignment: .trailing, spacing: 3) {
                Text(MeshFormat.latency(node.latencyMs))
                    .font(.custom(ZayTheme.monoFont, size: 11))
                    .foregroundStyle(ZayTheme.inkSecondary)
                if node.rxBytes > 0 || node.txBytes > 0 {
                    Text("↓\(MeshFormat.bytes(node.rxBytes)) ↑\(MeshFormat.bytes(node.txBytes))")
                        .font(.custom(ZayTheme.captionFont, size: 9))
                        .foregroundStyle(ZayTheme.inkTertiary)
                }
            }
        }
        .padding(.vertical, 10)
    }

    private func emptyState(icon: String, text: String, color: Color = ZayTheme.inkTertiary) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon)
                .foregroundStyle(color)
            Text(text)
                .font(.custom(ZayTheme.captionFont, size: 13))
                .foregroundStyle(color)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.vertical, 8)
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
                        try? await Task.sleep(nanoseconds: 1_000_000_000)
                        await refreshMeshStatus()
                    } else {
                        report = .empty
                        statusError = nil
                    }
                }
            }
        )
    }

    private var refreshTaskID: Int {
        var value = vpn.status.rawValue << 4
        if isVisible { value |= 1 }
        if powerPolicy.scenePhase == .active { value |= 2 }
        if powerPolicy.isLowPowerModeEnabled { value |= 4 }
        if configStore.config.meshEnabled { value |= 8 }
        return value
    }

    private func refreshMeshStatus(silent: Bool = false) async {
        guard configStore.config.meshEnabled, vpn.status == .connected else { return }
        if !silent { isLoadingStatus = true }
        defer { if !silent { isLoadingStatus = false } }
        do {
            guard let json = try await vpn.fetchMeshStatusJSON() else {
                statusError = "隧道未返回 Mesh 状态"
                return
            }
            guard let parsed = MeshStatusParser.parse(json) else {
                statusError = "无法解析 Mesh 节点状态"
                return
            }
            report = parsed
            statusError = nil
        } catch {
            statusError = error.localizedDescription
        }
    }

    private var meshDetail: String {
        if !configStore.config.meshEnabled { return "按需加入私有网络" }
        if !configStore.config.meshConfigReady { return "还需要填写中继、网络名与密钥" }
        return vpn.status == .connected ? "组网服务随隧道运行" : "连接代理隧道后生效"
    }

    private func fieldRow(_ field: SettingField, value: String) -> some View {
        Button { navigator.open(.edit(field)) } label: {
            SettingsRow(title: field.title, value: value)
        }
        .buttonStyle(.plain)
    }

    private func summary(_ keyPath: KeyPath<ZayRuntimeConfig, String>, empty: String) -> String {
        let value = configStore.config[keyPath: keyPath].trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? empty : value
    }
}
