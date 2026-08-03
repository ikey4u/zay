import SwiftUI

struct SettingsView: View {
    @EnvironmentObject private var configStore: ConfigStore
    @EnvironmentObject private var navigator: AppNavigator

    var body: some View {
        List {
            Section {
                row(.proxyURL, value: summary(\.proxyURL, empty: "未设置"))

                Button {
                    navigator.open(.proxyNodes)
                } label: {
                    HStack {
                        Text("代理节点")
                            .font(.custom(ZayTheme.bodyFont, size: 16))
                            .foregroundStyle(ZayTheme.ink)
                        Spacer()
                        Text(nodeSummary)
                            .font(.custom(ZayTheme.captionFont, size: 15))
                            .foregroundStyle(ZayTheme.inkTertiary)
                            .lineLimit(1)
                        Image(systemName: "chevron.right")
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundStyle(ZayTheme.inkTertiary)
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)

                Button {
                    navigator.open(.ruleList)
                } label: {
                    HStack {
                        Text("规则列表")
                            .font(.custom(ZayTheme.bodyFont, size: 16))
                            .foregroundStyle(ZayTheme.ink)
                        Spacer()
                        Text(ruleSummary)
                            .font(.custom(ZayTheme.captionFont, size: 15))
                            .foregroundStyle(ZayTheme.inkTertiary)
                        Image(systemName: "chevron.right")
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundStyle(ZayTheme.inkTertiary)
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            } header: {
                Text("代理")
            }

            Section {
                Toggle(isOn: meshEnabledBinding) {
                    Text("启用 Mesh")
                        .font(.custom(ZayTheme.bodyFont, size: 16))
                        .foregroundStyle(ZayTheme.ink)
                }
                .tint(ZayTheme.accent)

                Group {
                    row(.relayURL, value: summary(\.relayURL, empty: "未设置"))
                    row(.networkName, value: summary(\.networkName, empty: "未设置"))
                    row(
                        .networkSecret,
                        value: configStore.config.networkSecret.isEmpty ? "未设置" : "已设置",
                        muted: configStore.config.networkSecret.isEmpty
                    )
                    row(.hostname, value: summary(\.hostname, empty: "设备名（默认）"))
                    row(.meshIPv4, value: summary(\.meshIPv4, empty: "自动分配"))
                    row(.meshCIDRHint, value: summary(\.meshCIDRHint, empty: "未设置"))

                    Button {
                        navigator.open(.meshStatus)
                    } label: {
                        HStack {
                            Text("Mesh 状态")
                                .font(.custom(ZayTheme.bodyFont, size: 16))
                                .foregroundStyle(ZayTheme.ink)
                            Spacer()
                            Text(meshStatusLabel)
                                .font(.custom(ZayTheme.captionFont, size: 15))
                                .foregroundStyle(ZayTheme.inkTertiary)
                            Image(systemName: "chevron.right")
                                .font(.system(size: 13, weight: .semibold))
                                .foregroundStyle(ZayTheme.inkTertiary)
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
                .disabled(!configStore.config.meshEnabled)
                .opacity(configStore.config.meshEnabled ? 1 : 0.45)
            } header: {
                Text("Mesh")
            }

            Section {
                Button {
                    navigator.open(.logs)
                } label: {
                    HStack {
                        Text("运行日志")
                            .font(.custom(ZayTheme.bodyFont, size: 16))
                            .foregroundStyle(ZayTheme.ink)
                        Spacer()
                        Image(systemName: "chevron.right")
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundStyle(ZayTheme.inkTertiary)
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            } header: {
                Text("诊断")
            }

            Section {
                Button {
                    Task {
                        _ = await VPNManager.shared.installVPNConfiguration(reinstall: true)
                    }
                } label: {
                    Text("重置")
                        .font(.custom(ZayTheme.bodyFont, size: 16))
                        .foregroundStyle(ZayTheme.danger)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            } header: {
                Text("VPN")
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(ZayTheme.canvas.ignoresSafeArea())
        .navigationTitle("设置")
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(ZayTheme.canvas, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
    }

    private var meshEnabledBinding: Binding<Bool> {
        Binding(
            get: { configStore.config.meshEnabled },
            set: { newValue in
                let previous = configStore.config.meshEnabled
                guard newValue != previous else { return }
                configStore.update { $0.meshEnabled = newValue }
                configStore.saveNow()
                Task {
                    await VPNManager.shared.applyMeshSettingChange(config: configStore.config)
                }
            }
        )
    }

    private var meshStatusLabel: String {
        guard configStore.config.meshEnabled else { return "已关闭" }
        return VPNManager.shared.status == .connected ? "查看节点" : "未连接"
    }

    private func row(_ field: SettingField, value: String, muted: Bool? = nil) -> some View {
        let isMuted = muted ?? valueIsEmpty(field)
        return Button {
            navigator.open(.edit(field))
        } label: {
            HStack(spacing: 12) {
                Text(field.title)
                    .font(.custom(ZayTheme.bodyFont, size: 16))
                    .foregroundStyle(ZayTheme.ink)
                Spacer(minLength: 8)
                Text(value)
                    .font(.custom(ZayTheme.captionFont, size: 15))
                    .foregroundStyle(isMuted ? ZayTheme.inkTertiary : ZayTheme.inkSecondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Image(systemName: "chevron.right")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(ZayTheme.inkTertiary)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private func summary(_ keyPath: KeyPath<ZayRuntimeConfig, String>, empty: String) -> String {
        let trimmed = configStore.config[keyPath: keyPath]
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? empty : trimmed
    }

    private var nodeSummary: String {
        let tag = configStore.config.resolvedSelectedProxyTag
        return tag == "Auto" ? "自动" : tag
    }

    private var ruleSummary: String {
        let n = configStore.config.customRules.filter(\.enabled).count
        return n == 0 ? "内置" : "+\(n)"
    }

    private func valueIsEmpty(_ field: SettingField) -> Bool {
        configStore.config[keyPath: field.keyPath]
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .isEmpty
    }
}
