import SwiftUI

struct ProxyDashboardView: View {
    @EnvironmentObject private var configStore: ConfigStore
    @EnvironmentObject private var navigator: AppNavigator
    @StateObject private var vpn = VPNManager.shared

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                ZayPageHeader(
                    eyebrow: "Proxy",
                    title: "代理",
                    detail: "订阅、节点与规则在同一条隧道中生效。"
                )

                ZayCard {
                    VStack(alignment: .leading, spacing: 14) {
                        HStack {
                            ZaySectionTitle(title: "当前出口")
                            ZayStatusPill(title: vpn.statusText, color: statusColor)
                        }
                        Text(selectedNode)
                            .font(.custom(ZayTheme.titleFont, size: 24))
                            .foregroundStyle(ZayTheme.ink)
                            .lineLimit(2)
                        Text(providerSummary)
                            .font(.custom(ZayTheme.captionFont, size: 13))
                            .foregroundStyle(ZayTheme.inkSecondary)
                            .lineLimit(2)
                    }
                }

                VStack(spacing: 12) {
                    Button { navigator.open(.proxyNodes) } label: {
                        ZayCard {
                            ZayNavigationRow(
                                icon: "server.rack",
                                title: "节点",
                                detail: "选择出口、查看协议并执行延迟测试"
                            )
                        }
                    }
                    .buttonStyle(.plain)

                    Button { navigator.open(.ruleList) } label: {
                        ZayCard {
                            ZayNavigationRow(
                                icon: "list.bullet.rectangle.portrait",
                                title: "规则集",
                                detail: ruleSummary
                            )
                        }
                    }
                    .buttonStyle(.plain)
                }

                ZaySectionTitle(title: "代理商", detail: "当前支持 1 个订阅")
                ZayCard {
                    VStack(alignment: .leading, spacing: 14) {
                        HStack(alignment: .top, spacing: 12) {
                            Image(systemName: "shippingbox.fill")
                                .font(.system(size: 18, weight: .semibold))
                                .foregroundStyle(ZayTheme.accent)
                                .frame(width: 38, height: 38)
                                .background(ZayTheme.accent.opacity(0.12))
                                .clipShape(RoundedRectangle(cornerRadius: 11, style: .continuous))
                            VStack(alignment: .leading, spacing: 4) {
                                Text("默认订阅")
                                    .font(.custom(ZayTheme.bodyFont, size: 16))
                                    .foregroundStyle(ZayTheme.ink)
                                Text(providerSummary)
                                    .font(.custom(ZayTheme.captionFont, size: 12))
                                    .foregroundStyle(ZayTheme.inkTertiary)
                                    .lineLimit(2)
                            }
                            Spacer()
                        }

                        Button { navigator.open(.edit(.proxyURL)) } label: {
                            Label(configStore.config.proxyURL.isEmpty ? "添加订阅" : "编辑订阅", systemImage: "pencil")
                                .font(.custom(ZayTheme.bodyFont, size: 14))
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 11)
                                .background(ZayTheme.raisedSurface)
                                .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
            .padding(.horizontal, 18)
            .padding(.top, 12)
            .padding(.bottom, 28)
        }
        .background(ZayTheme.canvas.ignoresSafeArea())
        .navigationBarHidden(true)
    }

    private var selectedNode: String {
        let tag = configStore.config.resolvedSelectedProxyTag
        return tag == "Auto" ? "自动选择" : tag
    }

    private var providerSummary: String {
        let raw = configStore.config.proxyURL.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !raw.isEmpty else { return "尚未配置订阅" }
        guard let host = URLComponents(string: raw)?.host, !host.isEmpty else { return "订阅已配置" }
        return host
    }

    private var ruleSummary: String {
        let count = configStore.config.customRules.filter(\.enabled).count
        return count == 0 ? "内置分流规则" : "内置规则 + \(count) 条自定义规则"
    }

    private var statusColor: Color {
        switch vpn.status {
        case .connected: return ZayTheme.connected
        case .connecting, .reasserting: return ZayTheme.pending
        default: return ZayTheme.inkTertiary
        }
    }
}
