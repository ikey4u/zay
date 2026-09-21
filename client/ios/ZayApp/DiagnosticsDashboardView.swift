import SwiftUI

struct DiagnosticsDashboardView: View {
    @EnvironmentObject private var navigator: AppNavigator
    @StateObject private var vpn = VPNManager.shared
    @State private var reinstalling = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                ZayPageHeader(
                    eyebrow: "System",
                    title: "更多",
                    detail: "运行诊断与 VPN 系统配置。"
                )

                ZaySectionTitle(title: "诊断")
                Button { navigator.open(.logs) } label: {
                    ZayCard {
                        ZayNavigationRow(
                            icon: "doc.text.magnifyingglass",
                            title: "运行日志",
                            detail: "查看、复制或导出脱敏诊断信息"
                        )
                    }
                }
                .buttonStyle(.plain)

                ZaySectionTitle(title: "系统")
                ZayCard {
                    VStack(spacing: 0) {
                        HStack {
                            Text("VPN 配置")
                                .font(.custom(ZayTheme.bodyFont, size: 15))
                                .foregroundStyle(ZayTheme.ink)
                            Spacer()
                            Text(vpn.isInstalled ? "已安装" : "未安装")
                                .font(.custom(ZayTheme.captionFont, size: 13))
                                .foregroundStyle(vpn.isInstalled ? ZayTheme.connected : ZayTheme.pending)
                        }
                        .padding(.vertical, 13)

                        SettingsDivider()

                        Button {
                            reinstalling = true
                            Task {
                                _ = await vpn.installVPNConfiguration(reinstall: true)
                                reinstalling = false
                            }
                        } label: {
                            HStack {
                                Text("重置 VPN 配置")
                                    .font(.custom(ZayTheme.bodyFont, size: 15))
                                    .foregroundStyle(ZayTheme.danger)
                                Spacer()
                                if reinstalling { ProgressView() }
                            }
                            .padding(.vertical, 13)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .disabled(reinstalling || vpn.isBusy)
                    }
                }

                Text("Zay 进入后台后只停止界面刷新；代理与 Mesh 由 iOS Network Extension 持续运行。Mesh 默认关闭，可按需启用。")
                    .font(.custom(ZayTheme.captionFont, size: 12))
                    .foregroundStyle(ZayTheme.inkTertiary)
                    .padding(.horizontal, 4)
            }
            .padding(.horizontal, 18)
            .padding(.top, 12)
            .padding(.bottom, 28)
        }
        .background(ZayTheme.canvas.ignoresSafeArea())
        .navigationBarHidden(true)
        .task { await vpn.refreshInstallState() }
    }
}
