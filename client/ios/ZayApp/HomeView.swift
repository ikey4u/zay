import SwiftUI

struct HomeView: View {
    @EnvironmentObject private var configStore: ConfigStore
    @StateObject private var vpn = VPNManager.shared

    var body: some View {
        ZStack {
            homeAtmosphere

            VStack(spacing: 0) {
                Spacer(minLength: 36)

                brand
                    .padding(.bottom, 48)

                statusLine
                    .padding(.bottom, 36)

                connectControl
                    .padding(.bottom, 20)

                if let err = vpn.lastError {
                    Text(err)
                        .font(.custom(ZayTheme.captionFont, size: 13))
                        .foregroundStyle(ZayTheme.danger)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                        .padding(.top, 8)
                } else if !vpn.statusDetail.isEmpty {
                    Text(vpn.statusDetail)
                        .font(.custom(ZayTheme.captionFont, size: 12))
                        .foregroundStyle(Color.white.opacity(0.4))
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                        .padding(.top, 8)
                }

                Spacer()

                readinessHint
                    .padding(.horizontal, 28)
                    .padding(.bottom, 28)
            }
            .padding(.horizontal, 24)
        }
        .onAppear {
            Task { await vpn.refreshInstallState() }
        }
    }

    private var homeAtmosphere: some View {
        ZStack {
            LinearGradient(
                colors: [
                    Color(red: 0.06, green: 0.10, blue: 0.12),
                    Color(red: 0.08, green: 0.14, blue: 0.15),
                    Color(red: 0.05, green: 0.09, blue: 0.10),
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            .ignoresSafeArea()

            RadialGradient(
                colors: [
                    Color(red: 0.16, green: 0.48, blue: 0.42).opacity(isActive ? 0.45 : 0.22),
                    .clear,
                ],
                center: .center,
                startRadius: 20,
                endRadius: 340
            )
            .ignoresSafeArea()
            .animation(.easeInOut(duration: 0.6), value: isActive)

            // Soft concentric rings — mesh metaphor without clutter
            ForEach(0..<3, id: \.self) { i in
                Circle()
                    .stroke(Color.white.opacity(0.04 + Double(i) * 0.015), lineWidth: 1)
                    .frame(width: 180 + CGFloat(i) * 70, height: 180 + CGFloat(i) * 70)
                    .offset(y: -20)
            }
        }
    }

    private var brand: some View {
        VStack(spacing: 12) {
            Text("ZAY")
                .font(.custom(ZayTheme.brandFont, size: 64))
                .tracking(10)
                .foregroundStyle(
                    LinearGradient(
                        colors: [
                            Color(red: 0.94, green: 0.98, blue: 0.96),
                            Color(red: 0.55, green: 0.90, blue: 0.78),
                        ],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )

            Text(configStore.config.meshEnabled ? "全局代理与 Mesh" : "全局代理")
                .font(.custom(ZayTheme.captionFont, size: 16))
                .foregroundStyle(Color.white.opacity(0.55))
        }
    }

    private var statusLine: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(statusColor)
                .frame(width: 8, height: 8)
                .shadow(color: statusColor.opacity(0.8), radius: isActive ? 6 : 0)

            Text(vpn.statusText)
                .font(.custom(ZayTheme.bodyFont, size: 14))
                .foregroundStyle(statusColor)
                .tracking(1)
        }
        .animation(.easeInOut(duration: 0.25), value: vpn.status)
    }

    private var connectControl: some View {
        Button {
            Task {
                if isActive {
                    await vpn.stop()
                } else if !vpn.isInstalled {
                    // Install first — triggers system “Add VPN Configurations” alert.
                    // Does not require settings to be filled.
                    _ = await vpn.installVPNConfiguration(reinstall: false)
                } else {
                    configStore.saveNow()
                    await vpn.start(config: configStore.config)
                }
            }
        } label: {
            ZStack {
                Circle()
                    .fill(
                        RadialGradient(
                            colors: isActive
                                ? [
                                    Color(red: 0.25, green: 0.82, blue: 0.68),
                                    Color(red: 0.10, green: 0.52, blue: 0.46),
                                  ]
                                : [
                                    Color.white.opacity(0.14),
                                    Color.white.opacity(0.05),
                                  ],
                            center: .topLeading,
                            startRadius: 10,
                            endRadius: 120
                        )
                    )
                    .frame(width: 168, height: 168)
                    .overlay(
                        Circle()
                            .strokeBorder(
                                isActive
                                    ? Color.white.opacity(0.25)
                                    : Color.white.opacity(0.18),
                                lineWidth: 1.5
                            )
                    )
                    .shadow(
                        color: isActive
                            ? Color(red: 0.12, green: 0.7, blue: 0.55).opacity(0.45)
                            : .clear,
                        radius: 28,
                        y: 8
                    )

                VStack(spacing: 6) {
                    Text(primaryActionTitle)
                        .font(.custom(ZayTheme.titleFont, size: 22))
                        .foregroundStyle(isActive ? Color(red: 0.02, green: 0.10, blue: 0.09) : .white)
                    Text(isActive ? "轻触断开" : (vpn.isInstalled ? "轻触连接" : "轻触安装 VPN"))
                        .font(.custom(ZayTheme.captionFont, size: 12))
                        .foregroundStyle(isActive ? Color.black.opacity(0.45) : Color.white.opacity(0.45))
                }
            }
        }
        .buttonStyle(.plain)
        .disabled(vpn.isBusy || vpn.status == .connecting || vpn.status == .disconnecting)
        .scaleEffect(vpn.status == .connecting ? 0.96 : 1.0)
        .animation(.spring(response: 0.35, dampingFraction: 0.75), value: vpn.status)
    }

    private var readinessHint: some View {
        let text: String
        if !vpn.isInstalled {
            text = "首次需安装 VPN：点上方按钮，在系统弹窗中选择「允许」"
        } else if configStore.config.isValid {
            text = configStore.config.meshEnabled
                ? "配置已就绪 · Mesh 已开（锁屏会暂停组网）"
                : "配置已就绪 · 仅代理（Mesh 可在设置开启）"
        } else if configStore.config.meshEnabled, !configStore.config.meshConfigReady {
            text = "已开 Mesh · 请到设置补全中继与网络身份"
        } else {
            text = "VPN 已安装 · 请到右上角设置填写代理 URL"
        }
        return Text(text)
            .font(.custom(ZayTheme.captionFont, size: 13))
            .foregroundStyle(Color.white.opacity(0.35))
            .multilineTextAlignment(.center)
            .frame(maxWidth: .infinity)
    }

    private var isActive: Bool {
        switch vpn.status {
        case .connected, .connecting, .reasserting:
            return true
        default:
            return false
        }
    }

    private var primaryActionTitle: String {
        switch vpn.status {
        case .connected: return "已连接"
        case .connecting, .reasserting: return "连接中"
        case .disconnecting: return "断开中"
        default: return vpn.isInstalled ? "启动" : "安装"
        }
    }

    private var statusColor: Color {
        switch vpn.status {
        case .connected:
            return Color(red: 0.45, green: 0.92, blue: 0.68)
        case .connecting, .reasserting:
            return Color(red: 0.95, green: 0.80, blue: 0.40)
        default:
            return Color.white.opacity(0.4)
        }
    }
}
