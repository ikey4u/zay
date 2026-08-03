import SwiftUI

struct HomeView: View {
    @EnvironmentObject private var configStore: ConfigStore
    @StateObject private var vpn = VPNManager.shared

    var body: some View {
        ZStack {
            ZayTheme.canvas.ignoresSafeArea()

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
                }

                Spacer()
            }
            .padding(.horizontal, 24)
        }
        .onAppear {
            Task { await vpn.refreshInstallState() }
        }
    }

    private var brand: some View {
        Text("ZAY")
            .font(.custom(ZayTheme.brandFont, size: 64))
            .tracking(10)
            .foregroundStyle(
                LinearGradient(
                    colors: [ZayTheme.ink, ZayTheme.accent],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                )
            )
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
                                ? [ZayTheme.accentSoft, ZayTheme.accent]
                                : [
                                    ZayTheme.ink.opacity(0.10),
                                    ZayTheme.ink.opacity(0.04),
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
                                    ? Color.white.opacity(0.28)
                                    : ZayTheme.ink.opacity(0.14),
                                lineWidth: 1.5
                            )
                    )
                    .shadow(
                        color: isActive ? ZayTheme.accent.opacity(0.35) : .clear,
                        radius: 28,
                        y: 8
                    )

                VStack(spacing: 6) {
                    Text(primaryActionTitle)
                        .font(.custom(ZayTheme.titleFont, size: 22))
                        .foregroundStyle(isActive ? Color.white : ZayTheme.ink)
                    Text(isActive ? "轻触断开" : (vpn.isInstalled ? "轻触连接" : "轻触安装 VPN"))
                        .font(.custom(ZayTheme.captionFont, size: 12))
                        .foregroundStyle(isActive ? Color.white.opacity(0.75) : ZayTheme.inkTertiary)
                }
            }
        }
        .buttonStyle(.plain)
        .disabled(vpn.isBusy || vpn.status == .connecting || vpn.status == .disconnecting)
        .scaleEffect(vpn.status == .connecting ? 0.96 : 1.0)
        .animation(.spring(response: 0.35, dampingFraction: 0.75), value: vpn.status)
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
            return ZayTheme.connected
        case .connecting, .reasserting:
            return ZayTheme.pending
        default:
            return ZayTheme.inkTertiary
        }
    }
}
