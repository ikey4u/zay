import Foundation
import SwiftUI

/// Centralizes UI refresh behavior so the app never keeps background polling alive.
/// The packet tunnel has its own lifecycle; this policy only governs app-side diagnostics.
@MainActor
final class PowerPolicy: ObservableObject {
    @Published private(set) var isLowPowerModeEnabled = ProcessInfo.processInfo.isLowPowerModeEnabled
    @Published private(set) var scenePhase: ScenePhase = .active

    private var powerObserver: NSObjectProtocol?

    init() {
        powerObserver = NotificationCenter.default.addObserver(
            forName: .NSProcessInfoPowerStateDidChange,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                self?.isLowPowerModeEnabled = ProcessInfo.processInfo.isLowPowerModeEnabled
            }
        }
    }

    deinit {
        if let powerObserver {
            NotificationCenter.default.removeObserver(powerObserver)
        }
    }

    func update(scenePhase: ScenePhase) {
        self.scenePhase = scenePhase
    }

    /// Mesh status is useful while visible, but does not need desktop-like polling frequency.
    var meshRefreshInterval: TimeInterval? {
        guard scenePhase == .active else { return nil }
        return isLowPowerModeEnabled ? 45 : 15
    }

    /// Logs are expensive to reread while the extension writes them. In Low Power Mode,
    /// load once and leave further refreshes to the user.
    var logRefreshInterval: TimeInterval? {
        guard scenePhase == .active, !isLowPowerModeEnabled else { return nil }
        return 6
    }

    var title: String {
        isLowPowerModeEnabled ? "低电量保护中" : "智能省电"
    }

    var detail: String {
        if isLowPowerModeEnabled {
            return "已停止日志轮询，并将 Mesh 状态刷新降至 45 秒"
        }
        return "仅在当前页面可见时刷新；进入后台立即停止"
    }
}
