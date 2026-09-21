import Foundation
import NetworkExtension
import SystemExtensions

@MainActor
final class ProcessFilterController: NSObject, ObservableObject {
    @Published private(set) var extensionState = "未检查"
    @Published private(set) var filterState = "未检查"
    @Published private(set) var enabled = false
    @Published private(set) var busy = false
    @Published private(set) var message: String?
    @Published private(set) var hasError = false

    func refresh() async {
        do {
            try await loadPreferences()
            extensionState = "已安装或等待系统确认"
            hasError = false
        } catch {
            report(error)
        }
    }

    func installAndEnable() {
        busy = true
        message = "正在请求安装系统扩展…"
        hasError = false
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: ZayMacIdentifiers.filterExtension,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    func disable() async {
        busy = true
        defer { busy = false }
        do {
            let manager = NEFilterManager.shared()
            try await manager.loadFromPreferences()
            manager.isEnabled = false
            try await manager.saveToPreferences()
            enabled = false
            filterState = "已停用"
            message = "内容过滤器已停用。"
            hasError = false
        } catch {
            report(error)
        }
    }

    private func configureAndEnable() async {
        do {
            let manager = NEFilterManager.shared()
            try await manager.loadFromPreferences()
            let configuration = NEFilterProviderConfiguration()
            configuration.filterSockets = true
            configuration.filterPackets = false
            configuration.filterDataProviderBundleIdentifier =
                ZayMacIdentifiers.filterExtension
            manager.providerConfiguration = configuration
            manager.localizedDescription = "Zay Process Attribution"
            manager.grade = .inspector
            manager.isEnabled = true
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
            enabled = manager.isEnabled
            filterState = manager.isEnabled ? "已启用" : "未启用"
            extensionState = "已安装"
            message = "Zay 现在会在连接创建时记录进程身份。"
            hasError = false
        } catch {
            report(error)
        }
        busy = false
    }

    private func loadPreferences() async throws {
        let manager = NEFilterManager.shared()
        try await manager.loadFromPreferences()
        enabled = manager.isEnabled
        filterState = manager.isEnabled ? "已启用" : "未启用"
    }

    private func report(_ error: Error) {
        busy = false
        hasError = true
        message = error.localizedDescription
    }
}

extension ProcessFilterController: OSSystemExtensionRequestDelegate {
    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    nonisolated func requestNeedsUserApproval(
        _ request: OSSystemExtensionRequest
    ) {
        Task { @MainActor in
            self.extensionState = "等待用户批准"
            self.message = "请在系统设置中批准 Zay 系统扩展，然后返回此窗口。"
        }
    }

    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        Task { @MainActor in
            self.extensionState = result == .completed
                ? "已安装"
                : "安装完成，需要重启"
            await self.configureAndEnable()
        }
    }

    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        didFailWithError error: Error
    ) {
        Task { @MainActor in self.report(error) }
    }
}
