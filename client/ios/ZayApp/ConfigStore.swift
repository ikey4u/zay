import Foundation
import Combine

extension Notification.Name {
    static let zayRuntimeConfigDidChange = Notification.Name("zay.runtimeConfigDidChange")
}

@MainActor
final class ConfigStore: ObservableObject {
    @Published private(set) var config: ZayRuntimeConfig

    private var saveTask: Task<Void, Never>?
    private var reloadObserver: NSObjectProtocol?

    init() {
        config = ZayRuntimeConfig.load()
        reloadObserver = NotificationCenter.default.addObserver(
            forName: .zayRuntimeConfigDidChange,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                self?.reload()
            }
        }
    }

    deinit {
        if let reloadObserver {
            NotificationCenter.default.removeObserver(reloadObserver)
        }
    }

    func reload() {
        config = ZayRuntimeConfig.load()
    }

    func update(_ mutate: (inout ZayRuntimeConfig) -> Void) {
        var next = config
        mutate(&next)
        guard next != config else { return }
        config = next
        scheduleSave(next)
    }

    func saveNow() {
        saveTask?.cancel()
        config.save()
    }

    private func scheduleSave(_ value: ZayRuntimeConfig) {
        saveTask?.cancel()
        saveTask = Task {
            try? await Task.sleep(nanoseconds: 250_000_000)
            guard !Task.isCancelled else { return }
            value.save()
        }
    }
}
