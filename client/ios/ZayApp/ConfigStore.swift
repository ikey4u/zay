import Foundation
import Combine

@MainActor
final class ConfigStore: ObservableObject {
    @Published private(set) var config: ZayRuntimeConfig

    private var saveTask: Task<Void, Never>?

    init() {
        config = ZayRuntimeConfig.load()
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
