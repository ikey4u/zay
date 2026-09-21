import Foundation

final class AttributionEventWriter: @unchecked Sendable {
    private let queue = DispatchQueue(label: "dev.zay.process-attribution")
    private let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }()
    private var handle: FileHandle?
    private let maxBytes: UInt64 = 8 * 1024 * 1024

    func start() {
        queue.async { self.openIfNeeded() }
    }

    func stop() {
        queue.sync {
            try? self.handle?.synchronize()
            try? self.handle?.close()
            self.handle = nil
        }
    }

    func append(_ event: AttributionEvent) {
        queue.async {
            guard let data = try? self.encoder.encode(event) else { return }
            self.rotateIfNeeded(adding: UInt64(data.count + 1))
            self.openIfNeeded()
            guard let handle = self.handle else { return }
            do {
                try handle.seekToEnd()
                try handle.write(contentsOf: data)
                try handle.write(contentsOf: Data([0x0A]))
            } catch {
                try? handle.close()
                self.handle = nil
            }
        }
    }

    private func openIfNeeded() {
        guard handle == nil, let url = ZayMacAppGroup.flowEventsURL else {
            return
        }
        if !FileManager.default.fileExists(atPath: url.path) {
            FileManager.default.createFile(atPath: url.path, contents: nil)
        }
        handle = try? FileHandle(forWritingTo: url)
    }

    private func rotateIfNeeded(adding bytes: UInt64) {
        guard let url = ZayMacAppGroup.flowEventsURL,
              let attributes = try? FileManager.default.attributesOfItem(
                atPath: url.path
              ),
              let size = attributes[.size] as? UInt64,
              size + bytes > maxBytes
        else { return }
        try? handle?.close()
        handle = nil
        let archive = url.appendingPathExtension("1")
        try? FileManager.default.removeItem(at: archive)
        try? FileManager.default.moveItem(at: url, to: archive)
    }
}
