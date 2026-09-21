import Foundation

struct AttributionEvent: Codable, Sendable {
    let version: UInt8
    let observedAtMs: UInt64
    let network: String
    let source: String?
    let destination: String?
    let processName: String
    let processPath: String
    let signingIdentifier: String
    let pid: Int32?
    let uid: Int32?

    enum CodingKeys: String, CodingKey {
        case version
        case observedAtMs = "observed_at_ms"
        case network
        case source
        case destination
        case processName = "process_name"
        case processPath = "process_path"
        case signingIdentifier = "signing_identifier"
        case pid
        case uid
    }
}
