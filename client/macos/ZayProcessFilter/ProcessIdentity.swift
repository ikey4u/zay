import Darwin
import Foundation
import Security

/// Identities already resolved for a running process image.
///
/// Reading a signature touches the disk, and `handleNewFlow` holds the flow
/// until it returns, so one process must not pay for it on every connection.
/// The PID version changes on exec and PID reuse, which keeps an entry from
/// outliving the image it describes.
private final class ProcessIdentityCache: @unchecked Sendable {
    struct Key: Hashable {
        let pid: Int32
        let pidVersion: UInt32
    }

    private let lock = NSLock()
    private var entries: [Key: ProcessIdentity] = [:]
    private let limit = 512

    func identity(for key: Key) -> ProcessIdentity? {
        lock.lock()
        defer { lock.unlock() }
        return entries[key]
    }

    func store(_ identity: ProcessIdentity, for key: Key) {
        lock.lock()
        defer { lock.unlock() }
        if entries.count >= limit {
            entries.removeAll(keepingCapacity: true)
        }
        entries[key] = identity
    }
}

struct ProcessIdentity {
    let pid: Int32?
    let uid: Int32?
    let name: String
    let path: String
    let signingIdentifier: String

    private static let cache = ProcessIdentityCache()

    static func resolve(
        auditToken: Data?,
        fallbackIdentifier: String?
    ) -> ProcessIdentity {
        guard let auditToken,
              auditToken.count >= MemoryLayout<UInt32>.size * 8
        else {
            return ProcessIdentity(
                pid: nil,
                uid: nil,
                name: fallbackIdentifier ?? "",
                path: "",
                signingIdentifier: fallbackIdentifier ?? ""
            )
        }
        let values = auditToken.withUnsafeBytes { bytes in
            Array(bytes.bindMemory(to: UInt32.self).prefix(8))
        }
        let pid = Int32(bitPattern: values[5])
        let uid = Int32(bitPattern: values[1])
        let key = ProcessIdentityCache.Key(pid: pid, pidVersion: values[7])
        if let cached = cache.identity(for: key) {
            return cached
        }
        let signing = signingDetails(auditToken: auditToken)
        let livePath = processPath(pid: pid)
        let path = livePath.isEmpty ? signing.path : livePath
        let identity = ProcessIdentity(
            pid: pid,
            uid: uid,
            name: path.isEmpty
                ? (signing.identifier.isEmpty
                    ? (fallbackIdentifier ?? "")
                    : signing.identifier)
                : URL(fileURLWithPath: path).lastPathComponent,
            path: path,
            signingIdentifier: signing.identifier
        )
        cache.store(identity, for: key)
        return identity
    }

    private static func signingDetails(
        auditToken: Data
    ) -> (identifier: String, path: String) {
        let attributes = [kSecGuestAttributeAudit as String: auditToken]
            as CFDictionary
        var guest: SecCode?
        guard SecCodeCopyGuestWithAttributes(
            nil,
            attributes,
            SecCSFlags(),
            &guest
        ) == errSecSuccess, let guest else {
            return ("", "")
        }
        // Until the running code is checked against its signature, the
        // identifier is only what the binary claims about itself.
        let valid = SecCodeCheckValidity(guest, SecCSFlags(), nil)
            == errSecSuccess
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(
            guest,
            SecCSFlags(),
            &staticCode
        ) == errSecSuccess, let staticCode else {
            return ("", "")
        }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &information
        ) == errSecSuccess,
        let values = information as? [CFString: Any]
        else {
            return ("", "")
        }
        let path = (values[kSecCodeInfoMainExecutable] as? URL)?.path ?? ""
        // An ad-hoc signature lets anyone pick the identifier, so it only
        // counts when a team or Apple itself vouches for it.
        let flags = (values[kSecCodeInfoFlags] as? NSNumber)?.uint32Value ?? 0
        let adHoc = flags & SecCodeSignatureFlags.adhoc.rawValue != 0
        let team = values[kSecCodeInfoTeamIdentifier] as? String ?? ""
        let platform =
            (values[kSecCodeInfoPlatformIdentifier] as? NSNumber)?.intValue ?? 0
        guard valid, !adHoc, !team.isEmpty || platform != 0 else {
            return ("", path)
        }
        let identifier = values[kSecCodeInfoIdentifier] as? String ?? ""
        return (identifier, path)
    }

    private static func processPath(pid: Int32) -> String {
        // PROC_PIDPATHINFO_MAXSIZE is a C macro Swift cannot import.
        var buffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard length > 0 else { return "" }
        return String(cString: buffer)
    }
}
