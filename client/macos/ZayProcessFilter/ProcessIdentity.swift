import Darwin
import Foundation
import Security

struct ProcessIdentity {
    let pid: Int32?
    let uid: Int32?
    let name: String
    let path: String
    let signingIdentifier: String

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
        let signing = signingDetails(auditToken: auditToken)
        let livePath = processPath(pid: pid)
        let path = livePath.isEmpty ? signing.path : livePath
        return ProcessIdentity(
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
        let identifier = values[kSecCodeInfoIdentifier] as? String ?? ""
        let path = (values[kSecCodeInfoMainExecutable] as? URL)?.path ?? ""
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
