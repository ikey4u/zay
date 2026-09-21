import Darwin
import Foundation
import NetworkExtension

final class FilterDataProvider: NEFilterDataProvider {
    private let writer = AttributionEventWriter()

    override func startFilter(
        completionHandler: @escaping (Error?) -> Void
    ) {
        writer.start()
        completionHandler(nil)
    }

    override func stopFilter(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        writer.stop()
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socket = flow as? NEFilterSocketFlow else {
            return .allow()
        }
        let token = flow.sourceProcessAuditToken ?? flow.sourceAppAuditToken
        let identity = ProcessIdentity.resolve(
            auditToken: token,
            fallbackIdentifier: nil
        )
        guard !identity.name.isEmpty else {
            return .allow()
        }
        let event = AttributionEvent(
            version: 1,
            observedAtMs: UInt64(Date().timeIntervalSince1970 * 1_000),
            network: socket.socketType == SOCK_DGRAM ? "udp" : "tcp",
            source: endpointString(socket.localEndpoint),
            destination: endpointString(socket.remoteEndpoint),
            processName: identity.name,
            processPath: identity.path,
            signingIdentifier: identity.signingIdentifier,
            pid: identity.pid,
            uid: identity.uid
        )
        writer.append(event)
        return .allow()
    }

    private func endpointString(
        _ endpoint: NetworkExtension.NWEndpoint?
    ) -> String? {
        guard let endpoint = endpoint as? NetworkExtension.NWHostEndpoint else {
            return nil
        }
        let hostValue = endpoint.hostname
        let portValue = endpoint.port
        return hostValue.contains(":")
            ? "[\(hostValue)]:\(portValue)"
            : "\(hostValue):\(portValue)"
    }
}
