import Foundation
import Vision

enum ProxyQRCode {
    static func supportedURL(_ value: String) -> String? {
        let value = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URLComponents(string: value), let scheme = url.scheme?.lowercased() else { return nil }
        switch scheme {
        case "http", "https", "socks", "socks5", "ss", "vmess", "vless", "trojan":
            return value
        case "clash", "clashmeta", "cmfa":
            return url.host == "install-config" ? value : nil
        case "sing-box":
            return url.host == "import-remote-profile" ? value : nil
        case "quantumult-x":
            return (url.host == nil || url.host == "") && url.path == "/add-resource" ? value : nil
        case "tg":
            return url.host == "socks" ? value : nil
        default:
            return nil
        }
    }

    static func readPhoto(_ data: Data) throws -> String {
        let request = VNDetectBarcodesRequest()
        request.symbologies = [.qr]
        try VNImageRequestHandler(data: data).perform([request])
        for barcode in request.results ?? [] {
            if let value = barcode.payloadStringValue, let url = supportedURL(value) { return url }
        }
        throw PhotoError.noProxyQR
    }

    private enum PhotoError: LocalizedError {
        case noProxyQR
        var errorDescription: String? { "No supported server QR code was found in this photo." }
    }
}
