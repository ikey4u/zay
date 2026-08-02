import SwiftUI
import UIKit

enum AppRoute: Hashable {
    case settings
    case edit(SettingField)
    case logs
    case meshStatus
    case proxyNodes
    case ruleList
    case ruleSetDetail(RuleSetDetailRef)
}

enum RuleSetDetailRef: Hashable {
    case embedded(id: String, kind: String)
    case custom(id: String)
}

enum SettingField: String, Hashable, CaseIterable {
    case proxyURL
    case relayURL
    case networkName
    case networkSecret
    case hostname
    case meshIPv4
    case meshCIDRHint

    var title: String {
        switch self {
        case .proxyURL: return "代理 URL"
        case .relayURL: return "中继节点"
        case .networkName: return "网络名"
        case .networkSecret: return "密钥"
        case .hostname: return "节点名"
        case .meshIPv4: return "Mesh IP"
        case .meshCIDRHint: return "Mesh 网段"
        }
    }

    var subtitle: String {
        switch self {
        case .proxyURL:
            return "订阅链接或直连代理地址，用于全局 TUN 出站。"
        case .relayURL:
            return "EasyTier 中继 / peer 地址，例如 tcp://1.2.3.4:11010。"
        case .networkName:
            return "与桌面端或其他节点相同的 EasyTier 网络名称。"
        case .networkSecret:
            return "网络共享密钥，需与其他节点保持一致。"
        case .hostname:
            return "在其他 Mesh 节点上显示的名称。留空则使用本机设备名。"
        case .meshIPv4:
            return "固定虚拟 IP，格式如 10.126.126.5/24。留空则由 DHCP 分配。"
        case .meshCIDRHint:
            return "Mesh 路由提示 CIDR，用于把网段流量送入 EasyTier。"
        }
    }

    var placeholder: String {
        switch self {
        case .proxyURL: return "https://sub… 或 socks5://127.0.0.1:1080"
        case .relayURL: return "tcp://1.2.3.4:11010"
        case .networkName: return "network_name"
        case .networkSecret: return "network_secret"
        case .hostname: return "iPhone"
        case .meshIPv4: return "10.126.126.5/24"
        case .meshCIDRHint: return "10.126.126.0/24"
        }
    }

    var keyboard: UIKeyboardType {
        switch self {
        case .proxyURL, .relayURL: return .URL
        case .networkName, .networkSecret, .hostname: return .asciiCapable
        case .meshIPv4, .meshCIDRHint: return .numbersAndPunctuation
        }
    }

    var isSecure: Bool { self == .networkSecret }

    var keyPath: WritableKeyPath<ZayRuntimeConfig, String> {
        switch self {
        case .proxyURL: return \.proxyURL
        case .relayURL: return \.relayURL
        case .networkName: return \.networkName
        case .networkSecret: return \.networkSecret
        case .hostname: return \.hostname
        case .meshIPv4: return \.meshIPv4
        case .meshCIDRHint: return \.meshCIDRHint
        }
    }
}
