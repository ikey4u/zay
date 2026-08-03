import Foundation

struct ZayRuntimeConfig: Codable, Equatable {
    var proxyURL: String
    var relayURL: String
    var networkName: String
    var networkSecret: String
    /// Optional fixed mesh VIP, e.g. `10.126.126.5/24`. Empty → DHCP.
    var meshIPv4: String
    /// Default mesh route when VIP not yet known.
    var meshCIDRHint: String
    /// EasyTier peer display name (`hostname` in TOML). Empty → device name.
    var hostname: String
    var socksPort: Int
    /// Preferred `Proxy` selector member. Empty / `Auto` → urltest auto.
    var selectedProxyTag: String
    /// User-added rule lists (Settings → 规则列表).
    var customRules: [CustomRuleEntry]
    /// When false (default), tunnel runs proxy only — no EasyTier (saves battery).
    var meshEnabled: Bool

    static let storageKey = "zay.runtime.config"

    static var empty: ZayRuntimeConfig {
        ZayRuntimeConfig(
            proxyURL: "",
            relayURL: "",
            networkName: "",
            networkSecret: "",
            meshIPv4: "",
            meshCIDRHint: "10.126.126.0/24",
            hostname: "",
            socksPort: 18080,
            selectedProxyTag: "Auto",
            customRules: [],
            meshEnabled: false
        )
    }

    init(
        proxyURL: String,
        relayURL: String,
        networkName: String,
        networkSecret: String,
        meshIPv4: String,
        meshCIDRHint: String,
        hostname: String = "",
        socksPort: Int,
        selectedProxyTag: String = "Auto",
        customRules: [CustomRuleEntry] = [],
        meshEnabled: Bool = false
    ) {
        self.proxyURL = proxyURL
        self.relayURL = relayURL
        self.networkName = networkName
        self.networkSecret = networkSecret
        self.meshIPv4 = meshIPv4
        self.meshCIDRHint = meshCIDRHint
        self.hostname = hostname
        self.socksPort = socksPort
        self.selectedProxyTag = selectedProxyTag
        self.customRules = customRules
        self.meshEnabled = meshEnabled
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        proxyURL = try c.decodeIfPresent(String.self, forKey: .proxyURL) ?? ""
        relayURL = try c.decodeIfPresent(String.self, forKey: .relayURL) ?? ""
        networkName = try c.decodeIfPresent(String.self, forKey: .networkName) ?? ""
        networkSecret = try c.decodeIfPresent(String.self, forKey: .networkSecret) ?? ""
        meshIPv4 = try c.decodeIfPresent(String.self, forKey: .meshIPv4) ?? ""
        meshCIDRHint = try c.decodeIfPresent(String.self, forKey: .meshCIDRHint) ?? "10.126.126.0/24"
        hostname = try c.decodeIfPresent(String.self, forKey: .hostname) ?? ""
        socksPort = try c.decodeIfPresent(Int.self, forKey: .socksPort) ?? 18080
        selectedProxyTag = try c.decodeIfPresent(String.self, forKey: .selectedProxyTag) ?? "Auto"
        customRules = try c.decodeIfPresent([CustomRuleEntry].self, forKey: .customRules) ?? []
        meshEnabled = try c.decodeIfPresent(Bool.self, forKey: .meshEnabled) ?? false
    }

    var isValid: Bool {
        let proxyOK = !proxyURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        guard proxyOK else { return false }
        guard meshEnabled else { return true }
        return !relayURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !networkName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !networkSecret.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    var meshConfigReady: Bool {
        !relayURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !networkName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !networkSecret.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    /// Normalized selector default for sing-box (`Auto` when empty).
    var resolvedSelectedProxyTag: String {
        let t = selectedProxyTag.trimmingCharacters(in: .whitespacesAndNewlines)
        return t.isEmpty ? "Auto" : t
    }

    func save() {
        guard let data = try? JSONEncoder().encode(self) else { return }
        AppGroup.defaults.set(data, forKey: Self.storageKey)
        UserDefaults.standard.set(data, forKey: Self.storageKey)
        AppGroup.defaults.synchronize()
        UserDefaults.standard.synchronize()
    }

    static func load() -> ZayRuntimeConfig {
        if let cfg = decode(from: AppGroup.defaults) { return cfg }
        if let cfg = decode(from: .standard) { return cfg }
        return .empty
    }

    private static func decode(from defaults: UserDefaults) -> ZayRuntimeConfig? {
        guard let data = defaults.data(forKey: storageKey),
              let cfg = try? JSONDecoder().decode(ZayRuntimeConfig.self, from: data)
        else { return nil }
        return cfg
    }

    func tunnelOptions() -> [String: NSObject] {
        let data = (try? JSONEncoder().encode(self)) ?? Data()
        let json = String(data: data, encoding: .utf8) ?? "{}"
        return ["config": json as NSString]
    }

    static func from(tunnelOptions options: [String: NSObject]?) -> ZayRuntimeConfig? {
        guard let json = options?["config"] as? String,
              let data = json.data(using: .utf8),
              let cfg = try? JSONDecoder().decode(ZayRuntimeConfig.self, from: data)
        else {
            return load()
        }
        return cfg
    }
}

/// User rule list entry (Settings → 规则列表).
struct CustomRuleEntry: Codable, Equatable, Identifiable, Hashable {
    var id: String
    var name: String
    var enabled: Bool
    /// `proxy` | `direct` | `reject`
    var action: String
    /// `remote` | `manual`
    var source: String
    /// `auto` | `clash` | `shadowrocket` | `singbox` | `plain`
    var format: String
    var url: String
    /// Manual text or last successfully fetched body.
    var content: String
    var ruleCount: Int
    var updatedAt: Double

    static func makeManual(name: String, content: String, action: String = "proxy") -> CustomRuleEntry {
        CustomRuleEntry(
            id: UUID().uuidString.lowercased(),
            name: name,
            enabled: true,
            action: action,
            source: "manual",
            format: "auto",
            url: "",
            content: content,
            ruleCount: 0,
            updatedAt: Date().timeIntervalSince1970
        )
    }

    static func makeRemote(name: String, url: String, action: String = "proxy") -> CustomRuleEntry {
        CustomRuleEntry(
            id: UUID().uuidString.lowercased(),
            name: name,
            enabled: true,
            action: action,
            source: "remote",
            format: "auto",
            url: url,
            content: "",
            ruleCount: 0,
            updatedAt: Date().timeIntervalSince1970
        )
    }
}
