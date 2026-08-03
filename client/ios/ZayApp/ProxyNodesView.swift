import Foundation
import SwiftUI

struct ProxyNodeInfo: Identifiable, Equatable {
    var id: String { tag }
    var tag: String
    var type: String
    var server: String
    var port: Int
    var delayMs: Int?
    var isAuto: Bool = false
}

struct ProxyNodesView: View {
    @EnvironmentObject private var configStore: ConfigStore
    @StateObject private var vpn = VPNManager.shared

    @State private var nodes: [ProxyNodeInfo] = []
    @State private var hasAuto = false
    @State private var selectedTag: String = "Auto"
    @State private var liveSelected: String?
    @State private var errorText: String?
    @State private var isLoading = false
    @State private var isTesting = false

    var body: some View {
        List {
            Section {
                if isLoading && nodes.isEmpty {
                    HStack {
                        ProgressView()
                        Text("正在解析订阅…")
                            .font(.custom(ZayTheme.captionFont, size: 14))
                            .foregroundStyle(ZayTheme.inkSecondary)
                    }
                } else if nodes.isEmpty {
                    Text(configStore.config.proxyURL.isEmpty ? "请先设置代理 URL" : "未解析到节点")
                        .font(.custom(ZayTheme.captionFont, size: 14))
                        .foregroundStyle(ZayTheme.inkTertiary)
                } else {
                    if hasAuto {
                        nodeRow(
                            ProxyNodeInfo(tag: "Auto", type: "urltest", server: "", port: 0, isAuto: true),
                            subtitle: "自动选择延迟最低节点"
                        )
                    }
                    ForEach(nodes) { node in
                        nodeRow(node, subtitle: detail(node))
                    }
                }
            } header: {
                Text("节点")
            } footer: {
                Text(footerText)
                    .font(.custom(ZayTheme.captionFont, size: 12))
            }

            if let errorText, !errorText.isEmpty {
                Section {
                    Text(errorText)
                        .font(.custom(ZayTheme.captionFont, size: 13))
                        .foregroundStyle(ZayTheme.danger)
                }
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(ZayTheme.canvas.ignoresSafeArea())
        .navigationTitle("代理节点")
        .navigationBarTitleDisplayMode(.large)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    Task { await refresh() }
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .disabled(isLoading || isTesting)
            }
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    Task { await testAll() }
                } label: {
                    if isTesting {
                        ProgressView()
                    } else {
                        Text("测速")
                    }
                }
                .disabled(isLoading || isTesting || vpn.status != .connected)
            }
        }
        .task {
            selectedTag = configStore.config.resolvedSelectedProxyTag
            await refresh()
        }
        .refreshable { await refresh() }
    }

    private var footerText: String {
        if vpn.status == .connected {
            return "点选节点立即切换；测速需隧道已连接。重新连接后会沿用所选节点。"
        }
        return "当前隧道未连接：可预览节点并选定，启动后生效。测速需先连接。"
    }

    private func nodeRow(_ node: ProxyNodeInfo, subtitle: String) -> some View {
        let isSelected = selectedTag == node.tag || (liveSelected == node.tag)
        return Button {
            Task { await select(node.tag) }
        } label: {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: isSelected ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(isSelected ? ZayTheme.accent : ZayTheme.inkTertiary)
                    .padding(.top, 2)
                VStack(alignment: .leading, spacing: 4) {
                    Text(node.isAuto ? "自动 (Auto)" : node.tag)
                        .font(.custom(ZayTheme.bodyFont, size: 16))
                        .foregroundStyle(ZayTheme.ink)
                    Text(subtitle)
                        .font(.custom(ZayTheme.monoFont, size: 12))
                        .foregroundStyle(ZayTheme.inkTertiary)
                        .lineLimit(2)
                }
                Spacer(minLength: 8)
                if let delay = node.delayMs {
                    Text(delay <= 0 ? "超时" : "\(delay) ms")
                        .font(.custom(ZayTheme.monoFont, size: 12))
                        .foregroundStyle(delayColor(delay))
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private func detail(_ node: ProxyNodeInfo) -> String {
        var parts: [String] = [node.type]
        if !node.server.isEmpty {
            parts.append(node.port > 0 ? "\(node.server):\(node.port)" : node.server)
        }
        return parts.joined(separator: " · ")
    }

    private func delayColor(_ ms: Int) -> Color {
        if ms <= 0 { return ZayTheme.danger }
        if ms < 200 { return ZayTheme.connected }
        if ms < 500 { return ZayTheme.pending }
        return ZayTheme.danger
    }

    private func refresh() async {
        isLoading = true
        defer { isLoading = false }
        errorText = nil
        let url = configStore.config.proxyURL.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !url.isEmpty else {
            nodes = []
            hasAuto = false
            return
        }
        do {
            let json = try await Task.detached(priority: .userInitiated) {
                try ZayNative.listProxyNodes(proxyURL: url)
            }.value
            parseNodes(json)
            if vpn.status == .connected {
                await mergeLiveGroups()
            }
        } catch {
            errorText = error.localizedDescription
        }
    }

    private func parseNodes(_ json: String) {
        guard let data = json.data(using: .utf8),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return }
        hasAuto = (root["has_auto"] as? Bool) ?? false
        let arr = root["nodes"] as? [[String: Any]] ?? []
        nodes = arr.compactMap { n in
            guard let tag = n["tag"] as? String, !tag.isEmpty else { return nil }
            return ProxyNodeInfo(
                tag: tag,
                type: (n["type"] as? String) ?? "",
                server: (n["server"] as? String) ?? "",
                port: (n["port"] as? Int) ?? (n["port"] as? NSNumber)?.intValue ?? 0
            )
        }
    }

    private func mergeLiveGroups() async {
        guard let json = try? await vpn.sendTunnelMessage("proxy-groups"),
              let data = json.data(using: .utf8),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let groups = root["groups"] as? [[String: Any]]
        else { return }

        var delayByTag: [String: Int] = [:]
        for g in groups {
            if let selected = g["selected"] as? String, !selected.isEmpty {
                liveSelected = selected
            }
            let items = g["items"] as? [[String: Any]] ?? []
            for item in items {
                guard let tag = item["tag"] as? String else { continue }
                let delay = (item["url_test_delay"] as? Int)
                    ?? (item["url_test_delay"] as? NSNumber)?.intValue
                if let delay, delay > 0 {
                    delayByTag[tag] = delay
                }
            }
        }
        if !delayByTag.isEmpty {
            nodes = nodes.map { n in
                var copy = n
                copy.delayMs = delayByTag[n.tag]
                return copy
            }
        }
    }

    private func select(_ tag: String) async {
        selectedTag = tag
        configStore.update { $0.selectedProxyTag = tag }
        configStore.saveNow()
        guard vpn.status == .connected else { return }
        do {
            let resp = try await vpn.sendTunnelMessage("proxy-select:\(tag)")
            if let data = resp?.data(using: .utf8),
               let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               obj["ok"] as? Bool != true {
                errorText = (obj["error"] as? String) ?? "切换失败"
            } else {
                liveSelected = tag
                errorText = nil
            }
        } catch {
            errorText = error.localizedDescription
        }
    }

    private func testAll() async {
        guard vpn.status == .connected else {
            errorText = "请先连接隧道再测速"
            return
        }
        isTesting = true
        defer { isTesting = false }
        do {
            _ = try await vpn.sendTunnelMessage("proxy-urltest")
            // Wait for urltest results to propagate via group stream.
            try? await Task.sleep(nanoseconds: 2_500_000_000)
            await mergeLiveGroups()
            // Poll a couple more times.
            for _ in 0..<4 {
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                await mergeLiveGroups()
            }
            errorText = nil
        } catch {
            errorText = error.localizedDescription
        }
    }
}
