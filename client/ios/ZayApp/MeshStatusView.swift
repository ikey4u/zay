import SwiftUI

struct MeshStatusView: View {
    @StateObject private var vpn = VPNManager.shared
    @State private var report: MeshStatusReport = .empty
    @State private var errorText: String?
    @State private var isLoading = false
    @State private var expandedIDs: Set<String> = []
    @State private var autoRefresh = true

    var body: some View {
        List {
            overviewSection
            nodesSection
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
        .navigationTitle("Mesh 状态")
        .navigationBarTitleDisplayMode(.large)
        .toolbarBackground(ZayTheme.canvas, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    Task { await refresh() }
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .disabled(isLoading)
            }
        }
        .refreshable { await refresh() }
        .task {
            await refresh()
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 5_000_000_000)
                guard autoRefresh, !Task.isCancelled else { continue }
                await refresh(silent: true)
            }
        }
    }

    // MARK: - Overview

    private var overviewSection: some View {
        Section {
            if vpn.status != .connected {
                HStack {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(ZayTheme.pending)
                    Text("隧道未连接，无法读取 Mesh 状态")
                        .font(.custom(ZayTheme.bodyFont, size: 15))
                        .foregroundStyle(ZayTheme.inkSecondary)
                }
            } else if isLoading && report.nodes.isEmpty {
                HStack {
                    ProgressView()
                    Text("正在读取…")
                        .font(.custom(ZayTheme.captionFont, size: 14))
                        .foregroundStyle(ZayTheme.inkSecondary)
                }
            } else {
                overviewRow("状态", overview.running ? "运行中" : "未运行",
                            valueColor: overview.running ? ZayTheme.connected : ZayTheme.danger)
                overviewRow("本机节点", displayName(overview.hostname))
                overviewRow("虚拟 IP", blank(overview.virtualIPv4))
                overviewRow("网段", blank(overview.meshCIDR))
                overviewRow("网络名", blank(overview.networkName))
                overviewRow("节点数", "\(overview.nodeCount)（对端 \(overview.peerCount)）")
                overviewRow("实例", blank(overview.instanceName))
                if !overview.version.isEmpty {
                    overviewRow("版本", overview.version)
                }
                if report.fetchedAt != .distantPast {
                    overviewRow(
                        "刷新于",
                        report.fetchedAt.formatted(date: .omitted, time: .standard)
                    )
                }
            }
        } header: {
            Text("总览")
        } footer: {
            Text("数据来自隧道内 EasyTier；下拉或点右上角刷新。")
                .font(.custom(ZayTheme.captionFont, size: 12))
        }
    }

    private var overview: MeshOverview { report.overview }

    private func overviewRow(_ title: String, _ value: String, valueColor: Color = ZayTheme.inkSecondary) -> some View {
        HStack {
            Text(title)
                .font(.custom(ZayTheme.bodyFont, size: 15))
                .foregroundStyle(ZayTheme.ink)
            Spacer(minLength: 12)
            Text(value)
                .font(.custom(ZayTheme.monoFont, size: 13))
                .foregroundStyle(valueColor)
                .multilineTextAlignment(.trailing)
                .lineLimit(2)
        }
    }

    // MARK: - Nodes

    private var nodesSection: some View {
        Section {
            if vpn.status == .connected && report.nodes.isEmpty && !isLoading {
                Text("暂无节点信息")
                    .font(.custom(ZayTheme.captionFont, size: 14))
                    .foregroundStyle(ZayTheme.inkTertiary)
            }
            ForEach(report.nodes) { node in
                DisclosureGroup(
                    isExpanded: Binding(
                        get: { expandedIDs.contains(node.id) },
                        set: { open in
                            if open { expandedIDs.insert(node.id) }
                            else { expandedIDs.remove(node.id) }
                        }
                    )
                ) {
                    nodeDetail(node)
                } label: {
                    nodeHeader(node)
                }
            }
        } header: {
            Text("节点")
        }
    }

    private func nodeHeader(_ node: MeshNodeStatus) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Text(node.hostname)
                    .font(.custom(ZayTheme.bodyFont, size: 16))
                    .foregroundStyle(ZayTheme.ink)
                if node.isSelf {
                    Text("本机")
                        .font(.custom(ZayTheme.captionFont, size: 11))
                        .foregroundStyle(ZayTheme.accent)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(ZayTheme.accent.opacity(0.12))
                        .clipShape(RoundedRectangle(cornerRadius: 4, style: .continuous))
                }
                Spacer()
                Text(MeshFormat.latency(node.latencyMs))
                    .font(.custom(ZayTheme.monoFont, size: 12))
                    .foregroundStyle(ZayTheme.inkSecondary)
            }
            Text(node.ipv4.isEmpty ? "无虚拟 IP" : node.ipv4)
                .font(.custom(ZayTheme.monoFont, size: 12))
                .foregroundStyle(ZayTheme.inkTertiary)
        }
        .padding(.vertical, 2)
    }

    private func nodeDetail(_ node: MeshNodeStatus) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            detailLine("Peer ID", node.peerID.isEmpty ? "—" : node.peerID)
            detailLine("跳数 / Cost", "\(node.cost)")
            detailLine("延迟", MeshFormat.latency(node.latencyMs))
            if !node.nextHopPeerID.isEmpty {
                detailLine("下一跳", node.nextHopPeerID)
            }
            detailLine("连接数", "\(node.connCount)")
            detailLine("流量", "↓ \(MeshFormat.bytes(node.rxBytes))  ↑ \(MeshFormat.bytes(node.txBytes))")
            if !node.natTCP.isEmpty || !node.natUDP.isEmpty {
                detailLine("NAT", "TCP \(blank(node.natTCP)) / UDP \(blank(node.natUDP))")
            }
            if !node.version.isEmpty {
                detailLine("版本", node.version)
            }
            if !node.proxyCIDRs.isEmpty {
                detailLine("代理网段", node.proxyCIDRs.joined(separator: ", "))
            }
            if !node.tunnels.isEmpty {
                Text("隧道")
                    .font(.custom(ZayTheme.captionFont, size: 12))
                    .foregroundStyle(ZayTheme.inkTertiary)
                    .padding(.top, 4)
                ForEach(node.tunnels) { t in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(t.type.isEmpty ? "tunnel" : t.type)
                            .font(.custom(ZayTheme.captionFont, size: 12))
                            .foregroundStyle(ZayTheme.accent)
                        if !t.local.isEmpty {
                            Text("本地 \(t.local)")
                                .font(.custom(ZayTheme.monoFont, size: 11))
                                .foregroundStyle(ZayTheme.inkSecondary)
                        }
                        if !t.remote.isEmpty {
                            Text("远端 \(t.remote)")
                                .font(.custom(ZayTheme.monoFont, size: 11))
                                .foregroundStyle(ZayTheme.inkSecondary)
                        }
                    }
                    .padding(.vertical, 2)
                }
            }
        }
        .padding(.vertical, 4)
    }

    private func detailLine(_ title: String, _ value: String) -> some View {
        HStack(alignment: .top) {
            Text(title)
                .font(.custom(ZayTheme.captionFont, size: 12))
                .foregroundStyle(ZayTheme.inkTertiary)
                .frame(width: 72, alignment: .leading)
            Text(value)
                .font(.custom(ZayTheme.monoFont, size: 12))
                .foregroundStyle(ZayTheme.inkSecondary)
                .textSelection(.enabled)
        }
    }

    // MARK: - Actions

    private func refresh(silent: Bool = false) async {
        if !silent { isLoading = true }
        defer { if !silent { isLoading = false } }

        guard vpn.status == .connected else {
            if !silent {
                report = .empty
                errorText = nil
            }
            return
        }

        do {
            guard let json = try await vpn.fetchMeshStatusJSON() else {
                if !silent { errorText = "隧道未响应状态查询" }
                return
            }
            if let parsed = MeshStatusParser.parse(json) {
                report = parsed
                errorText = nil
                // Keep self expanded by default on first load.
                if expandedIDs.isEmpty, let selfNode = parsed.nodes.first(where: \.isSelf) {
                    expandedIDs.insert(selfNode.id)
                }
            } else {
                errorText = "无法解析 Mesh 状态"
            }
        } catch {
            errorText = error.localizedDescription
        }
    }

    private func blank(_ s: String) -> String {
        s.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "—" : s
    }

    private func displayName(_ s: String) -> String {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        return t.isEmpty ? "—" : t
    }
}
