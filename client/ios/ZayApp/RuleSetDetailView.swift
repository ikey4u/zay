import Foundation
import SwiftUI

/// Browse rules inside an embedded or custom rule-set.
struct RuleSetDetailView: View {
    let ref: RuleSetDetailRef
    @EnvironmentObject private var configStore: ConfigStore

    @State private var title = ""
    @State private var subtitle = ""
    @State private var entries: [String] = []
    @State private var totalCount = 0
    @State private var query = ""
    @State private var errorText: String?
    @State private var loading = true
    @State private var kindLabel = ""

    private let displayCap = 2_000

    var body: some View {
        List {
            Section {
                overviewRow("类型", kindLabel.isEmpty ? "—" : kindLabel)
                overviewRow("规则条数", "\(totalCount)")
                if totalCount > displayCap {
                    overviewRow("列表上限", "显示前 \(displayCap) 条（可搜索）")
                }
            } header: {
                Text("概览")
            } footer: {
                if !subtitle.isEmpty {
                    Text(subtitle)
                        .font(.custom(ZayTheme.captionFont, size: 12))
                }
            }

            if let errorText, !errorText.isEmpty {
                Section {
                    Text(errorText)
                        .font(.custom(ZayTheme.captionFont, size: 13))
                        .foregroundStyle(ZayTheme.danger)
                }
            }

            Section {
                if loading {
                    ProgressView("加载规则…")
                } else if filtered.isEmpty {
                    Text(query.isEmpty ? "无可显示规则" : "无匹配结果")
                        .font(.custom(ZayTheme.captionFont, size: 14))
                        .foregroundStyle(ZayTheme.inkTertiary)
                } else {
                    ForEach(Array(filtered.enumerated()), id: \.offset) { _, line in
                        Text(line)
                            .font(.custom(ZayTheme.monoFont, size: 12))
                            .foregroundStyle(ZayTheme.ink)
                            .textSelection(.enabled)
                    }
                }
            } header: {
                Text("规则明细")
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(ZayTheme.canvas.ignoresSafeArea())
        .navigationTitle(title.isEmpty ? "规则详情" : title)
        .navigationBarTitleDisplayMode(.inline)
        .preferredColorScheme(.light)
        .searchable(text: $query, placement: .navigationBarDrawer(displayMode: .always), prompt: "搜索域名 / CIDR")
        .task { await load() }
    }

    private var filtered: [String] {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !q.isEmpty else { return entries }
        return entries.filter { $0.lowercased().contains(q) }
    }

    private func overviewRow(_ k: String, _ v: String) -> some View {
        HStack {
            Text(k)
                .font(.custom(ZayTheme.bodyFont, size: 15))
                .foregroundStyle(ZayTheme.ink)
            Spacer()
            Text(v)
                .font(.custom(ZayTheme.monoFont, size: 13))
                .foregroundStyle(ZayTheme.inkSecondary)
        }
    }

    @MainActor
    private func load() async {
        loading = true
        defer { loading = false }
        switch ref {
        case .embedded(let id, let kind):
            title = id
            kindLabel = kind
            if id == "applications" {
                entries = []
                totalCount = 0
                subtitle = "applications 按进程名/包名匹配，桌面端可用。iOS Packet Tunnel 拿不到应用进程信息，因此不写出、不加载该规则集。"
                errorText = nil
                loading = false
                return
            }
            if id == "direct" || id == "reject" {
                await loadEmbedded(id: id, kind: kind)
                let stage = RulesProgress.maxOk
                let loaded = RulesProgress.includes(id, stage: stage)
                let note: String
                if loaded {
                    note = "已在渐进阶段 \(stage) 加载进隧道。"
                } else if let failed = RulesProgress.failed,
                          (id == "direct" && failed <= 1) || (id == "reject" && failed <= 2) {
                    note = "加载时因内存被系统杀掉，已自动封顶跳过；以下仅供查看。"
                } else {
                    note = "体积较大，隧道启动后按阶段渐进加载；当前尚未生效。以下可预览内容。"
                }
                if subtitle.isEmpty {
                    subtitle = note
                } else {
                    subtitle = note + "\n" + subtitle
                }
                return
            }
            await loadEmbedded(id: id, kind: kind)
        case .custom(let id):
            title = configStore.config.customRules.first(where: { $0.id == id })?.name ?? id
            kindLabel = "custom"
            await loadCustom(id: id)
        }
    }

    private func loadEmbedded(id: String, kind: String) async {
        let result = await Task.detached(priority: .userInitiated) { () -> LoadResult in
            guard let working = AppGroup.workingDirectory else {
                return .fail("App Group 不可用")
            }
            if kind == "binary" {
                let path = working.appendingPathComponent("ruleset-embedded/\(id).srs")
                let size = (try? FileManager.default.attributesOfItem(atPath: path.path)[.size] as? NSNumber)?.intValue ?? 0
                return .binary(bytes: size, path: path.path)
            }
            let path = working.appendingPathComponent("ruleset-embedded/\(id).json")
            return Self.parseSourceFile(at: path, displayCap: displayCap)
        }.value
        apply(result)
    }

    private func loadCustom(id: String) async {
        let entry = configStore.config.customRules.first(where: { $0.id == id })
        let result = await Task.detached(priority: .userInitiated) { () -> LoadResult in
            if let working = AppGroup.workingDirectory {
                let path = working.appendingPathComponent("ruleset-custom/\(id).json")
                if FileManager.default.fileExists(atPath: path.path) {
                    return Self.parseSourceFile(at: path, displayCap: displayCap)
                }
            }
            // Fall back to original text when not yet synced to disk.
            if let content = entry?.content, !content.isEmpty {
                let lines = content
                    .components(separatedBy: .newlines)
                    .map { $0.trimmingCharacters(in: .whitespaces) }
                    .filter { !$0.isEmpty && !$0.hasPrefix("#") }
                let total = lines.count
                return .ok(
                    lines: Array(lines.prefix(displayCap)),
                    total: total,
                    subtitle: "来源文本（尚未写出到 ruleset-custom，重启隧道后生效）"
                )
            }
            return .fail("找不到自定义规则内容")
        }.value
        apply(result)
        if let entry {
            subtitle = [
                entry.source == "remote" ? "远程" : "手动",
                entry.format,
                entry.action,
                entry.url.isEmpty ? nil : entry.url,
            ]
            .compactMap { $0 }
            .joined(separator: " · ")
        }
    }

    private func apply(_ result: LoadResult) {
        switch result {
        case .ok(let lines, let total, let note):
            entries = lines
            totalCount = total
            if !note.isEmpty { subtitle = note }
            errorText = nil
        case .binary(let bytes, let path):
            entries = []
            totalCount = 0
            subtitle = "二进制规则集（.srs），无法展开条目列表。\n\(path)"
            kindLabel = "binary · \(byteSize(bytes))"
            errorText = nil
        case .fail(let msg):
            entries = []
            totalCount = 0
            errorText = msg
        }
    }

    private func byteSize(_ n: Int) -> String {
        if n < 1024 { return "\(n) B" }
        let kb = Double(n) / 1024
        if kb < 1024 { return String(format: "%.1f KB", kb) }
        return String(format: "%.1f MB", kb / 1024)
    }

    private enum LoadResult {
        case ok(lines: [String], total: Int, subtitle: String)
        case binary(bytes: Int, path: String)
        case fail(String)
    }

    /// Parse sing-box local source rule-set JSON into display lines.
    private static func parseSourceFile(at path: URL, displayCap: Int) -> LoadResult {
        guard FileManager.default.fileExists(atPath: path.path) else {
            return .fail("文件不存在：\(path.lastPathComponent)\n请先启动一次隧道以解压内置规则。")
        }
        guard let data = try? Data(contentsOf: path) else {
            return .fail("无法读取 \(path.lastPathComponent)")
        }
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return .fail("不是有效的 JSON 规则集")
        }
        let rules = root["rules"] as? [Any] ?? []
        var lines: [String] = []
        lines.reserveCapacity(min(rules.count, displayCap))
        for item in rules {
            if lines.count >= displayCap { break }
            lines.append(contentsOf: flattenRule(item).prefix(displayCap - lines.count))
        }
        // Approximate total: one display line per top-level rule object is wrong when
        // one object has many domains — recount via flatten for accuracy up to a soft cap.
        var total = 0
        for item in rules {
            total += flattenRule(item).count
            if total > 200_000 { break }
        }
        return .ok(lines: lines, total: total, subtitle: path.path)
    }

    private static func flattenRule(_ item: Any) -> [String] {
        if let s = item as? String {
            return [s]
        }
        guard let obj = item as? [String: Any] else {
            return ["\(item)"]
        }
        var out: [String] = []
        let keys = [
            "domain", "domain_suffix", "domain_keyword", "domain_regex",
            "ip_cidr", "source_ip_cidr", "process_name", "package_name",
        ]
        for key in keys {
            if let arr = obj[key] as? [String] {
                for v in arr { out.append("\(key): \(v)") }
            } else if let v = obj[key] as? String {
                out.append("\(key): \(v)")
            }
        }
        if out.isEmpty {
            if let data = try? JSONSerialization.data(withJSONObject: obj),
               let s = String(data: data, encoding: .utf8) {
                out.append(s)
            }
        }
        return out
    }
}
