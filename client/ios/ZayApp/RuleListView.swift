import Foundation
import SwiftUI

struct RuleListView: View {
    @EnvironmentObject private var configStore: ConfigStore
    @EnvironmentObject private var navigator: AppNavigator
    @State private var embedInfo: EmbedRulesInfo = .empty
    @State private var errorText: String?
    @State private var showAddRemote = false
    @State private var showAddManual = false

    var body: some View {
        List {
            Section {
                overviewRow("来源", embedInfo.source)
                overviewRow("模式", embedInfo.mode == "blacklist" ? "黑名单（最终直连）" : embedInfo.mode)
                overviewRow("版本", embedInfo.version.isEmpty ? "—" : embedInfo.version)
                overviewRow("规则集", "\(embedInfo.sets.count) 个")
                overviewRow(
                    "加载阶段",
                    rulesStageSummary()
                )
            } header: {
                Text("内置规则")
            } footer: {
                Text("编译期嵌入的 Loyalsoldier clash-rules。隧道先用核心集启动，再渐进加载 direct / reject；若某级因内存被系统杀掉会自动封顶，避免重连循环。")
                    .font(.custom(ZayTheme.captionFont, size: 12))
            }

            Section {
                ForEach(embedInfo.sets) { set in
                    Button {
                        navigator.open(.ruleSetDetail(.embedded(id: set.id, kind: set.kind)))
                    } label: {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(set.id)
                                    .font(.custom(ZayTheme.bodyFont, size: 15))
                                    .foregroundStyle(ZayTheme.ink)
                                Text(set.kind)
                                    .font(.custom(ZayTheme.captionFont, size: 12))
                                    .foregroundStyle(ZayTheme.inkTertiary)
                            }
                            Spacer()
                            Text(byteSize(set.bytes))
                                .font(.custom(ZayTheme.monoFont, size: 12))
                                .foregroundStyle(ZayTheme.inkSecondary)
                            Text(statusLabel(set))
                                .font(.custom(ZayTheme.captionFont, size: 12))
                                .foregroundStyle(statusColor(set))
                            Image(systemName: "chevron.right")
                                .font(.system(size: 12, weight: .semibold))
                                .foregroundStyle(ZayTheme.inkTertiary)
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
            } header: {
                Text("内置明细")
            } footer: {
                Text("点进可查看明细。applications 在 iOS 无效；direct / reject 按阶段渐进加载（失败则自动跳过）。")
                    .font(.custom(ZayTheme.captionFont, size: 12))
            }

            Section {
                if configStore.config.customRules.isEmpty {
                    Text("暂无自定义规则")
                        .font(.custom(ZayTheme.captionFont, size: 14))
                        .foregroundStyle(ZayTheme.inkTertiary)
                }
                ForEach(configStore.config.customRules) { rule in
                    customRow(rule)
                }
                .onDelete(perform: deleteRules)

                Button {
                    showAddRemote = true
                } label: {
                    Label("从远程 URL 添加", systemImage: "link")
                        .font(.custom(ZayTheme.bodyFont, size: 15))
                }
                Button {
                    showAddManual = true
                } label: {
                    Label("手动添加规则", systemImage: "plus")
                        .font(.custom(ZayTheme.bodyFont, size: 15))
                }
            } header: {
                Text("自定义规则")
            } footer: {
                Text("支持 Clash payload、Shadowrocket/Quantumult 规则行、纯域名列表、sing-box JSON。重启隧道后生效。")
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
        .navigationTitle("规则列表")
        .navigationBarTitleDisplayMode(.large)
        .preferredColorScheme(.light)
        .sheet(isPresented: $showAddRemote) {
            AddRemoteRuleSheet { entry in
                configStore.update { $0.customRules.append(entry) }
                configStore.saveNow()
            }
        }
        .sheet(isPresented: $showAddManual) {
            AddManualRuleSheet { entry in
                configStore.update { $0.customRules.append(entry) }
                configStore.saveNow()
            }
        }
        .task { reloadEmbedInfo() }
    }

    private func customRow(_ rule: CustomRuleEntry) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Button {
                navigator.open(.ruleSetDetail(.custom(id: rule.id)))
            } label: {
                HStack {
                    Text(rule.name)
                        .font(.custom(ZayTheme.bodyFont, size: 16))
                        .foregroundStyle(ZayTheme.ink)
                    Spacer()
                    Image(systemName: "chevron.right")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(ZayTheme.inkTertiary)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            HStack {
                Text(meta(rule))
                    .font(.custom(ZayTheme.captionFont, size: 12))
                    .foregroundStyle(ZayTheme.inkTertiary)
                Spacer()
                Toggle("", isOn: Binding(
                    get: { rule.enabled },
                    set: { enabled in
                        configStore.update { cfg in
                            if let i = cfg.customRules.firstIndex(where: { $0.id == rule.id }) {
                                cfg.customRules[i].enabled = enabled
                            }
                        }
                        configStore.saveNow()
                    }
                ))
                .labelsHidden()
            }
            Picker("动作", selection: Binding(
                get: { rule.action },
                set: { action in
                    configStore.update { cfg in
                        if let i = cfg.customRules.firstIndex(where: { $0.id == rule.id }) {
                            cfg.customRules[i].action = action
                        }
                    }
                    configStore.saveNow()
                }
            )) {
                Text("代理").tag("proxy")
                Text("直连").tag("direct")
                Text("拒绝").tag("reject")
            }
            .pickerStyle(.segmented)
        }
        .padding(.vertical, 4)
    }

    private func meta(_ rule: CustomRuleEntry) -> String {
        var parts = [rule.source == "remote" ? "远程" : "手动", rule.format]
        if rule.ruleCount > 0 { parts.append("\(rule.ruleCount) 条") }
        if rule.source == "remote", !rule.url.isEmpty {
            parts.append(rule.url)
        }
        return parts.joined(separator: " · ")
    }

    private func deleteRules(at offsets: IndexSet) {
        configStore.update { cfg in
            cfg.customRules.remove(atOffsets: offsets)
        }
        configStore.saveNow()
    }

    private func overviewRow(_ title: String, _ value: String) -> some View {
        HStack {
            Text(title)
                .font(.custom(ZayTheme.bodyFont, size: 15))
                .foregroundStyle(ZayTheme.ink)
            Spacer()
            Text(value)
                .font(.custom(ZayTheme.monoFont, size: 13))
                .foregroundStyle(ZayTheme.inkSecondary)
                .multilineTextAlignment(.trailing)
                .lineLimit(2)
        }
    }

    private func statusLabel(_ set: EmbedRuleSet) -> String {
        switch set.skipReason {
        case "ios-process": return "iOS 跳过"
        case "ios-progressive":
            let stage = RulesProgress.maxOk
            if RulesProgress.includes(set.id, stage: stage) {
                return "已加载"
            }
            if let failed = RulesProgress.failed,
               (set.id == "direct" && failed <= 1) || (set.id == "reject" && failed <= 2) {
                return "过大跳过"
            }
            return "待加载"
        case "ios-memory": return "过大未加载"
        default: break
        }
        if set.skipped { return "已跳过" }
        return set.installed ? "已安装" : "未写出"
    }

    private func statusColor(_ set: EmbedRuleSet) -> Color {
        switch set.skipReason {
        case "ios-process": return ZayTheme.pending
        case "ios-progressive":
            if RulesProgress.includes(set.id, stage: RulesProgress.maxOk) {
                return ZayTheme.connected
            }
            return ZayTheme.pending
        default: break
        }
        if set.skipped || !set.skipReason.isEmpty { return ZayTheme.pending }
        return set.installed ? ZayTheme.connected : ZayTheme.inkTertiary
    }

    private func rulesStageSummary() -> String {
        let maxOk = RulesProgress.maxOk
        if let failed = RulesProgress.failed {
            return "已达 \(maxOk)/\(RulesProgress.maxStage)（封顶 \(failed)）"
        }
        return "\(maxOk)/\(RulesProgress.maxStage)"
    }

    private func reloadEmbedInfo() {
        let working = AppGroup.workingDirectory?.path
        let json = ZayNative.embeddedRulesInfo(workingDir: working)
        embedInfo = EmbedRulesInfo.parse(json)
    }

    private func byteSize(_ n: Int) -> String {
        if n < 1024 { return "\(n) B" }
        let kb = Double(n) / 1024
        if kb < 1024 { return String(format: "%.1f KB", kb) }
        return String(format: "%.1f MB", kb / 1024)
    }
}

struct EmbedRulesInfo {
    var version: String
    var source: String
    var mode: String
    var sets: [EmbedRuleSet]

    static let empty = EmbedRulesInfo(version: "", source: "", mode: "", sets: [])

    static func parse(_ json: String) -> EmbedRulesInfo {
        guard let data = json.data(using: .utf8),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return .empty }
        let sets = (root["sets"] as? [[String: Any]] ?? []).compactMap { s -> EmbedRuleSet? in
            guard let id = s["id"] as? String else { return nil }
            return EmbedRuleSet(
                id: id,
                kind: (s["kind"] as? String) ?? "source",
                bytes: (s["bytes"] as? Int) ?? (s["bytes"] as? NSNumber)?.intValue ?? 0,
                installed: (s["installed"] as? Bool) ?? false,
                skipped: (s["skipped"] as? Bool) ?? false,
                skipReason: (s["skip_reason"] as? String) ?? ""
            )
        }
        return EmbedRulesInfo(
            version: (root["version"] as? String) ?? "",
            source: (root["source"] as? String) ?? "",
            mode: (root["mode"] as? String) ?? "",
            sets: sets
        )
    }
}

struct EmbedRuleSet: Identifiable {
    var id: String
    var kind: String
    var bytes: Int
    var installed: Bool
    var skipped: Bool
    var skipReason: String
}

struct AddRemoteRuleSheet: View {
    @Environment(\.dismiss) private var dismiss
    var onSave: (CustomRuleEntry) -> Void

    @State private var name = ""
    @State private var url = ""
    @State private var action = "proxy"
    @State private var busy = false
    @State private var errorText: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("名称", text: $name)
                    TextField("规则 URL", text: $url)
                        .textInputAutocapitalization(.never)
                        .keyboardType(.URL)
                        .autocorrectionDisabled()
                    Picker("动作", selection: $action) {
                        Text("代理").tag("proxy")
                        Text("直连").tag("direct")
                        Text("拒绝").tag("reject")
                    }
                } footer: {
                    Text("支持 Clash payload YAML、Shadowrocket 规则、域名列表、sing-box JSON。")
                }
                if let errorText {
                    Section {
                        Text(errorText).foregroundStyle(ZayTheme.danger)
                    }
                }
            }
            .navigationTitle("远程规则")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("添加") {
                        Task { await save() }
                    }
                    .disabled(busy || url.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
            .overlay {
                if busy { ProgressView("下载并解析…") }
            }
        }
    }

    private func save() async {
        busy = true
        defer { busy = false }
        do {
            let body = try await CustomRulesStore.fetchRemote(url)
            let converted = try ZayNative.convertRuleText(body, hint: "auto")
            var entry = CustomRuleEntry.makeRemote(
                name: name.isEmpty ? URL(string: url)?.host ?? "远程规则" : name,
                url: url,
                action: action
            )
            entry.content = body
            entry.format = converted.format
            entry.ruleCount = converted.ruleCount
            entry.updatedAt = Date().timeIntervalSince1970
            onSave(entry)
            dismiss()
        } catch {
            errorText = error.localizedDescription
        }
    }
}

struct AddManualRuleSheet: View {
    @Environment(\.dismiss) private var dismiss
    var onSave: (CustomRuleEntry) -> Void

    @State private var name = ""
    @State private var content = ""
    @State private var action = "proxy"
    @State private var errorText: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("名称", text: $name)
                    Picker("动作", selection: $action) {
                        Text("代理").tag("proxy")
                        Text("直连").tag("direct")
                        Text("拒绝").tag("reject")
                    }
                }
                Section {
                    TextEditor(text: $content)
                        .font(.custom(ZayTheme.monoFont, size: 13))
                        .frame(minHeight: 180)
                } header: {
                    Text("规则内容")
                } footer: {
                    Text("示例：\nDOMAIN-SUFFIX,google.com\nDOMAIN,api.example.com\nIP-CIDR,1.1.1.1/32\n或一行一个域名 / +.suffix")
                }
                if let errorText {
                    Section {
                        Text(errorText).foregroundStyle(ZayTheme.danger)
                    }
                }
            }
            .navigationTitle("手动规则")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("添加") { save() }
                }
            }
        }
    }

    private func save() {
        do {
            let converted = try ZayNative.convertRuleText(content, hint: "auto")
            var entry = CustomRuleEntry.makeManual(
                name: name.isEmpty ? "手动规则" : name,
                content: content,
                action: action
            )
            entry.format = converted.format
            entry.ruleCount = converted.ruleCount
            onSave(entry)
            dismiss()
        } catch {
            errorText = error.localizedDescription
        }
    }
}
