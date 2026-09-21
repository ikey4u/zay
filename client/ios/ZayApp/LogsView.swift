import SwiftUI
import UIKit

struct LogsView: View {
    @EnvironmentObject private var powerPolicy: PowerPolicy
    @State private var rows: [LogTableRow] = []
    @State private var query = ""
    @State private var selectedLevel = "all"
    @State private var toast: String?
    @State private var shareURL: URL?
    @State private var loading = false

    private let tableWidth: CGFloat = 1_410

    var body: some View {
        VStack(spacing: 0) {
            controls
            Divider()

            ScrollView([.horizontal, .vertical]) {
                LazyVStack(spacing: 0, pinnedViews: [.sectionHeaders]) {
                    Section {
                        if filteredRows.isEmpty {
                            emptyState
                        } else {
                            ForEach(Array(filteredRows.enumerated()), id: \.element.id) { index, row in
                                logRow(row, alternate: !index.isMultiple(of: 2))
                            }
                        }
                    } header: {
                        tableHeader
                    }
                }
                .frame(minWidth: tableWidth, alignment: .topLeading)
            }
            .background(ZayTheme.surface)

            if let toast {
                Text(toast)
                    .font(.custom(ZayTheme.captionFont, size: 12))
                    .foregroundStyle(ZayTheme.accent)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 7)
                    .background(ZayTheme.canvasDeep)
            }
        }
        .background(ZayTheme.canvas.ignoresSafeArea())
        .navigationTitle("运行日志")
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(ZayTheme.canvas, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
        .toolbar {
            ToolbarItemGroup(placement: .topBarTrailing) {
                Button { copyDiagnostics() } label: {
                    Image(systemName: "doc.on.doc")
                }
                Button { exportDiagnostics() } label: {
                    Image(systemName: "square.and.arrow.up")
                }
                Menu {
                    Button("立即刷新", systemImage: "arrow.clockwise") { refreshAsync() }
                    Button("清空日志", systemImage: "trash", role: .destructive) {
                        ZayLog.clear()
                        rows = []
                        refreshAsync()
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
            }
        }
        .sheet(item: Binding(
            get: { shareURL.map { IdentifiedURL(url: $0) } },
            set: { shareURL = $0?.url }
        )) { item in
            ActivityView(activityItems: [item.url])
        }
        .task(id: powerPolicy.logRefreshInterval) {
            await refreshFromDisk()
            guard let interval = powerPolicy.logRefreshInterval else { return }
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
                guard !Task.isCancelled else { return }
                await refreshFromDisk()
            }
        }
    }

    private var controls: some View {
        VStack(spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(ZayTheme.inkTertiary)
                TextField("筛选来源、进程、地址、规则或消息", text: $query)
                    .font(.custom(ZayTheme.bodyFont, size: 13))
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                if !query.isEmpty {
                    Button { query = "" } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(ZayTheme.inkTertiary)
                    }
                    .buttonStyle(.plain)
                }
                Menu {
                    levelButton("all", title: "全部级别")
                    levelButton("error", title: "Error")
                    levelButton("warn", title: "Warn")
                    levelButton("info", title: "Info")
                    levelButton("debug", title: "Debug")
                } label: {
                    HStack(spacing: 5) {
                        Text(selectedLevel == "all" ? "全部" : selectedLevel.uppercased())
                        Image(systemName: "chevron.down")
                            .font(.system(size: 9, weight: .bold))
                    }
                    .font(.custom(ZayTheme.captionFont, size: 11))
                    .foregroundStyle(ZayTheme.inkSecondary)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 7)
                    .background(ZayTheme.canvasDeep)
                    .clipShape(Capsule())
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 9)
            .background(ZayTheme.surface)
            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))

            HStack {
                HStack(spacing: 6) {
                    Circle()
                        .fill(powerPolicy.logRefreshInterval == nil ? ZayTheme.inkTertiary : ZayTheme.connected)
                        .frame(width: 6, height: 6)
                    Text(powerPolicy.logRefreshInterval == nil ? "已暂停自动更新" : "自动更新")
                }
                Spacer()
                Text("\(filteredRows.count) 条 · 滚动保留最多 200 MB")
            }
            .font(.custom(ZayTheme.captionFont, size: 11))
            .foregroundStyle(ZayTheme.inkTertiary)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }

    private var tableHeader: some View {
        HStack(spacing: 0) {
            headerCell("时间", width: 92)
            headerCell("级别", width: 68)
            headerCell("事件", width: 160)
            headerCell("进程", width: 200)
            headerCell("源地址", width: 150)
            headerCell("协议", width: 90)
            headerCell("目标地址", width: 190)
            headerCell("规则 / 节点", width: 160)
            headerCell("详情", width: 300)
        }
        .background(ZayTheme.canvasDeep)
        .overlay(alignment: .bottom) { Divider() }
    }

    private func logRow(_ row: LogTableRow, alternate: Bool) -> some View {
        HStack(alignment: .top, spacing: 0) {
            tableCell(row.time, width: 92, mono: true, color: ZayTheme.inkTertiary)
            levelCell(row.level)
            tableCell(row.event, width: 160)
            processCell(row)
            tableCell(row.sourceAddress, width: 150, mono: true)
            tableCell(row.networkProtocol, width: 90)
            tableCell(row.destination, width: 190, mono: true)
            tableCell(row.ruleNode, width: 160)
            tableCell(row.detail, width: 300, color: ZayTheme.inkSecondary, lines: 3)
        }
        .background(alternate ? ZayTheme.canvas.opacity(0.45) : ZayTheme.surface)
        .overlay(alignment: .bottom) { Divider().opacity(0.65) }
    }

    private func headerCell(_ title: String, width: CGFloat) -> some View {
        Text(title)
            .font(.custom(ZayTheme.bodyFont, size: 11))
            .foregroundStyle(ZayTheme.inkSecondary)
            .frame(width: width, alignment: .leading)
            .padding(.horizontal, 10)
            .padding(.vertical, 11)
    }

    private func tableCell(
        _ value: String,
        width: CGFloat,
        mono: Bool = false,
        color: Color = ZayTheme.ink,
        lines: Int = 2
    ) -> some View {
        Text(value.isEmpty ? "—" : value)
            .font(.custom(mono ? ZayTheme.monoFont : ZayTheme.captionFont, size: 10))
            .foregroundStyle(value.isEmpty || value == "—" ? ZayTheme.inkTertiary : color)
            .lineLimit(lines)
            .textSelection(.enabled)
            .frame(width: width, alignment: .leading)
            .padding(.horizontal, 10)
            .padding(.vertical, 10)
    }

    private func levelCell(_ level: String) -> some View {
        Text(level.uppercased())
            .font(.custom(ZayTheme.monoFont, size: 9))
            .foregroundStyle(levelColor(level))
            .padding(.horizontal, 7)
            .padding(.vertical, 4)
            .background(levelColor(level).opacity(0.11))
            .clipShape(Capsule())
            .frame(width: 68, alignment: .leading)
            .padding(.horizontal, 10)
            .padding(.vertical, 9)
    }

    private func processCell(_ row: LogTableRow) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(row.processName.isEmpty ? "—" : row.processName)
                .font(.custom(ZayTheme.captionFont, size: 10))
                .foregroundStyle(row.processName.isEmpty ? ZayTheme.inkTertiary : ZayTheme.ink)
            if !row.processPath.isEmpty {
                Text(row.processPath)
                    .font(.custom(ZayTheme.monoFont, size: 9))
                    .foregroundStyle(ZayTheme.inkTertiary)
                    .lineLimit(2)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
            }
        }
        .frame(width: 200, alignment: .leading)
        .padding(.horizontal, 10)
        .padding(.vertical, 10)
    }

    private var emptyState: some View {
        VStack(spacing: 10) {
            Image(systemName: "tablecells")
                .font(.system(size: 24))
                .foregroundStyle(ZayTheme.inkTertiary)
            Text(loading ? "正在读取日志…" : "没有匹配的日志")
                .font(.custom(ZayTheme.bodyFont, size: 14))
                .foregroundStyle(ZayTheme.inkSecondary)
        }
        .frame(width: tableWidth, height: 180)
    }

    private var filteredRows: [LogTableRow] {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return rows.filter { row in
            let levelMatches = selectedLevel == "all" || row.level == selectedLevel
            guard levelMatches else { return false }
            guard !needle.isEmpty else { return true }
            return row.searchText.contains(needle)
        }
    }

    private func levelButton(_ level: String, title: String) -> some View {
        Button {
            selectedLevel = level
        } label: {
            if selectedLevel == level {
                Label(title, systemImage: "checkmark")
            } else {
                Text(title)
            }
        }
    }

    private func levelColor(_ level: String) -> Color {
        switch level {
        case "error": return ZayTheme.danger
        case "warn", "warning": return ZayTheme.pending
        case "debug": return ZayTheme.inkTertiary
        default: return ZayTheme.accent
        }
    }

    private func copyDiagnostics() {
        Task {
            let report = await Task.detached(priority: .userInitiated) {
                ZayLog.diagnosticReport()
            }.value
            UIPasteboard.general.string = report
            showToast("诊断信息已复制")
        }
    }

    private func exportDiagnostics() {
        Task {
            let url = await Task.detached(priority: .userInitiated) {
                ZayLog.writeDiagnosticFile()
            }.value
            if let url {
                shareURL = url
            } else {
                showToast("导出失败")
            }
        }
    }

    private func refreshAsync() {
        Task { await refreshFromDisk() }
    }

    @MainActor
    private func refreshFromDisk() async {
        guard !loading else { return }
        loading = true
        let parsed = await Task.detached(priority: .utility) {
            LogTableParser.parse(
                text: ZayLog.readTail(maxBytes: 512_000),
                lastFailure: ZayLog.readLastFailure()
            )
        }.value
        rows = parsed
        loading = false
    }

    private func showToast(_ message: String) {
        toast = message
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.4) {
            if toast == message { toast = nil }
        }
    }
}

private struct LogTableRow: Identifiable, Sendable {
    let id: String
    let time: String
    let level: String
    let event: String
    let processName: String
    let processPath: String
    let sourceAddress: String
    let networkProtocol: String
    let destination: String
    let ruleNode: String
    let detail: String

    var searchText: String {
        [time, level, event, processName, processPath, sourceAddress,
         networkProtocol, destination, ruleNode, detail]
            .joined(separator: " ")
            .lowercased()
    }
}

private enum LogTableParser {
    static func parse(text: String, lastFailure: String?) -> [LogTableRow] {
        var parsed: [LogTableRow] = []
        if let lastFailure, !lastFailure.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            parsed.append(makeRow(time: "最近", level: "error", source: "tunnel", message: lastFailure))
        }

        for line in text.split(whereSeparator: \.isNewline) {
            let raw = String(line).trimmingCharacters(in: .whitespacesAndNewlines)
            guard !raw.isEmpty else { continue }
            let row = parseLine(raw)
            if let last = parsed.last, last.level == row.level, last.detail == row.detail {
                continue
            }
            parsed.append(row)
        }
        return Array(parsed.suffix(500).reversed())
    }

    private static func parseLine(_ line: String) -> LogTableRow {
        if line.hasPrefix("[") {
            let parts = line.split(separator: "]", maxSplits: 2, omittingEmptySubsequences: false)
            if parts.count == 3 {
                let time = String(parts[0].dropFirst())
                let level = String(parts[1]).trimmingCharacters(in: CharacterSet(charactersIn: " []")).lowercased()
                let message = String(parts[2]).trimmingCharacters(in: .whitespaces)
                return makeRow(time: time, level: level, source: inferSource(message), message: message)
            }
        }

        let tokens = line.split(separator: " ", maxSplits: 3, omittingEmptySubsequences: true)
        if tokens.count == 4,
           tokens[0].contains("T"),
           ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"].contains(String(tokens[1])) {
            let timestamp = String(tokens[0])
            let time = timestamp.split(separator: "T", maxSplits: 1).last.map(String.init) ?? timestamp
            let level = String(tokens[1]).lowercased()
            let remainder = String(tokens[3])
            if let delimiter = remainder.range(of: ": ") {
                let source = String(remainder[..<delimiter.lowerBound])
                let message = String(remainder[delimiter.upperBound...])
                return makeRow(time: time, level: level, source: source, message: message)
            }
            return makeRow(time: time, level: level, source: "core", message: remainder)
        }

        return makeRow(time: "—", level: "info", source: inferSource(line), message: line)
    }

    private static func makeRow(time: String, level: String, source: String, message: String) -> LogTableRow {
        let processPath = field(["process_path", "app"], in: message)
        let processName = field(["process_name"], in: message).nonEmpty
            ?? processPath.split(separator: "/").last.map(String.init)
            ?? ""
        let sourceAddress = field(["source", "src"], in: message)
        let network = field(["network"], in: message)
        let proto = field(["protocol", "proto"], in: message)
        let networkProtocol = [network, proto].filter { !$0.isEmpty }.joined(separator: " / ")
        let destination = field(["destination", "dst"], in: message)
        let domain = field(["domain", "host"], in: message)
        let target = !destination.isEmpty ? destination : domain
        let rule = field(["rule"], in: message)
        let node = field(["node", "outbound"], in: message)
        let ruleNode = [rule, node].filter { !$0.isEmpty }.joined(separator: " / ")
        let event = "\(shortSource(source)).\(inferEvent(message))"
        return LogTableRow(
            id: [time, level, source, message].joined(separator: "\u{1F}"),
            time: normalizeTime(time),
            level: level == "warning" ? "warn" : level,
            event: event,
            processName: processName,
            processPath: processPath,
            sourceAddress: sourceAddress,
            networkProtocol: networkProtocol,
            destination: target,
            ruleNode: ruleNode,
            detail: message
        )
    }

    private static func field(_ keys: [String], in text: String) -> String {
        for key in keys {
            for marker in ["\"\(key)\":\"", "\(key)="] {
                guard let markerRange = text.range(of: marker) else { continue }
                let tail = text[markerRange.upperBound...]
                if marker.hasSuffix("\"") {
                    if let end = tail.firstIndex(of: "\"") {
                        return String(tail[..<end])
                    }
                } else if tail.first == "\"" {
                    let value = tail.dropFirst()
                    if let end = value.firstIndex(of: "\"") {
                        return String(value[..<end])
                    }
                } else {
                    let end = tail.firstIndex { $0.isWhitespace || $0 == "," || $0 == "}" } ?? tail.endIndex
                    return String(tail[..<end]).trimmingCharacters(in: CharacterSet(charactersIn: "[]\""))
                }
            }
        }
        return ""
    }

    private static func inferSource(_ message: String) -> String {
        let lower = message.lowercased()
        if lower.contains("easytier") || lower.contains("mesh") { return "mesh" }
        if lower.contains("sing-box") || lower.contains("singbox") || lower.contains("proxy") { return "proxy" }
        if lower.contains("vpn") || lower.contains("tunnel") { return "tunnel" }
        return "zay"
    }

    private static func inferEvent(_ message: String) -> String {
        let lower = message.lowercased()
        if lower.contains("dispatcher stats") { return "traffic" }
        if lower.contains("connection") || lower.contains("destination=") { return "connection" }
        if lower.contains("dns") { return "dns" }
        if lower.contains("status") { return "status" }
        if lower.contains("start") || lower.contains("bootstrap") { return "start" }
        if lower.contains("stop") || lower.contains("teardown") { return "stop" }
        if lower.contains("failed") || lower.contains("error") { return "failure" }
        if lower.contains("config") { return "config" }
        return "event"
    }

    private static func shortSource(_ source: String) -> String {
        source.split(separator: ":").last.map(String.init) ?? source
    }

    private static func normalizeTime(_ value: String) -> String {
        var time = value
        if time.hasSuffix("Z") { time.removeLast() }
        if time.count > 12 { time = String(time.prefix(12)) }
        return time
    }
}

private extension String {
    var nonEmpty: String? { isEmpty ? nil : self }
}

private struct IdentifiedURL: Identifiable {
    let url: URL
    var id: String { url.absoluteString }
}

private struct ActivityView: UIViewControllerRepresentable {
    let activityItems: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: activityItems, applicationActivities: nil)
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}
