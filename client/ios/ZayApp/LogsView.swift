import SwiftUI
import UIKit

struct LogsView: View {
    @State private var logText = "加载中…"
    @State private var toast: String?
    @State private var shareURL: URL?
    @State private var loading = false

    var body: some View {
        VStack(spacing: 0) {
            LogTextView(text: logText)
                .background(ZayTheme.surface)
                .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                .padding(.horizontal, 16)
                .padding(.top, 8)

            HStack(spacing: 10) {
                actionButton(title: "复制", systemImage: "doc.on.doc") {
                    Task {
                        let report = await Task.detached(priority: .userInitiated) {
                            ZayLog.diagnosticReport()
                        }.value
                        UIPasteboard.general.string = report
                        showToast("已复制")
                    }
                }

                actionButton(title: "导出", systemImage: "square.and.arrow.up") {
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

                actionButton(title: "刷新", systemImage: "arrow.clockwise") {
                    refreshAsync()
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)

            if let toast {
                Text(toast)
                    .font(.custom(ZayTheme.captionFont, size: 13))
                    .foregroundStyle(ZayTheme.accent)
                    .padding(.bottom, 8)
            }
        }
        .background(ZayTheme.canvas.ignoresSafeArea())
        .navigationTitle("运行日志")
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(ZayTheme.canvas, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button("清空") {
                    ZayLog.clear()
                    refreshAsync()
                }
                .font(.custom(ZayTheme.bodyFont, size: 15))
                .foregroundStyle(ZayTheme.danger)
            }
        }
        .sheet(item: Binding(
            get: { shareURL.map { IdentifiedURL(url: $0) } },
            set: { shareURL = $0?.url }
        )) { item in
            ActivityView(activityItems: [item.url])
        }
        .task {
            // Light polling — avoid thrashing the shared App Group log while the extension writes.
            logText = ZayLog.readForUI(maxLines: 160, maxFileBytes: 12_000)
            await refreshFromDisk()
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 5_000_000_000)
                await refreshFromDisk()
            }
        }
    }

    private func actionButton(title: String, systemImage: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Label(title, systemImage: systemImage)
                .font(.custom(ZayTheme.bodyFont, size: 14))
                .frame(maxWidth: .infinity)
                .padding(.vertical, 12)
                .background(ZayTheme.surface)
                .foregroundStyle(ZayTheme.ink)
                .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
        }
        .buttonStyle(.plain)
        .disabled(loading)
    }

    private func refreshAsync() {
        Task { await refreshFromDisk() }
    }

    @MainActor
    private func refreshFromDisk() async {
        guard !loading else { return }
        loading = true
        let text = await Task.detached(priority: .utility) {
            var parts: [String] = []
            if let fail = ZayLog.readLastFailure() {
                parts.append("—— 最近失败 ——\n\(fail)\n")
            }
            parts.append(ZayLog.readForUI(maxLines: 160, maxFileBytes: 16_000))
            return parts.joined(separator: "\n")
        }.value
        if text != logText {
            logText = text
        }
        loading = false
    }

    private func showToast(_ message: String) {
        toast = message
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.4) {
            if toast == message { toast = nil }
        }
    }
}

/// UITextView is far faster than SwiftUI Text for multi-kilobyte logs.
private struct LogTextView: UIViewRepresentable {
    let text: String

    func makeUIView(context: Context) -> UITextView {
        let tv = UITextView()
        tv.isEditable = false
        tv.isSelectable = true
        tv.backgroundColor = .clear
        tv.textColor = .label
        tv.font = UIFont(name: ZayTheme.monoFont, size: 11) ?? .monospacedSystemFont(ofSize: 11, weight: .regular)
        tv.textContainerInset = UIEdgeInsets(top: 12, left: 10, bottom: 12, right: 10)
        tv.alwaysBounceVertical = true
        return tv
    }

    func updateUIView(_ uiView: UITextView, context: Context) {
        uiView.textColor = .label
        if uiView.text != text {
            let wasAtBottom = uiView.contentOffset.y + uiView.bounds.height >= uiView.contentSize.height - 40
            uiView.text = text
            if wasAtBottom {
                let end = NSRange(location: max(0, (text as NSString).length - 1), length: 0)
                uiView.scrollRangeToVisible(end)
            }
        }
    }
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
