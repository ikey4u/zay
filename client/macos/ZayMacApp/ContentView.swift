import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var filter: ProcessFilterController

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack(spacing: 14) {
                Image(systemName: "network.badge.shield.half.filled")
                    .font(.system(size: 30))
                    .foregroundStyle(.green)
                VStack(alignment: .leading, spacing: 3) {
                    Text("Zay macOS 网络归属")
                        .font(.title2.bold())
                    Text("为 Zay 核心提供连接创建时的应用与进程身份")
                        .foregroundStyle(.secondary)
                }
            }

            GroupBox {
                VStack(alignment: .leading, spacing: 12) {
                    LabeledContent("系统扩展", value: filter.extensionState)
                    LabeledContent("内容过滤器", value: filter.filterState)
                    LabeledContent("事件文件") {
                        Text(ZayMacAppGroup.flowEventsURL?.path ?? "App Group 不可用")
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                    }
                    if let message = filter.message {
                        Text(message)
                            .font(.callout)
                            .foregroundStyle(filter.hasError ? .red : .secondary)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(8)
            } label: {
                Label("进程识别服务", systemImage: "person.text.rectangle")
            }

            Text("该扩展只观察 flow 元数据并允许流量通过；代理、TUN、路由和 Mesh 仍由独立的 Zay Rust 核心负责。")
                .font(.callout)
                .foregroundStyle(.secondary)

            Spacer()

            HStack {
                Button("刷新") { Task { await filter.refresh() } }
                Spacer()
                Button("停用") { Task { await filter.disable() } }
                    .disabled(filter.busy || !filter.enabled)
                Button("安装并启用") { filter.installAndEnable() }
                    .buttonStyle(.borderedProminent)
                    .disabled(filter.busy)
            }
        }
        .padding(28)
    }
}
