import SwiftUI

struct ContentView: View {
    @StateObject private var configStore = ConfigStore()
    @StateObject private var navigator = AppNavigator()

    var body: some View {
        NavigationStack(path: $navigator.path) {
            HomeView()
                .toolbar {
                    ToolbarItem(placement: .topBarTrailing) {
                        Button {
                            navigator.openSettings()
                        } label: {
                            Image(systemName: "gearshape")
                                .font(.system(size: 17, weight: .semibold))
                                .foregroundStyle(ZayTheme.ink.opacity(0.85))
                                .frame(width: 36, height: 36)
                                .background(ZayTheme.ink.opacity(0.08))
                                .clipShape(Circle())
                        }
                        .accessibilityLabel("设置")
                    }
                }
                .toolbarBackground(.hidden, for: .navigationBar)
                .navigationBarTitleDisplayMode(.inline)
                .navigationDestination(for: AppRoute.self) { route in
                    switch route {
                    case .settings:
                        SettingsView()
                    case .edit(let field):
                        SettingEditorView(field: field)
                    case .logs:
                        LogsView()
                    case .meshStatus:
                        MeshStatusView()
                    case .proxyNodes:
                        ProxyNodesView()
                    case .ruleList:
                        RuleListView()
                    case .ruleSetDetail(let ref):
                        RuleSetDetailView(ref: ref)
                    }
                }
        }
        .tint(ZayTheme.accent)
        .environmentObject(configStore)
        .environmentObject(navigator)
    }
}
