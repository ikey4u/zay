import SwiftUI

private enum RootTab: Hashable {
    case home
    case proxy
    case mesh
    case diagnostics
}

struct ContentView: View {
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var configStore = ConfigStore()
    @StateObject private var navigator = AppNavigator()
    @StateObject private var powerPolicy = PowerPolicy()
    @State private var selectedTab: RootTab = .home

    var body: some View {
        NavigationStack(path: $navigator.path) {
            TabView(selection: $selectedTab) {
                HomeView()
                    .tabItem { Label("主页", systemImage: "shield.lefthalf.filled") }
                    .tag(RootTab.home)

                ProxyDashboardView()
                    .tabItem { Label("代理", systemImage: "point.3.connected.trianglepath.dotted") }
                    .tag(RootTab.proxy)

                MeshDashboardView(isVisible: selectedTab == .mesh)
                    .tabItem { Label("Mesh", systemImage: "circle.grid.3x3.fill") }
                    .tag(RootTab.mesh)

                DiagnosticsDashboardView()
                    .tabItem { Label("更多", systemImage: "ellipsis.circle.fill") }
                    .tag(RootTab.diagnostics)
            }
            .toolbarBackground(ZayTheme.canvas, for: .navigationBar)
            .toolbarBackground(.visible, for: .tabBar)
            .navigationDestination(for: AppRoute.self) { route in
                switch route {
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
        .environmentObject(powerPolicy)
        .onAppear {
            powerPolicy.update(scenePhase: scenePhase)
        }
        .onChange(of: scenePhase) { phase in
            powerPolicy.update(scenePhase: phase)
        }
        .onChange(of: selectedTab) { _ in
            navigator.popToRoot()
        }
    }
}
