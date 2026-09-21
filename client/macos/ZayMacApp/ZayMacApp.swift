import SwiftUI

@main
struct ZayMacApp: App {
    @StateObject private var filter = ProcessFilterController()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(filter)
                .frame(minWidth: 620, minHeight: 420)
                .task { await filter.refresh() }
        }
        .windowStyle(.hiddenTitleBar)
    }
}
