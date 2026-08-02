import SwiftUI

@main
struct ZayApp: App {
    init() {
        ZayLog.setupNativeLogPath()
        ZayLog.info("ZayApp launched")
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
