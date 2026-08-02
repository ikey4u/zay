import SwiftUI

@MainActor
final class AppNavigator: ObservableObject {
    @Published var path = NavigationPath()

    func openSettings() {
        path.append(AppRoute.settings)
    }

    func open(_ route: AppRoute) {
        path.append(route)
    }

    func pop() {
        guard !path.isEmpty else { return }
        path.removeLast()
    }
}
