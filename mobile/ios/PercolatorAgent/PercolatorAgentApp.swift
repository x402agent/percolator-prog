import SwiftUI

@main
struct PercolatorAgentApp: App {
    @StateObject private var settings = Settings.shared

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(settings)
                .environmentObject(APIClient(settings: settings))
        }
    }
}
