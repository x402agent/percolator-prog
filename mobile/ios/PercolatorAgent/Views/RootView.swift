import SwiftUI

struct RootView: View {
    var body: some View {
        TabView {
            RegisterView()
                .tabItem { Label("Register", systemImage: "person.badge.plus") }
            MintView()
                .tabItem { Label("Mint", systemImage: "sparkles") }
            ExplorerView()
                .tabItem { Label("Explore", systemImage: "magnifyingglass") }
            SettingsView()
                .tabItem { Label("Settings", systemImage: "gear") }
        }
    }
}
