import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var settings: Settings

    var body: some View {
        NavigationStack {
            Form {
                Section("Backend") {
                    TextField("Server URL", text: $settings.serverURL)
                        .autocapitalization(.none)
                        .keyboardType(.URL)
                    SecureField("API key", text: $settings.apiKey)
                }
                Section {
                    Text("The iOS app talks to the Percolator routing backend. Run `npm run dev:server` from /mobile and point this URL at it (use a Tailscale or ngrok address for off-device testing).")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Settings")
        }
    }
}
