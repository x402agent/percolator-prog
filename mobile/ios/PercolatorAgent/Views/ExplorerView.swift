import SwiftUI

struct ExplorerView: View {
    @EnvironmentObject var api: APIClient
    @State private var address = ""
    @State private var agent: AgentView?
    @State private var error: String?
    @State private var loading = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Lookup") {
                    TextField("Asset address", text: $address)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                    Button(loading ? "Loading…" : "Explore") { Task { await load() } }
                        .disabled(address.count < 32 || loading)
                }
                if let agent {
                    Section("Agent") {
                        LabeledContent("Name", value: agent.name)
                        LabeledContent("Owner", value: agent.owner)
                        LabeledContent("Asset", value: agent.asset)
                        LabeledContent("Identity PDA", value: agent.identity.pda)
                        if let u = URL(string: agent.uri) { Link("Metadata", destination: u) }
                        if let u = URL(string: agent.explorer) { Link("Open in explorer", destination: u) }
                    }
                    if !agent.identity.services.isEmpty {
                        Section("Services") {
                            ForEach(agent.identity.services, id: \.self) { svc in
                                VStack(alignment: .leading) {
                                    Text(svc.name).font(.headline)
                                    Text(svc.endpoint).font(.caption).foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                    if !agent.identity.supportedTrust.isEmpty {
                        Section("Trust") {
                            ForEach(agent.identity.supportedTrust, id: \.self) { Text($0) }
                        }
                    }
                }
                if let error { Text(error).foregroundStyle(.red) }
            }
            .navigationTitle("Explorer")
        }
    }

    private func load() async {
        loading = true
        defer { loading = false }
        error = nil
        agent = nil
        do { agent = try await api.explore(address) }
        catch { self.error = error.localizedDescription }
    }
}
