import SwiftUI

struct MintView: View {
    @EnvironmentObject var api: APIClient
    @State private var name = ""
    @State private var uri = ""
    @State private var description = ""
    @State private var owner = ""
    @State private var result: MintResult?
    @State private var error: String?
    @State private var loading = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Agent") {
                    TextField("Name", text: $name)
                    TextField("Metadata URI", text: $uri)
                        .keyboardType(.URL)
                        .autocapitalization(.none)
                    TextField("Description", text: $description, axis: .vertical)
                    TextField("Owner pubkey (optional)", text: $owner)
                        .autocapitalization(.none)
                }
                Section {
                    Button(loading ? "Minting…" : "Mint") { Task { await submit() } }
                        .disabled(name.isEmpty || uri.isEmpty || description.isEmpty || loading)
                }
                if let result {
                    Section("Minted") {
                        LabeledContent("Asset", value: result.asset)
                        LabeledContent("Identity PDA", value: result.identityPda)
                        LabeledContent("Signature", value: result.signature)
                        if let u = URL(string: result.explorer) {
                            Link("Open in explorer", destination: u)
                        }
                    }
                }
                if let error { Text(error).foregroundStyle(.red) }
            }
            .navigationTitle("Mint")
        }
    }

    private func submit() async {
        loading = true
        defer { loading = false }
        error = nil
        result = nil
        do {
            let req = MintRequest(
                name: name,
                uri: uri,
                metadata: AgentMetadata(
                    type: "agent",
                    name: name,
                    description: description,
                    services: [],
                    registrations: [],
                    supportedTrust: []
                ),
                owner: owner.isEmpty ? nil : owner
            )
            result = try await api.mint(req)
        } catch {
            self.error = error.localizedDescription
        }
    }
}
