import SwiftUI

struct RegisterView: View {
    @EnvironmentObject var api: APIClient
    @State private var name = ""
    @State private var description = ""
    @State private var image = ""
    @State private var servicesJSON = ""
    @State private var dryRun = true
    @State private var result: RegisterResult?
    @State private var error: String?
    @State private var loading = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Agent") {
                    TextField("Name", text: $name)
                    TextField("Description", text: $description, axis: .vertical)
                    TextField("Image path or URL", text: $image)
                    TextField("Services JSON (optional)", text: $servicesJSON, axis: .vertical)
                    Toggle("Dry run (return command only)", isOn: $dryRun)
                }
                Section {
                    Button(loading ? "Registering…" : "Register") { Task { await submit() } }
                        .disabled(name.isEmpty || loading)
                }
                if let result {
                    Section("Result") {
                        if let cmd = result.command { LabeledContent("Command", value: cmd) }
                        if let asset = result.asset { LabeledContent("Asset", value: asset) }
                        if let sig = result.signature { LabeledContent("Signature", value: sig) }
                        if let url = result.explorer, let u = URL(string: url) {
                            Link("Open in explorer", destination: u)
                        }
                    }
                }
                if let error { Text(error).foregroundStyle(.red) }
            }
            .navigationTitle("Register")
        }
    }

    private func submit() async {
        loading = true
        defer { loading = false }
        error = nil
        result = nil
        do {
            let services: [AgentService]? = servicesJSON.isEmpty ? nil :
                try JSONDecoder().decode([AgentService].self, from: Data(servicesJSON.utf8))
            let req = RegisterRequest(
                name: name,
                description: description.isEmpty ? nil : description,
                image: image.isEmpty ? nil : image,
                services: services,
                supportedTrust: nil,
                useIx: nil,
                dryRun: dryRun
            )
            result = try await api.register(req)
        } catch {
            self.error = error.localizedDescription
        }
    }
}
