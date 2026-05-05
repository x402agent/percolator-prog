import Foundation
import Combine

final class Settings: ObservableObject {
    static let shared = Settings()

    @Published var serverURL: String {
        didSet { UserDefaults.standard.set(serverURL, forKey: "serverURL") }
    }
    @Published var apiKey: String {
        didSet { UserDefaults.standard.set(apiKey, forKey: "apiKey") }
    }

    private init() {
        let d = UserDefaults.standard
        self.serverURL = d.string(forKey: "serverURL") ?? "http://localhost:8787"
        self.apiKey = d.string(forKey: "apiKey") ?? ""
    }
}
