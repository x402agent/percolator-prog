import Foundation

enum APIError: LocalizedError {
    case badURL
    case http(Int, String)
    case decoding(Error)

    var errorDescription: String? {
        switch self {
        case .badURL: return "Invalid server URL"
        case .http(let code, let body): return "HTTP \(code): \(body)"
        case .decoding(let e): return "Decoding error: \(e.localizedDescription)"
        }
    }
}

@MainActor
final class APIClient: ObservableObject {
    private let settings: Settings
    private let session: URLSession

    init(settings: Settings, session: URLSession = .shared) {
        self.settings = settings
        self.session = session
    }

    func register(_ req: RegisterRequest) async throws -> RegisterResult {
        try await post("/agents/register", body: req)
    }

    func mint(_ req: MintRequest) async throws -> MintResult {
        try await post("/agents/mint", body: req)
    }

    func explore(_ address: String) async throws -> AgentView {
        try await get("/agents/\(address)")
    }

    private func post<B: Encodable, R: Decodable>(_ path: String, body: B) async throws -> R {
        var req = try makeRequest(path: path, method: "POST")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONEncoder().encode(body)
        return try await send(req)
    }

    private func get<R: Decodable>(_ path: String) async throws -> R {
        let req = try makeRequest(path: path, method: "GET")
        return try await send(req)
    }

    private func makeRequest(path: String, method: String) throws -> URLRequest {
        guard let url = URL(string: settings.serverURL + path) else { throw APIError.badURL }
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.setValue(settings.apiKey, forHTTPHeaderField: "x-api-key")
        return req
    }

    private func send<R: Decodable>(_ req: URLRequest) async throws -> R {
        let (data, resp) = try await session.data(for: req)
        guard let http = resp as? HTTPURLResponse else { throw APIError.http(0, "no response") }
        guard (200..<300).contains(http.statusCode) else {
            throw APIError.http(http.statusCode, String(data: data, encoding: .utf8) ?? "")
        }
        do { return try JSONDecoder().decode(R.self, from: data) }
        catch { throw APIError.decoding(error) }
    }
}
