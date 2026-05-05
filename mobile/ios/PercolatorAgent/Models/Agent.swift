import Foundation

struct AgentService: Codable, Hashable {
    let name: String
    let endpoint: String
}

struct AgentMetadata: Codable {
    let type: String
    let name: String
    let description: String
    let services: [AgentService]
    let registrations: [String]
    let supportedTrust: [String]
}

struct MintRequest: Codable {
    let name: String
    let uri: String
    let metadata: AgentMetadata
    let owner: String?
}

struct MintResult: Codable, Identifiable {
    let asset: String
    let identityPda: String
    let signature: String
    let explorer: String
    var id: String { asset }
}

struct AgentIdentityView: Codable {
    let pda: String
    let services: [AgentService]
    let supportedTrust: [String]
}

struct AgentView: Codable, Identifiable {
    let asset: String
    let owner: String
    let name: String
    let uri: String
    let identity: AgentIdentityView
    let explorer: String
    var id: String { asset }
}

struct RegisterRequest: Codable {
    let name: String
    let description: String?
    let image: String?
    let services: [AgentService]?
    let supportedTrust: [String]?
    let useIx: Bool?
    let dryRun: Bool?
}

struct RegisterResult: Codable {
    let asset: String?
    let signature: String?
    let explorer: String?
    let stdout: String?
    let stderr: String?
    let command: String?
}
