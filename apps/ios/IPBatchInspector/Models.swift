import Foundation

struct NodeEndpoint: Codable, Hashable, Sendable {
    let protocolName: String
    let name: String
    let host: String
    let port: Int?
    let chain: String

    enum CodingKeys: String, CodingKey {
        case protocolName = "protocol"
        case name, host, port, chain
    }
}

struct EntranceResult: Codable, Identifiable, Sendable {
    var id: String { name }
    let name: String
    let kind: String
    let host: String
    let httpCode: Int?
    let status: String
    let detail: String
    let checkedAt: String
}

struct SourceEvidence: Codable, Sendable {
    let source: String
    let ok: Bool
    let elapsedMilliseconds: Int
    let checkedAt: String
    let fields: [String: String]
    let error: String?
}

struct IPResult: Codable, Identifiable, Sendable {
    var id: String { ip }
    let ip: String
    var status: String
    var country: String = ""
    var countryCode: String = ""
    var asn: String = ""
    var organization: String = ""
    var riskScores: [String: Int] = [:]
    var signals: [String: String] = [:]
    var consensus: [String: String] = [:]
    var conflicts: [String] = []
    var confidence = "none"
    var evidence: [SourceEvidence] = []
    var conclusionBoundary = "Third-party evidence only; accuracy and future platform acceptance are not guaranteed."
}

struct SubscriptionResult: Codable {
    let nodeCount: Int
    let protocolCounts: [String: Int]
    let nodes: [NodeEndpoint]
    let directExposedPublicIPs: [String]
    let dnsObservations: [String: [String]]
    let unobservableExitNodeCount: Int
    let localOrReserved: [String]
    let intelligence: [IPResult]
    let warnings: [String]
    let rawContentPersisted: Bool
    let networkBoundary: String
}

enum JSONRender {
    static func string<T: Encodable>(_ value: T) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        guard let data = try? encoder.encode(value) else { return "Unable to render result." }
        return String(decoding: data, as: UTF8.self)
    }
}
