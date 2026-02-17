import Foundation

struct DomainScoreResponse: Decodable, Identifiable {
    var id: String { domain + "-" + String(riskScore) }
    let domain: String
    let riskScore: Double
    let riskLabel: String
    let reasonTags: [String]

    enum CodingKeys: String, CodingKey {
        case domain
        case riskScore = "risk_score"
        case riskLabel = "risk_label"
        case reasonTags = "reason_tags"
    }
}

struct WindowScoreResponse: Decodable, Identifiable {
    let id = UUID()
    let anomalyScore: Double
    let anomalyLabel: String
    let summary: String
    let reasonTags: [String]
    let recommendedAction: String

    enum CodingKeys: String, CodingKey {
        case anomalyScore = "anomaly_score"
        case anomalyLabel = "anomaly_label"
        case summary
        case reasonTags = "reason_tags"
        case recommendedAction = "recommended_action"
    }
}

struct ActivityItem: Identifiable {
    let id = UUID()
    let timestamp: String
    let domain: String
    let category: String
    let score: Double
}

struct AlertItem: Identifiable {
    let id = UUID()
    let timestamp: String
    let label: String
    let summary: String
}
