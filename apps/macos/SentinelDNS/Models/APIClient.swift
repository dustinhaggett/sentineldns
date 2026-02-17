import Foundation

@MainActor
final class APIClient: ObservableObject {
    @Published var serviceURL: String = "http://127.0.0.1:8787"
    @Published var useSimulation: Bool = true
    @Published var status: String = "Normal"
    @Published var statusMessage: String = "Ready"
    @Published var activity: [ActivityItem] = []
    @Published var alerts: [AlertItem] = []
    @Published var serviceError: String?

    func runDemo() async {
        serviceError = nil
        guard let simURL = Bundle.module.url(forResource: "SampleSimulatedEvents", withExtension: "jsonl")
            ?? URL(string: "file://\(FileManager.default.currentDirectoryPath)/SentinelDNS/Resources/SampleSimulatedEvents.jsonl")
        else {
            statusMessage = "Simulation file missing."
            return
        }
        do {
            let text = try String(contentsOf: simURL)
            let lines = text.split(separator: "\n")
            var windowBatch: [[String: Any]] = []
            for line in lines {
                guard let data = line.data(using: .utf8),
                      let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                      let domain = obj["domain"] as? String,
                      let ts = obj["ts"] as? String
                else { continue }

                let score = try await scoreDomain(domain: domain)
                activity.insert(ActivityItem(timestamp: ts, domain: domain, category: score.riskLabel, score: score.riskScore), at: 0)
                if activity.count > 80 { activity.removeLast() }
                windowBatch.append(obj)
            }
            if !windowBatch.isEmpty {
                let alert = try await scoreWindow(events: windowBatch)
                alerts.insert(alert, at: 0)
                if alerts.count > 30 { alerts.removeLast() }
                status = alert.label
                statusMessage = alert.summary
            }
        } catch {
            serviceError = "Start the service: python -m sentineldns.service.run --host 127.0.0.1 --port 8787"
            statusMessage = "Service unavailable. \(error.localizedDescription)"
        }
    }

    private func scoreDomain(domain: String) async throws -> DomainScoreResponse {
        var req = URLRequest(url: URL(string: "\(serviceURL)/score/domain")!)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONEncoder().encode(["domain": domain])
        let (data, resp) = try await URLSession.shared.data(for: req)
        guard let http = resp as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            throw URLError(.badServerResponse)
        }
        return try JSONDecoder().decode(DomainScoreResponse.self, from: data)
    }

    private func scoreWindow(events: [[String: Any]]) async throws -> AlertItem {
        let domains = events.compactMap { $0["domain"] as? String }
        let tsStart = events.first?["ts"] as? String ?? ""
        let tsEnd = events.last?["ts"] as? String ?? ""
        let payload: [String: Any] = [
            "window_start": tsStart,
            "window_end": tsEnd,
            "queries_per_min": Double(events.count) / 5.0,
            "unique_domains": Set(domains).count,
            "nxdomain_rate": Double(events.filter { ($0["rcode"] as? String) == "NXDOMAIN" }.count) / Double(max(events.count, 1)),
            "mean_domain_risk": Double(activity.prefix(events.count).map(\.score).reduce(0, +)) / Double(max(events.count, 1)),
            "high_risk_domain_ratio": Double(activity.prefix(events.count).filter { $0.score > 70 }.count) / Double(max(events.count, 1)),
            "newly_seen_ratio": 0.4,
            "periodicity_score": 1.2
        ]
        var req = URLRequest(url: URL(string: "\(serviceURL)/score/window")!)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: payload)
        let (data, resp) = try await URLSession.shared.data(for: req)
        guard let http = resp as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            throw URLError(.badServerResponse)
        }
        let decoded = try JSONDecoder().decode(WindowScoreResponse.self, from: data)
        return AlertItem(timestamp: tsEnd, label: decoded.anomalyLabel, summary: decoded.summary)
    }
}
