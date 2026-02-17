import SwiftUI

struct DashboardView: View {
    @EnvironmentObject var client: APIClient

    var body: some View {
        TabView {
            VStack(alignment: .leading, spacing: 18) {
                HStack {
                    Text("Status:")
                    Text(client.status)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 6)
                        .background(statusColor.opacity(0.2))
                        .foregroundColor(statusColor)
                        .clipShape(Capsule())
                    Spacer()
                    Button(client.isRunningDemo ? "Running..." : "Run Demo") {
                        Task { await client.runDemo() }
                    }
                    .disabled(client.isRunningDemo)
                }
                HStack(spacing: 10) {
                    Text("Service:")
                    Text(client.serviceState.rawValue)
                        .foregroundStyle(client.serviceState == .online ? .green : .orange)
                    Spacer()
                    Button("Check Connection") {
                        Task { await client.checkServiceHealth() }
                    }
                }

                Text(client.statusMessage).font(.body)
                Text("Last demo run: \(client.lastDemoRunAt)")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                GroupBox("Quick Domain Lookup") {
                    HStack {
                        TextField("example.com", text: $client.searchedDomain)
                        Button("Score") {
                            Task { await client.lookupDomain() }
                        }
                    }
                    if let lookup = client.latestLookup {
                        Divider().padding(.vertical, 4)
                        Text("\(lookup.domain) -> \(lookup.riskLabel) (\(String(format: "%.1f", lookup.riskScore)))")
                            .font(.callout)
                        Text(lookup.reasonTags.joined(separator: ", "))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                if let error = client.serviceError {
                    Text(error)
                        .foregroundStyle(.orange)
                        .font(.callout)
                }
                Spacer()
            }
            .padding()
            .tabItem { Text("Dashboard") }

            ActivityView()
                .tabItem { Text("Activity") }

            AlertsView()
                .tabItem { Text("Alerts") }

            SettingsView()
                .tabItem { Text("Settings") }
        }
        .task {
            await client.checkServiceHealth()
        }
    }

    private var statusColor: Color {
        switch client.status {
        case "Likely Compromise": return .red
        case "Unusual": return .orange
        default: return .green
        }
    }
}
