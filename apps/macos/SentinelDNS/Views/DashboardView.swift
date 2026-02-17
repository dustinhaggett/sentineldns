import SwiftUI

struct DashboardView: View {
    @EnvironmentObject var client: APIClient

    var body: some View {
        TabView {
            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    Text("Status:")
                    Text(client.status)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 6)
                        .background(statusColor.opacity(0.2))
                        .foregroundColor(statusColor)
                        .clipShape(Capsule())
                    Spacer()
                    Button("Run Demo") {
                        Task { await client.runDemo() }
                    }
                }
                Text(client.statusMessage).font(.body)
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
    }

    private var statusColor: Color {
        switch client.status {
        case "Likely Compromise": return .red
        case "Unusual": return .orange
        default: return .green
        }
    }
}
