import SwiftUI

struct AlertsView: View {
    @EnvironmentObject var client: APIClient

    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Text("Alerts").font(.title3).bold()
                Spacer()
                Text("\(client.alerts.count) total")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Button("Clear Alerts") {
                    client.clearAlerts()
                }
                .disabled(client.alerts.isEmpty)
            }
            List(client.alerts) { alert in
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Text(alert.timestamp).font(.caption).foregroundStyle(.secondary)
                        Spacer()
                        Text(alert.label)
                            .bold()
                            .foregroundStyle(alertColor(for: alert.label))
                    }
                    Text(alert.summary).font(.body)
                    Text("Action: \(alert.recommendedAction)")
                        .font(.callout)
                    if !alert.reasonTags.isEmpty {
                        Text("Signals: \(alert.reasonTags.joined(separator: ", "))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(.vertical, 4)
            }
        }
        .padding()
    }

    private func alertColor(for label: String) -> Color {
        switch label {
        case "Likely Compromise":
            return .red
        case "Unusual":
            return .orange
        default:
            return .green
        }
    }
}
