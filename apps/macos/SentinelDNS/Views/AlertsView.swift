import SwiftUI

struct AlertsView: View {
    @EnvironmentObject var client: APIClient

    var body: some View {
        VStack(alignment: .leading) {
            Text("Alerts").font(.title3).bold()
            List(client.alerts) { alert in
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Text(alert.timestamp).font(.caption).foregroundStyle(.secondary)
                        Spacer()
                        Text(alert.label).bold()
                    }
                    Text(alert.summary).font(.body)
                }
                .padding(.vertical, 4)
            }
        }
        .padding()
    }
}
