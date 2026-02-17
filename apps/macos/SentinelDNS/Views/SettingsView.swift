import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var client: APIClient

    var body: some View {
        Form {
            TextField("Service URL", text: $client.serviceURL)
            Toggle("Use Simulation", isOn: $client.useSimulation)
            HStack {
                Text("Connection")
                Spacer()
                Text(client.serviceState.rawValue)
                    .foregroundStyle(client.serviceState == .online ? .green : .orange)
                Button("Check") {
                    Task { await client.checkServiceHealth() }
                }
            }
            Text("If service is down, start it locally and run the demo again.")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .padding()
    }
}
