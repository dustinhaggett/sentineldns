import SwiftUI

struct ActivityView: View {
    @EnvironmentObject var client: APIClient
    @State private var query = ""
    @State private var showOnlyFlagged = false

    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Text("Recent Domains").font(.title3).bold()
                Spacer()
                Button("Clear Activity") {
                    client.clearActivity()
                }
                .disabled(client.activity.isEmpty)
            }
            HStack {
                TextField("Filter domain", text: $query)
                Toggle("Suspicious+", isOn: $showOnlyFlagged)
                    .toggleStyle(.switch)
            }
            .padding(.bottom, 8)
            Table(filteredItems) {
                TableColumn("Time") { item in Text(item.timestamp) }
                TableColumn("Domain") { item in Text(item.domain) }
                TableColumn("Category") { item in Text(item.category) }
                TableColumn("Score") { item in Text(String(format: "%.1f", item.score)) }
            }
        }
        .padding()
    }

    private var filteredItems: [ActivityItem] {
        client.activity.filter { item in
            let queryPass = query.isEmpty || item.domain.localizedCaseInsensitiveContains(query)
            let flaggedPass = !showOnlyFlagged || item.category != "Normal"
            return queryPass && flaggedPass
        }
    }
}
