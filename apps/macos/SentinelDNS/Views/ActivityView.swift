import SwiftUI

struct ActivityView: View {
    @EnvironmentObject var client: APIClient

    var body: some View {
        VStack(alignment: .leading) {
            Text("Recent Domains").font(.title3).bold()
            Table(client.activity) {
                TableColumn("Time") { item in Text(item.timestamp) }
                TableColumn("Domain") { item in Text(item.domain) }
                TableColumn("Category") { item in Text(item.category) }
                TableColumn("Score") { item in Text(String(format: "%.1f", item.score)) }
            }
        }
        .padding()
    }
}
