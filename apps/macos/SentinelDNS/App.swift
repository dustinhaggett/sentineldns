import SwiftUI

@main
struct SentinelDNSApp: App {
    @StateObject private var client = APIClient()

    var body: some Scene {
        WindowGroup {
            DashboardView()
                .environmentObject(client)
                .frame(minWidth: 920, minHeight: 620)
        }
    }
}
