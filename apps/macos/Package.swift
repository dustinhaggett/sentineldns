// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SentinelDNS",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "SentinelDNS", targets: ["SentinelDNS"]),
    ],
    targets: [
        .executableTarget(
            name: "SentinelDNS",
            path: "SentinelDNS",
            resources: [.copy("Resources")]
        ),
    ]
)
