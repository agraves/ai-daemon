// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ai-daemon",
    platforms: [.macOS(.v13)],
    targets: [
        // The /dev/ai broker. Targets Linux in production; builds on macOS
        // so development needs nothing exotic.
        .executableTarget(name: "aid"),
    ]
)
