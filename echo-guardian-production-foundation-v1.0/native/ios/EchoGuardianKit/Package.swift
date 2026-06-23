// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "EchoGuardianKit",
    platforms: [.iOS(.v16)],
    products: [
        .library(name: "EchoGuardianKit", targets: ["EchoGuardianKit"])
    ],
    targets: [
        .target(name: "EchoGuardianKit"),
        .testTarget(name: "EchoGuardianKitTests", dependencies: ["EchoGuardianKit"])
    ]
)
