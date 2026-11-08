// swift-tools-version: 6.0
import PackageDescription
let package = Package(name: "SzuSecureLink", platforms: [.macOS(.v13)], products: [
    .library(name: "SecureLinkCore", targets: ["SecureLinkCore"]),
    .executable(name: "szu-securelink-probe", targets: ["SecureLinkProbe"]),
    .executable(name: "szu-securelink", targets: ["SecureLinkApp"])
], targets: [.target(name: "SecureLinkCore"),
             .target(name: "SecureLinkTransport", dependencies: ["SecureLinkCore"]),
             .executableTarget(name: "SecureLinkProbe", dependencies: ["SecureLinkCore", "SecureLinkTransport"]),
             .executableTarget(name: "SecureLinkApp", dependencies: ["SecureLinkCore", "SecureLinkTransport"]),
             .testTarget(name: "SecureLinkCoreTests", dependencies: ["SecureLinkCore", "SecureLinkTransport"], path: "tests/SecureLinkCoreTests")])
