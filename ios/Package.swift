// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "ISignClient", platforms: [.macOS(.v13)], products: [.library(name: "ISignCore", targets: ["ISignCore"])], targets: [.target(name: "ISignCore", path: "ISignClient/iSign/Core"), .testTarget(name: "ISignCoreTests", dependencies: ["ISignCore"], path: "Tests/ISignCoreTests")])
