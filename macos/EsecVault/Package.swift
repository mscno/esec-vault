// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "EsecVault",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "EsecVault", targets: ["EsecVault"]),
    ],
    targets: [
        // Models and the esec-vault runner: no UI, so they are testable.
        .target(name: "EsecVaultCore"),
        .executableTarget(name: "EsecVault", dependencies: ["EsecVaultCore"]),
        .testTarget(name: "EsecVaultCoreTests", dependencies: ["EsecVaultCore"]),
    ]
)
