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
        .target(name: "EsecVaultUI", dependencies: ["EsecVaultCore"]),
        .executableTarget(name: "EsecVault", dependencies: ["EsecVaultUI"]),
        .testTarget(name: "EsecVaultCoreTests", dependencies: ["EsecVaultCore", "EsecVaultUI"]),
    ]
)
