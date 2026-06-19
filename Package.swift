// swift-tools-version:6.0
// AgePony Phase 1a — Crypto Core
// Pure-Swift implementation of the age encryption protocol primitives.
// No third-party dependencies. CryptoKit (Apple) only.
//
// Hotfix 2 on 1g: AgePonyCore now compiles with -O optimization even in
// Debug builds. Without this, scrypt at N=2^18 takes minutes instead of
// seconds on iPhone — Swift's Array<UInt8> bounds checking + lack of
// generic specialization in unoptimized builds is catastrophic for
// crypto inner loops. -O in Debug means slightly less precise debug
// information for AgePonyCore code (irrelevant in practice; it's a
// stable lib), in exchange for usable crypto performance during dev.

import PackageDescription

let package = Package(
    name: "AgePonyCore",
    platforms: [
        .iOS(.v18),
        .macOS(.v14)  // for `swift test` from the terminal during dev
    ],
    products: [
        .library(
            name: "AgePonyCore",
            targets: ["AgePonyCore"]
        ),
    ],
    dependencies: [],
    targets: [
        .target(
            name: "AgePonyCore",
            dependencies: [],
            path: "Sources/AgePonyCore",
            swiftSettings: [
                // Force -O even in Debug. Without this, scrypt is unusable
                // on iPhone during development.
                .unsafeFlags(["-O"], .when(configuration: .debug))
            ]
        ),
        .testTarget(
            name: "AgePonyCoreTests",
            dependencies: ["AgePonyCore"],
            path: "Tests/AgePonyCoreTests"
        ),
    ]
)
