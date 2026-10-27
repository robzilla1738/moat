// swift-tools-version:5.9
//
// MoatKit: the testable heart of the macOS endpoint.
//
// * MoatKit         filter engine, typed XPC control surface, policy store, event spool, recovery model
// * MoatCoreBridge  Swift wrapper over the Rust moat-core C ABI (core/moat-ffi). Needs libmoat_ffi.a:
//                   run ../scripts/build-ffi.sh, then pass -Xlinker -L../build/ffi to swift build/test.
// * MoatUI          SwiftUI screens shared by the app (and rendered to PNGs by the screenshot test)
import PackageDescription

let package = Package(
    name: "MoatKit",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "MoatKit", targets: ["MoatKit"]),
        .library(name: "MoatCoreBridge", targets: ["MoatCoreBridge"]),
        .library(name: "MoatUI", targets: ["MoatUI"]),
    ],
    targets: [
        .target(name: "MoatKit"),
        .systemLibrary(name: "CMoatFFI", path: "Sources/CMoatFFI"),
        .target(name: "MoatCoreBridge", dependencies: ["MoatKit", "CMoatFFI"]),
        .target(name: "MoatUI", dependencies: ["MoatKit"]),
        .testTarget(name: "MoatKitTests", dependencies: ["MoatKit"]),
        .testTarget(name: "MoatCoreBridgeTests", dependencies: ["MoatCoreBridge", "MoatKit"], exclude: ["Fixtures"]),
        .testTarget(name: "MoatUITests", dependencies: ["MoatUI", "MoatKit"]),
    ]
)
