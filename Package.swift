// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
  name: "ConvexAuth0",
  platforms: [.iOS(.v14), .macOS(.v11)],
  products: [
    // Products define the executables and libraries a package produces, making them visible to other packages.
    .library(
      name: "ConvexAuth0",
      targets: ["ConvexAuth0"])
  ],
  dependencies: [
    .package(url: "https://github.com/get-convex/convex-swift", "0.8.0"..<"0.9.0"),
    .package(url: "https://github.com/auth0/Auth0.swift", exact: "2.17.0"),
  ],
  targets: [
    // Targets are the basic building blocks of a package, defining a module or a test suite.
    // Targets can depend on other targets in this package and products from dependencies.
    .target(
      name: "ConvexAuth0",
      dependencies: [
        .product(name: "ConvexMobile", package: "convex-swift"),
        .product(name: "Auth0", package: "Auth0.swift"),
      ]),
    .testTarget(
      name: "ConvexAuth0Tests",
      dependencies: ["ConvexAuth0"]
    ),
  ]
)
