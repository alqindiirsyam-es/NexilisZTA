// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "NexilisZTA",
    platforms: [.iOS(.v15)],
    products: [
        .library(name: "NexilisZTA", targets: ["NexilisZTA"])
    ],
    targets: [
        .target(
            name: "NexilisZTACore",
            path: "NexilisZTA/Source",
            sources: [
                "Attestation/AppAttestManager.m",
                "Encryption/EncryptedStrings.mm",
                "Encryption/StringEncryptor.mm",
                "GlobalState.m",
                "RASP/rasp_native.c",
                "RASP/RASPBridge.m",
                "RASP/RASPGuard.m",
                "Security/EnvironmentReport.m",
                "Security/NetworkPosture.m",
                "Security/NXSecurityPolicy.m",
                "Security/PrivacyShield.m",
                "Security/SessionManager.m"
            ],
            publicHeadersPath: ".",
            // CocoaPods flattens every public header into one directory, so the
            // `#import "RASPGuard.h"` style used throughout resolves without help.
            // SwiftPM keeps the tree as it is, so each directory holding a header has
            // to be on the search path for those same imports to resolve.
            cSettings: [
                .headerSearchPath("."),
                .headerSearchPath("Attestation"),
                .headerSearchPath("Encryption"),
                .headerSearchPath("RASP"),
                .headerSearchPath("Security")
            ]
        ),
        .target(
            name: "NexilisZTA",
            dependencies: ["NexilisZTACore"],
            path: "NexilisZTA/Source",
            sources: [
                "APISZTA.swift",
                "AppAttestService.swift",
                "Input/SecureInputHardening.swift",
                "Input/SecureNumericKeypad.swift",
                "Network/PinnedURLSessionDelegate.swift",
                "Network/SecureWebViewFactory.swift",
                "NexilisZTA.swift",
                "NXLogger.swift",
                "Security/DuressAndGeofence.swift",
                "Security/OnDeviceStatisticalModel.swift",
                "Security/SecurityPackPolicyValidator.swift",
                "Security/ProtectedAssetStore.swift",
                "Security/SecuritySupport.swift",
                "Security/TelemetryLoop.swift",
                "Security/ThreatIntelMatcher.swift",
                "Support/ZTAReachability.swift",
                "UI/ZTAErrorViewController.swift"
            ]
        )
    ],
    cxxLanguageStandard: .gnucxx20
)
