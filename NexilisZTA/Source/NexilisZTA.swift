//
//  NexilisZTA.swift
//  NexilisZTA
//
//  What the layer is configured with. What it does with it lives in APISZTA.swift.
//

import Foundation

#if SWIFT_PACKAGE
// CocoaPods builds Swift and Objective-C as one mixed-language target, so these
// types are already in scope. SwiftPM has no mixed target, so the Objective-C and
// C half is its own module and has to be imported.
//
// Re-exported so that `import NexilisZTA` alone puts RASPGuard, AppAttestManager,
// stateGet/stateSet and the NXEncrypted* functions in scope, exactly as the pod
// does. Without this a SwiftPM consumer would have to import the core module too,
// and the same integration code would not compile under both build systems.
@_exported import NexilisZTACore
#endif

/// Everything the ZTA layer needs from the app that embeds it.
///
/// The values used to be compiled into `EncryptedStrings.m` as OneApp's own, which is fine while
/// the code lives inside OneApp and impossible once a second host exists. They are settings now,
/// and every one of them still falls back to what OneApp was already using - a host that says
/// nothing keeps the behaviour it had.
public struct NexilisZTAConfiguration {

    /// Base of the ZTA service. The endpoints below are derived from it unless given.
    public var baseURL: String

    public var challengeEndpoint: String
    public var attestEndpoint: String
    public var assertEndpoint: String
    public var statusVerifyEndpoint: String
    public var registerEndpoint: String
    public var keyDeliveryEndpoint: String
    public var revokeEndpoint: String

    /// SPKI pins for the ZTA host, `sha256/<base64>`. Backup is what a rotation switches to.
    public var primaryPin: String
    public var backupPin: String

    /// Identity the host is known by on the Nexilis side.
    public var appName: String
    public var apiKey: String

    /// Where the feature-access policy is pulled from.
    public var featureAccessURL: String

    /// Address the failure screen's "Hubungi Support" opens a mail to.
    public var supportEmail: String

    /// Builds a configuration from the compiled-in values - OneApp's, today.
    public init() {
        self.baseURL = NXEncryptedAPIBaseURL()
        self.challengeEndpoint = NXEncryptedChallengeEndpoint()
        self.attestEndpoint = NXEncryptedAttestEndpoint()
        self.assertEndpoint = NXEncryptedAssertEndpoint()
        self.statusVerifyEndpoint = NXEncryptedStatusVerifyEndpoint()
        self.registerEndpoint = NXEncryptedRegisterEndpoint()
        self.keyDeliveryEndpoint = NXEncryptedKeyEndpoint()
        self.revokeEndpoint = NXEncryptedRevokeEndpoint()
        self.primaryPin = NXEncryptedPrimaryPin()
        self.backupPin = NXEncryptedBackupPin()
        self.appName = NXEncryptedAppName()
        self.apiKey = NXEncryptedAPIKey()
        self.featureAccessURL = NXEncryptedFeatureAccessURL()
        self.supportEmail = "support@nexilis.io"
    }

    /// Points every endpoint at a service of the host's own, keeping the paths.
    ///
    /// - Parameters:
    ///   - baseURL: root of the ZTA service, with or without a trailing slash.
    ///   - appName: identity the host is known by.
    ///   - apiKey: key issued for that identity.
    ///   - primaryPin: SPKI pin of the ZTA host, `sha256/<base64>`. Nil keeps the built-in one.
    ///   - backupPin: the pin a rotation switches to. Nil keeps the built-in one.
    ///   - featureAccessURL: where the feature-access policy is pulled from. Nil keeps the
    ///     compiled-in one, which is not derived from `baseURL` - it sits at its own path on its
    ///     own host - so a host running its own policy service has to name it here.
    public init(baseURL: String,
                appName: String,
                apiKey: String,
                primaryPin: String? = nil,
                backupPin: String? = nil,
                featureAccessURL: String? = nil) {
        self.init()
        let root = baseURL.hasSuffix("/") ? String(baseURL.dropLast()) : baseURL
        self.baseURL = root + "/"
        self.challengeEndpoint = root + "/zta/challenge"
        self.attestEndpoint = root + "/zta/attest"
        self.assertEndpoint = root + "/zta/assert"
        self.statusVerifyEndpoint = root + "/zta/status/verify"
        self.registerEndpoint = root + "/zta/register"
        self.keyDeliveryEndpoint = root + "/zta/key"
        self.revokeEndpoint = root + "/zta/revoke"
        self.appName = appName
        self.apiKey = apiKey
        if let primaryPin { self.primaryPin = primaryPin }
        if let backupPin { self.backupPin = backupPin }
        if let featureAccessURL { self.featureAccessURL = featureAccessURL }
    }
}
