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
    public var registerEndpoint: String
    public var keyDeliveryEndpoint: String
    public var revokeEndpoint: String
    /// Where a live session is re-checked. This is the carrier the Android SDK polls in
    /// `KillSwitchManager.checkServerStatusAndApply`: it is how a signed pin rotation and a
    /// revoked install reach a device that is already running. Modes 1 and 2 only.
    public var statusVerifyEndpoint: String

    /// Sentinel v2 endpoints. All three are reached only with a live ZTA session, so none of them
    /// is ever the first thing this app says to the network - attestation is. Modes 1 and 2 only;
    /// a mode 3 host never calls any of them.
    public var securityPackEndpoint: String
    public var telemetryEndpoint: String
    public var sensitiveDecisionEndpoint: String

    /// SPKI (DER, base64) of the offline Security Pack signing key. Absent, no pack is ever
    /// accepted and the client keeps the policy it compiled in - which is the safe default, not a
    /// degraded one.
    public var securityPackSignerSPKIBase64: String?

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

    /// Whether App Attest is requested by the host configuration. Hardened builds require this
    /// to remain true; setting it false is accepted only behind the explicit DEBUG-only
    /// `NEXILIS_ALLOW_ATTESTATION_BYPASS` compile flag. Server/locally cached feature flags cannot
    /// turn mandatory attestation into a trusted state.
    public var appAttestEnabled: Bool

    /// The host's application mode - the same 1/2/3 as `APIS.setAppMode(mode:)`, as
    /// `Utils.getAppMode()`, and as the Android SDK's `mode_app`.
    ///
    /// `.hsa` (1) makes every control in the NX-01..NX-23 remediation a precondition. `.middle`
    /// (2) keeps the server half - App Attest, the ZTA token, the offline park - and drops the
    /// parts that stop the app or the process. `.regular` (3), the default, leaves the service
    /// in charge of whether App Attest applies at all and never holds traffic behind a token.
    ///
    /// Local data protection - database and preference encryption, first-party pinning, no
    /// click-through past a pin mismatch - applies at all three. See SECURITY-LEVELS.md.
    public var appMode: NXAppMode

    /// Lowest iOS major version this app attests from. Must match the service's `minIosMajor`
    /// for this app: below it the service rejects the registration, and a device that was never
    /// going to be accepted is better reported as unsupported than as a failed launch.
    ///
    /// 14 is where App Attest itself begins - `DCAppAttestService` is iOS 14 API. Raising this
    /// does not turn anyone away at app mode 3; it only stops verifying them, so the floor is
    /// kept at what the platform actually supports and the hardware guarantee is left to the
    /// service's AAGUID policy, which is where it belongs.
    public var minimumAppAttestOSMajor: Int

    /// Pins for first-party hosts other than the ZTA host, keyed by host.
    ///
    /// `primaryPin`/`backupPin` are one host's key and its rotation successor - they are not a
    /// list of every domain the app talks to, and matching them is deliberately host-agnostic.
    /// A second first-party domain therefore needs its own entry here, which is what the app
    /// carried before this layer existed. Leaving one out does not weaken pinning; it refuses
    /// every connection to that host.
    public var pinnedHostPins: [String: [String]]

    /// SPKI (DER, base64) of the offline pin-rotation signing key. Hardened release
    /// authorization requires this value; DEBUG builds may omit it while using only the
    /// configured primary/backup pin floor.
    public var rotationSignerSPKIBase64: String?

    /// Release signing/entitlement identity expected by the RASP integrity gate. Hardened
    /// authorization refuses to start until all four are configured.
    public var expectedBundleID: String
    public var expectedApplicationID: String
    public var expectedTeamID: String
    public var expectedAppAttestEnvironment: String

    /// Builds a configuration from the compiled-in values - OneApp's, today.
    public init() {
        self.baseURL = NXEncryptedAPIBaseURL()
        self.challengeEndpoint = NXEncryptedChallengeEndpoint()
        self.attestEndpoint = NXEncryptedAttestEndpoint()
        self.registerEndpoint = NXEncryptedRegisterEndpoint()
        self.keyDeliveryEndpoint = NXEncryptedKeyEndpoint()
        self.revokeEndpoint = NXEncryptedRevokeEndpoint()
        self.statusVerifyEndpoint = NXEncryptedAPIBaseURL() + "zta/status/verify"
        self.securityPackEndpoint = NXEncryptedAPIBaseURL() + "zta/security-pack"
        self.telemetryEndpoint = NXEncryptedAPIBaseURL() + "zta/telemetry/events"
        self.sensitiveDecisionEndpoint = NXEncryptedAPIBaseURL() + "zta/sensitive/decision"
        self.securityPackSignerSPKIBase64 = nil
        self.primaryPin = NXEncryptedPrimaryPin()
        self.backupPin = NXEncryptedBackupPin()
        self.appName = NXEncryptedAppName()
        self.apiKey = NXEncryptedAPIKey()
        self.featureAccessURL = NXEncryptedFeatureAccessURL()
        self.supportEmail = "support@nexilis.io"
        self.appAttestEnabled = true
        // Whatever the app mode already is, not a hardcoded Regular. A host that declared its
        // mode through APIS.setAppMode(mode:) and then hands over a default-built configuration
        // would otherwise be silently downgraded by its own configure() call.
        self.appMode = NXSecurityPolicy.mode
        self.pinnedHostPins = ["newuniverse.io": [NXEncryptedNewUniversePin()]]
        self.minimumAppAttestOSMajor = 14
        self.rotationSignerSPKIBase64 = nil
        self.expectedBundleID = Bundle.main.bundleIdentifier ?? ""
        self.expectedApplicationID = ""
        self.expectedTeamID = ""
        self.expectedAppAttestEnvironment = ""
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
    ///   - appAttestEnabled: must be true at `.hsa` and `.middle`, where a false value is
    ///     accepted only by an explicit DEBUG-only attestation-bypass build. At `.regular` it is
    ///     the host's own switch again, and the service's `device_check_attestation` flag can
    ///     also turn attestation off.
    ///   - appMode: `.hsa` (1), `.middle` (2) or `.regular` (3, the default). See the property.
    public init(baseURL: String,
                appName: String,
                apiKey: String,
                primaryPin: String? = nil,
                backupPin: String? = nil,
                featureAccessURL: String? = nil,
                appAttestEnabled: Bool = true,
                appMode: NXAppMode = .regular,
                pinnedHostPins: [String: [String]]? = nil,
                minimumAppAttestOSMajor: Int? = nil,
                rotationSignerSPKIBase64: String? = nil,
                securityPackSignerSPKIBase64: String? = nil,
                expectedBundleID: String? = nil,
                expectedApplicationID: String? = nil,
                expectedTeamID: String? = nil,
                expectedAppAttestEnvironment: String? = nil) {
        self.init()
        let root = baseURL.hasSuffix("/") ? String(baseURL.dropLast()) : baseURL
        self.baseURL = root + "/"
        self.challengeEndpoint = root + "/zta/challenge"
        self.attestEndpoint = root + "/zta/attest"
        self.registerEndpoint = root + "/zta/register"
        self.keyDeliveryEndpoint = root + "/zta/key"
        self.revokeEndpoint = root + "/zta/revoke"
        self.statusVerifyEndpoint = root + "/zta/status/verify"
        self.securityPackEndpoint = root + "/zta/security-pack"
        self.telemetryEndpoint = root + "/zta/telemetry/events"
        self.sensitiveDecisionEndpoint = root + "/zta/sensitive/decision"
        self.appName = appName
        self.apiKey = apiKey
        if let primaryPin { self.primaryPin = primaryPin }
        if let backupPin { self.backupPin = backupPin }
        if let featureAccessURL { self.featureAccessURL = featureAccessURL }
        self.appAttestEnabled = appAttestEnabled
        self.appMode = appMode
        if let pinnedHostPins { self.pinnedHostPins = pinnedHostPins }
        if let minimumAppAttestOSMajor { self.minimumAppAttestOSMajor = minimumAppAttestOSMajor }
        self.rotationSignerSPKIBase64 = rotationSignerSPKIBase64
        self.securityPackSignerSPKIBase64 = securityPackSignerSPKIBase64
        if let expectedBundleID { self.expectedBundleID = expectedBundleID }
        if let expectedApplicationID { self.expectedApplicationID = expectedApplicationID }
        if let expectedTeamID { self.expectedTeamID = expectedTeamID }
        if let expectedAppAttestEnvironment { self.expectedAppAttestEnvironment = expectedAppAttestEnvironment }
    }
}
