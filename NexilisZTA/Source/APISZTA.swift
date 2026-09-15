//
//  APISZTA.swift
//  NexilisZTA
//
//  The one call a host app makes. Everything the ZTA layer does happens behind it.
//

import Foundation
import UIKit

#if SWIFT_PACKAGE
// CocoaPods builds Swift and Objective-C as one mixed-language target, so these
// types are already in scope. SwiftPM has no mixed target, so the Objective-C and
// C half is its own module and has to be imported. The re-export that puts those
// types in a consumer's scope lives in NexilisZTA.swift, once for the module.
import NexilisZTACore
#endif

// MARK: - Notifications

public extension Notification.Name {

    /// Verification passed and the host may start its session. Same string OneApp already listens
    /// for, so a host that watches the notification instead of the callback keeps working.
    static let ztaSessionReady = Notification.Name("io.nexilis.appSessionReady")

    /// Verification failed for good, after every automatic attempt. `userInfo["error"]` carries it.
    static let ztaSessionError = Notification.Name("io.nexilis.appSessionError")

    /// Something asked for the chain to be run again - the error screen's button, usually.
    static let ztaSessionRetry = Notification.Name("io.nexilis.appSessionRetry")

    /// Runtime RASP found a condition that invalidates the current authorization.
    static let ztaRuntimeCompromised = Notification.Name("io.nexilis.zta.runtimeCompromise")
}

// MARK: - APISZTA

/// The ZTA layer as a whole.
///
/// One call runs the lot: certificate pinning, the feature-access gate, App Attest registration,
/// assertion and key delivery, the retries in between, and the screen a reader sees if it will not
/// pass. The host is told only the thing it needs to act on - verification succeeded - and starts
/// its own session then, and only then.
///
/// ```swift
/// APISZTA.configure(baseURL: ztaBaseURL,
///                   appName: appName,
///                   apiKey: apiKey,
///                   primaryPin: ztaPrimaryPin) {
///     APIS.connect(appName: appName, apiKey: apiKey, delegate: self)
/// }
/// ```
///
/// The RASP half - jailbreak, debugger, Frida, injection and hook detection, states 1 to 15 - has
/// already run by the time any of this is reached: `RASPBridge` installs it from `+load`, before
/// `main`. What this drives is everything after it.
public enum APISZTA {

    // MARK: - Configuration

    private static var stored = NexilisZTAConfiguration()
    private static let lock = NSLock()

    /// What the layer is running on. Never nil - before `configure` it is the compiled-in set.
    public static var configuration: NexilisZTAConfiguration {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }

    // MARK: - Chain state
    //
    // Every field below is read and written on the main queue only, which is where the chain runs.
    // The callbacks it waits on - DeviceCheck, the Secure Enclave, five network round trips - come
    // back on queues of their own, and `AppAttestService` already hops to main before calling us.

    /// The host's success callback. Held until verification passes, then called once per pass.
    private static var onReady: (() -> Void)?
    /// The host's failure callback, called when the automatic attempts are spent.
    private static var onFailure: ((Error) -> Void)?
    /// Whether the layer puts its own screen up when verification is finally given up on.
    private static var showsErrorScreen = true
    /// Whether the app ever got as far as a passing verification this launch.
    ///
    /// This one value crosses threads: every protected send, upload and download asks for it
    /// through `hasValidAuthorization`, and `TMessage.pack()` asks for it on the outgoing thread.
    /// It used to be read with `DispatchQueue.main.sync`, which deadlocks - `Nexilis.writeSync`
    /// spins on the main thread waiting for `isProcessWriteSync` while the background thread
    /// holding that flag calls `pack()`, which then blocks on a main thread that is never coming
    /// back. A lock costs nothing here and cannot deadlock against the main thread.
    ///
    /// Everything else in the chain's state stays main-thread-confined, so the check-then-act
    /// reads below (`guard !sessionReady`) are still atomic with respect to the only writers.
    private static let sessionReadyLock = NSLock()
    private static var _sessionReady = false
    private static var sessionReady: Bool {
        get {
            sessionReadyLock.lock()
            defer { sessionReadyLock.unlock() }
            return _sessionReady
        }
        set {
            sessionReadyLock.lock()
            _sessionReady = newValue
            sessionReadyLock.unlock()
        }
    }
    /// How many times verification has been tried since the last success.
    private static var attempts = 0
    /// Tried this many times quietly before the reader is shown anything. A cold launch after the
    /// app has been closed for days has to do DNS, TLS with pinning, and five sequential round
    /// trips before it can succeed; three tries six seconds apart gave up while the radio was
    /// still coming up, which is the failure a reader saw as "Verifikasi Gagal" on a connection
    /// that was about to be perfectly fine.
    private static let maxAutomaticAttempts = 6
    /// Backoff never grows past this, so a long wait stays a wait and not an abandonment.
    private static let maxBackoff: TimeInterval = 16
    /// One verification chain at a time. The backoff timer, the retry button and every resume all
    /// start one; they share one global flow-state counter, so two chains running at once step on
    /// each other's state and both fail on a guard.
    private static var inFlight = false
    /// Set while the chain is parked waiting for the network to come back, so a resume does not
    /// start a second one.
    private static var waitingForNetwork = false
    /// Identifies the current chain, so a watchdog armed for an earlier one stays quiet.
    private static var generation = 0
    /// How long a single chain is given before its in-flight flag is released.
    private static let chainWatchdog: TimeInterval = 45
    /// How many times key delivery alone is sent again before the App Attest registration is
    /// thrown away and rebuilt.
    ///
    /// Key delivery is the last of five round trips, and it used to be the one whose failure cost
    /// the device its Secure Enclave key: one miss cleared the registration and started over from
    /// `attest`. Most of what fails there is not the registration - it is a radio that dropped
    /// between the assertion and the POST - and discarding a good key to recover from a lost packet
    /// is an expensive answer to a cheap problem. It also spends a fresh attestation against
    /// Apple's per-device rate limit every time, on a device that had nothing wrong with it.
    ///
    /// Three tries, and the backoffs below are deliberately short: they have to fit inside
    /// `chainWatchdog` above, not inside whatever the network feels like taking.
    private static let keyDeliveryMaxTries = 3
    /// Waits before the second and third key-delivery try. 3.0s of backoff in total, which leaves
    /// the 45s chain budget to the round trips themselves.
    private static let keyDeliveryBackoff: [TimeInterval] = [1.0, 2.0]
    /// Registered once, however many times `configure` is called.
    private static var observing = false

    /// Where the feature-access answer is kept between launches.
    ///
    /// Only ever consulted after a fresh attempt to fetch it, and only as the fallback for a
    /// launch that could not reach the service. Absent, it reads as "1" - attestation on - so the
    /// safe answer is also the default one.
    private static let featureAccessKey = "nx_zta_access"
    /// The full policy answer, kept for diagnostics and for a host that wants to read it.
    private static let featureAccessDetailKey = "nx_zta_access_flags"

    // MARK: - Entry points

    /// Hands the layer the host's own settings and runs the whole verification chain.
    ///
    /// Call it from `application(_:didFinishLaunchingWithOptions:)`, before anything of the host's
    /// reaches the network. `onReady` is called on the main queue once verification has passed,
    /// and that is where the host starts its session - `APIS.connect`, push registration, the rest.
    /// It is not called at all while verification is failing, which is the point: a session that
    /// only starts behind a passing check cannot start behind a failing one.
    ///
    /// - Parameters:
    ///   - baseURL: root of the ZTA service, with or without a trailing slash.
    ///   - appName: identity the host is known by.
    ///   - apiKey: key issued for that identity.
    ///   - primaryPin: SPKI pin of the ZTA host, `sha256/<base64>`. Nil keeps the built-in one.
    ///   - backupPin: the pin a rotation switches to. Nil keeps the built-in one.
    ///   - featureAccessURL: nil derives it from `baseURL`.
    ///   - appAttest: must remain true for hardened builds. A false value is accepted only behind
    ///     the explicit DEBUG-only `NEXILIS_ALLOW_ATTESTATION_BYPASS` development flag; a release
    ///     build never reaches `onReady` without successful mandatory attestation.
    ///   - showsErrorScreen: whether the layer presents its own failure screen. Turn it off to
    ///     show one of the host's own from `onFailure`.
    ///   - onFailure: called once the automatic attempts are spent, with the failure that stopped
    ///     the chain. The chain can still be restarted afterwards - by the screen's button, by the
    ///     app coming back to the foreground, or by `APISZTA.retry()`.
    ///   - onReady: called on the main queue when verification has passed.
    public static func configure(baseURL: String,
                                 appName: String,
                                 apiKey: String,
                                 primaryPin: String? = nil,
                                 backupPin: String? = nil,
                                 featureAccessURL: String? = nil,
                                 appAttest: Bool = true,
                                 showsErrorScreen: Bool = true,
                                 onFailure: ((Error) -> Void)? = nil,
                                 onReady: @escaping () -> Void) {
        configure(NexilisZTAConfiguration(baseURL: baseURL,
                                          appName: appName,
                                          apiKey: apiKey,
                                          primaryPin: primaryPin,
                                          backupPin: backupPin,
                                          featureAccessURL: featureAccessURL,
                                          appAttestEnabled: appAttest),
                  showsErrorScreen: showsErrorScreen,
                  onFailure: onFailure,
                  onReady: onReady)
    }

    /// The same, for a host that builds the configuration itself - a service whose endpoints do
    /// not sit at the usual paths, say.
    public static func configure(_ configuration: NexilisZTAConfiguration,
                                 showsErrorScreen: Bool = true,
                                 onFailure: ((Error) -> Void)? = nil,
                                 onReady: @escaping () -> Void) {
        applyConfiguration(configuration, armAppAttest: false)

        onMain {
            self.onReady = onReady
            self.onFailure = onFailure
            self.showsErrorScreen = showsErrorScreen
            self.sessionReady = false
            self.attempts = 0
            self.startObservingIfNeeded()
            self.start()
        }
    }

    /// Stores the configuration and applies the parts that are applied once - the certificate pins
    /// and the App Attest endpoints - without running the chain.
    ///
    /// For a host that drives the steps itself, as OneApp did before any of this existed. Almost
    /// every host wants `configure` instead.
    public static func applyConfiguration(_ configuration: NexilisZTAConfiguration) {
        applyConfiguration(configuration, armAppAttest: true)
    }

    private static func applyConfiguration(_ configuration: NexilisZTAConfiguration,
                                           armAppAttest: Bool) {
        lock.lock()
        stored = configuration
        lock.unlock()

        // Set before anything else reads it: RASPGuard's pre-main callbacks, the chain below and
        // the host's own gate all branch on this, and they must all see the host's answer.
        NXSecurityPolicy.mode = configuration.appMode

        RASPGuard.shared().configurePinning(withPrimaryPin: configuration.primaryPin,
                                            backupPin: configuration.backupPin)
        RASPGuard.shared().configureHostPinFloor(configuration.pinnedHostPins)
        AppAttestManager.shared().minimumOSMajor = configuration.minimumAppAttestOSMajor
        if armAppAttest {
            AppAttestService.shared.configure()
        }
    }

    /// Runs the chain again from the top, with the current registration thrown away first.
    ///
    /// This is what the error screen's button does. A registration that has stopped working is the
    /// usual reason a launch fails after the app has sat closed for days, and running the same
    /// chain against the same registration would fail the same way - which is why a retry that
    /// kept it changed nothing.
    public static func retry() {
        onMain {
            self.attempts = 0
            AppAttestManager.shared().clearRegistration()
            UserDefaults.standard.removeObject(forKey: "nx_appattest_env")
            NXLogger.appAttest.publicInfo("[AppAttest] Retry: registration cleared, starting fresh.")
            self.inFlight = false
            self.start()
        }
    }

    // MARK: - Authorization surface

    /// At `.hsa` and `.middle`: true only while this process has a clean RASP verdict and a live
    /// server-issued ZTA token. The global flow-state integer is intentionally NOT part of it.
    ///
    /// At `.regular`: true once the chain has passed, whatever it passed by. A host at that mode
    /// runs without a token - offline, or with attestation switched off by the service - and
    /// holding its traffic behind one would simply stop the app.
    public static var hasValidAuthorization: Bool {
        guard NXSecurityPolicy.requiresServerChain() else {
            return sessionReady
        }
        guard RASPGuard.shared().deviceClean,
              RASPGuard.shared().lastThreatMask == RASP_THREAT_NONE,
              SessionManager.shared().hasValidSession else { return false }
        return sessionReady
    }

    /// Current server-issued Sentinel authorization token. Nil means protected business traffic
    /// must be denied. Exposed so non-HTTP transports can bind their own session to the same
    /// server authorization artifact instead of relying on a client callback.
    public static var currentAuthorizationToken: String? {
        // `hasValidSession` is `validSessionToken() != nil` - asking both was asking the same
        // question twice, and this is on the path of every message that leaves the app.
        guard hasValidAuthorization,
              let token = SessionManager.shared().validSessionToken(),
              !token.isEmpty else { return nil }
        return token
    }

    /// Headers for HTTP services that enforce Sentinel server-side. Empty means deny the request.
    public static func authorizationHeaders() -> [String: String] {
        guard let token = currentAuthorizationToken else { return [:] }
        return [
            "X-Nexilis-ZTA-Session": token,
            "X-Nexilis-ZTA-Posture": "clean",
            "X-Nexilis-Audit-Head": SecurityAuditChain.headHash()
        ]
    }

    /// Immediately revokes this process' local authorization. A best-effort signed server revoke
    /// is also initiated; local revocation never waits on network availability.
    public static func revokeLocalAuthorization(reason: String = "local security revocation") {
        // First, so nothing wakes up mid-teardown holding a token that is about to stop existing.
        SentinelTelemetryLoop.stop()
        if AppAttestManager.shared().isRegistered {
            AppAttestManager.shared().clearRegistration()
        }
        SessionManager.shared().clearAll()
        onMain {
            sessionReady = false
            inFlight = false
            SecurityAuditChain.append(event: "zta_authorization_revoked", detail: ["reason": reason])
        }
    }

    // MARK: - Server-driven security signals

    /// Re-checks the live session, and applies what only the server can tell this device.
    ///
    /// Three controls in this layer were built and then left with nothing to call them:
    /// `PinSetStore.applyRotation`, `SecureWipe.secureWipe(hard:)` and the audit chain's
    /// `onHeadChanged`. All three need a signal that arrives *after* launch, and the remediation
    /// removed the endpoint that carried it - `/zta/status/verify` was deleted as a dead endpoint
    /// while being, on the Android side, the carrier for exactly these three
    /// (`KillSwitchManager.checkServerStatusAndApply` applies `pin_rotation_payload` and
    /// `install_revoked` from that same response).
    ///
    /// Runs wherever there is a live server-issued token to run it with — every mode, including
    /// `.regular`. A kill switch that only reaches the strict modes is a kill switch that cannot
    /// reach the installed base, which is the population it exists for.
    ///
    /// A `.regular` host that opened with no network has no token and makes no extra call, which
    /// is the tolerance that mode is for. It is not a smaller set of controls; it is the same set,
    /// skipped while there is nothing to authenticate them with.
    public static func refreshSecurityStatus(completion: ((Bool) -> Void)? = nil) {
        guard currentAuthorizationToken != nil else {
            completion?(false)
            return
        }

        AppAttestManager.shared().verifySessionStatus(withAuditHead: SecurityAuditChain.headHash()) { status, error in
            guard let status, error == nil else {
                // An unreachable status endpoint is not a revocation. The session keeps whatever
                // validity it already had and the next poll tries again.
                NXLogger.appAttest.publicInfo("[Sentinel] Status poll gagal: \(error?.localizedDescription ?? "unknown")")
                completion?(false)
                return
            }

            // 1. Kill switch. The server has decided this install must not keep its data, and it
            //    keeps saying so on every poll - a device that was offline when the switch was
            //    thrown still learns about it.
            if (status["install_revoked"] as? NSNumber)?.boolValue == true
                || (status["status"] as? String) == "install_revoked" {
                NXLogger.appAttest.publicError("[Sentinel] Install dicabut server; melakukan hard wipe.")
                SecurityAuditChain.append(event: "install_revoked_wipe")
                revokeLocalAuthorization(reason: "server revoked this install")
                SecureWipe.secureWipe(hard: true)
                completion?(true)
                return
            }

            // 2. Signed pin rotation. Additive, and re-verified against the compiled signer on
            //    every read - the server carries it, it does not authorise it.
            if let payload = status["pin_rotation_payload"] as? String, !payload.isEmpty,
               let signature = status["pin_rotation_sig"] as? String, !signature.isEmpty {
                if PinSetStore.applyRotation(payloadJSON: payload, signatureB64: signature) {
                    NXLogger.appAttest.publicInfo("[Sentinel] Rotasi pin bertanda tangan diterapkan.")
                } else {
                    // A rotation that fails verification is the interesting case: either the
                    // signer is misconfigured or something tampered with it in transit.
                    SecurityAuditChain.append(event: "pin_rotation_rejected")
                }
            }

            // 3. The audit head travelled with the request and has now been witnessed, so the
            //    chain is anchored somewhere the device cannot rewrite.
            SecurityAuditChain.append(event: "status_verified")
            completion?(true)
        }
    }

    // MARK: - Sentinel v2 — pack, telemetry, sensitive decisions
    //
    // Every entry point below refuses unless a live server-issued token exists.
    //
    // That gate used to be the application mode, and mode was the wrong question. It asked *who
    // the host is*, when what these controls actually need is *whether the server has already
    // vouched for this install*. A token exists only after the attestation chain has finished, so
    // gating on the token keeps the guarantee the mode check was there for — none of these can put
    // a packet on the wire before the device has proved what it is — while letting `.regular` have
    // every control it can pay for.
    //
    // At `.regular` the two states that legitimately have no token are a launch with no network
    // and attestation switched off by the service. Both are exactly the states where these
    // controls have nothing to authenticate with, so they skip and the app still opens. That is
    // the whole difference between the modes: tolerance of being offline, not a thinner set of
    // security controls.

    /// Fetches the independently signed policy pack over the pinned channel.
    ///
    /// A failed fetch cannot grant trust and cannot clear policy: the pack already in force stays
    /// in force. The signature is checked against the compiled signer, so the ZTA service carries
    /// the pack without being able to write one.
    public static func refreshSecurityIntelligence(completion: ((Bool) -> Void)? = nil) {
        guard let token = currentAuthorizationToken,
              let url = URL(string: configuration.securityPackEndpoint) else {
            completion?(false)
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.timeoutInterval = 10
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue(token, forHTTPHeaderField: "X-Nexilis-ZTA-Session")

        pinnedSession.dataTask(with: request) { data, response, error in
            guard error == nil, (response as? HTTPURLResponse)?.statusCode == 200, let data,
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                completion?(false)
                return
            }
            // Recorded before the pack is read: it is what stops a device clock moved backwards
            // from reviving a pack that has expired.
            if let epoch = (object["server_epoch_ms"] as? NSNumber)?.doubleValue {
                SecurityPackStore.recordServerTime(epoch)
            }
            var applied = true
            if let payload = object["security_pack_bundle"] as? String, !payload.isEmpty,
               let signature = object["security_pack_sig"] as? String, !signature.isEmpty {
                applied = SecurityPackStore.apply(payloadJSON: payload, signatureB64: signature)
            }
            submitThreatTelemetry()
            completion?(applied)
        }.resume()
    }

    /// Sends normalized security evidence.
    ///
    /// The server may use it only to add risk or revoke, never to grant a clean posture, so a
    /// silent client and a client reporting nothing wrong are treated the same way. Failures back
    /// off exponentially: a device that cannot reach the collector must not spend its battery
    /// proving it.
    public static func submitThreatTelemetry() {
        guard let token = currentAuthorizationToken,
              let url = URL(string: configuration.telemetryEndpoint) else { return }

        let now = Date().timeIntervalSince1970
        telemetryLock.lock()
        // Two timers reach this now — the five-minute evidence loop and the fifteen-minute status
        // poll's chained refresh — and a batch is not removed from the buffer until the server
        // acknowledges it. Without this, two calls that overlap send the same evidence twice.
        let allowed = now >= telemetryNextAttempt && !telemetryInFlight
        if allowed { telemetryInFlight = true }
        telemetryLock.unlock()
        guard allowed else { return }

        SentinelTelemetryBuffer.offer(SentinelThreatTelemetry.currentEvents())
        let events = SentinelTelemetryBuffer.batch()
        guard !events.isEmpty else {
            telemetryLock.lock(); telemetryInFlight = false; telemetryLock.unlock()
            return
        }

        let body: [String: Any] = ["events": events,
                                   "audit_chain_head": SecurityAuditChain.headHash(),
                                   "sentinel_protocol": SentinelProtocol.current]
        guard let bytes = try? JSONSerialization.data(withJSONObject: body) else {
            telemetryLock.lock(); telemetryInFlight = false; telemetryLock.unlock()
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = bytes
        request.timeoutInterval = 10
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(token, forHTTPHeaderField: "X-Nexilis-ZTA-Session")

        pinnedSession.dataTask(with: request) { _, response, error in
            let code = (response as? HTTPURLResponse)?.statusCode ?? 0
            if error == nil, (200...299).contains(code) {
                SentinelTelemetryBuffer.ack(events)
                telemetryLock.lock()
                telemetryFailures = 0
                telemetryNextAttempt = 0
                telemetryInFlight = false
                telemetryLock.unlock()
            } else {
                telemetryLock.lock()
                telemetryFailures = min(6, telemetryFailures + 1)
                let delay = min(15 * 60.0, 30.0 * pow(2.0, Double(min(5, telemetryFailures - 1))))
                telemetryNextAttempt = Date().timeIntervalSince1970 + delay
                telemetryInFlight = false
                telemetryLock.unlock()
            }
            // The collector is the one endpoint that can answer "this install is gone". A 401 here
            // means the server acted on the evidence, so the device stops holding an authorization
            // the server has already withdrawn.
            if code == 401 { revokeLocalAuthorization(reason: "server rejected threat telemetry authorization") }
        }.resume()
    }

    private static let telemetryLock = NSLock()
    private static var telemetryFailures = 0
    private static var telemetryNextAttempt: TimeInterval = 0
    private static var telemetryInFlight = false

    /// Obtains a one-time, transaction-bound decision for a business payload.
    ///
    /// Returns the caller's original JSON bytes with three proof members appended, so the relying
    /// party can strip them, hash what remains, and get back exactly the payload the decision was
    /// issued against. Available at any mode that is holding a live server-issued token; a caller
    /// without one gets an error rather than an unproven pass, because a decision that cannot be
    /// proved is not a decision.
    public static func authorizeSensitiveTransactionJSON(_ businessJSON: String,
                                                         completion: @escaping (Result<String, Error>) -> Void) {
        func failWith(_ code: Int, _ message: String) {
            completion(.failure(NSError(domain: "io.nexilis.zta.sensitive", code: code,
                                        userInfo: [NSLocalizedDescriptionKey: message])))
        }

        // Not a mode check any more. A decision that cannot be proved is still not a decision,
        // but what makes it provable is the live token and the attestation behind it — and a
        // `.regular` host that is online and attested has both. What it cannot do is authorize a
        // transaction while offline, which is correct: there is nothing to prove it with.
        guard let token = currentAuthorizationToken,
              let keyID = AppAttestManager.shared().keyId, !keyID.isEmpty,
              let challengeURL = URL(string: configuration.challengeEndpoint),
              let decisionURL = URL(string: configuration.sensitiveDecisionEndpoint) else {
            failWith(2, "A live Sentinel authorization and configured endpoints are required.")
            return
        }

        let prepared: SentinelSensitiveTransaction.Prepared
        do { prepared = try SentinelSensitiveTransaction.prepare(businessJSON) }
        catch { completion(.failure(error)); return }

        // The device's own refusal, before the network is asked. A process that can already see it
        // is compromised should not need the server's permission to stop.
        let events    = SentinelThreatTelemetry.currentEvents()
        let localRisk = SentinelThreatTelemetry.localRiskScore(events: events)
        guard localRisk < SecurityPackStore.denyAt() else {
            revokeLocalAuthorization(reason: "local continuous risk denied sensitive transaction")
            failWith(3, "Sensitive transaction denied by local risk floor.")
            return
        }

        var components = URLComponents(url: challengeURL, resolvingAgainstBaseURL: false)
        var items = components?.queryItems ?? []
        items.append(URLQueryItem(name: "purpose", value: "sensitive"))
        components?.queryItems = items
        guard let url = components?.url else { failWith(4, "Invalid sensitive challenge endpoint."); return }

        var challengeRequest = URLRequest(url: url)
        challengeRequest.httpMethod = "GET"
        challengeRequest.timeoutInterval = 10
        challengeRequest.setValue("application/json", forHTTPHeaderField: "Accept")

        pinnedSession.dataTask(with: challengeRequest) { data, response, error in
            guard error == nil, (response as? HTTPURLResponse)?.statusCode == 200, let data,
                  let challenge = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let nonceID = challenge["nonce_id"] as? String, !nonceID.isEmpty,
                  let nonce = challenge["nonce"] as? String, !nonce.isEmpty else {
                completion(.failure(error ?? NSError(domain: "io.nexilis.zta.sensitive", code: 5,
                                                     userInfo: [NSLocalizedDescriptionKey: "Sensitive challenge failed."])))
                return
            }
            // The channel this decision request will travel, not whichever pinned host happened to
            // connect last — see RASPGuard's channel-binding note. A sensitive decision that names
            // the wrong channel is refused by a server that checks it, and means nothing on one
            // that does not.
            let channel = RASPGuard.shared().pinnedLeafSPKI(forEndpoint: decisionURL.absoluteString) ?? ""
            guard !channel.isEmpty else { failWith(6, "Pinned channel binding unavailable."); return }

            var body: [String: Any] = [
                "key_id": keyID, "nonce_id": nonceID, "challenge": nonce, "tls_spki": channel,
                "timestamp_ms": Int64(Date().timeIntervalSince1970 * 1000),
                "audit_chain_head": SecurityAuditChain.headHash(),
                "session_token_sha256": SentinelSensitiveTransaction.sha256Hex(token),
                "payload_sha256": prepared.payloadSHA256, "semantic_sha256": prepared.semanticSHA256,
                "transaction_id": prepared.transactionID, "transaction_type": prepared.transactionType,
                "source_account_id": prepared.sourceAccountID, "beneficiary_id": prepared.beneficiaryID,
                "beneficiary_bank": prepared.beneficiaryBank, "merchant_id": prepared.merchantID,
                "amount_minor": prepared.amountMinor, "currency": prepared.currency,
                "local_risk_score": localRisk, "sentinel_protocol": SentinelProtocol.current,
            ]

            // Two signatures, two questions. The Secure Enclave approval key signs the summary the
            // user was shown; the App Attest assertion signs the request that carries it.
            let approval = SentinelSensitiveTransaction.approvalCanonical(body)
            AppAttestManager.shared().signTransactionData(approval) { signature, signError in
                guard signError == nil, let signature else {
                    completion(.failure(signError ?? NSError(domain: "io.nexilis.zta.sensitive", code: 7,
                                                             userInfo: [NSLocalizedDescriptionKey: "Secure Enclave approval failed."])))
                    return
                }
                body["approval_signature_b64"] = signature.base64EncodedString()

                let canonical: Data
                do { canonical = try SentinelSensitiveTransaction.canonicalJSON(body) }
                catch { completion(.failure(error)); return }

                AppAttestManager.shared().generateAssertion(forClientData: canonical) { assertion, assertError in
                    guard assertError == nil, let assertion else {
                        completion(.failure(assertError ?? NSError(domain: "io.nexilis.zta.sensitive", code: 8,
                                                                   userInfo: [NSLocalizedDescriptionKey: "App Attest sensitive assertion failed."])))
                        return
                    }
                    body["assertion"] = assertion.base64EncodedString()
                    guard let bytes = try? JSONSerialization.data(withJSONObject: body) else {
                        failWith(9, "Sensitive request encoding failed."); return
                    }

                    var request = URLRequest(url: decisionURL)
                    request.httpMethod = "POST"
                    request.httpBody = bytes
                    request.timeoutInterval = 15
                    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
                    request.setValue(token, forHTTPHeaderField: "X-Nexilis-ZTA-Session")

                    pinnedSession.dataTask(with: request) { respData, resp, respError in
                        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
                        if code == 401 { revokeLocalAuthorization(reason: "server revoked authorization during sensitive decision") }

                        // Everything the server says is re-checked against what was asked for. A
                        // decision issued for a different payload is not this transaction's
                        // decision, however well signed the response was.
                        guard respError == nil, code == 200, let respData,
                              let obj = try? JSONSerialization.jsonObject(with: respData) as? [String: Any],
                              (obj["allow"] as? NSNumber)?.boolValue == true,
                              let decision = obj["decision_token"] as? String,
                              let payload = obj["payload_sha256"] as? String, payload == prepared.payloadSHA256,
                              let semantic = obj["semantic_sha256"] as? String, semantic == prepared.semanticSHA256,
                              let expires = (obj["expires_at_ms"] as? NSNumber)?.doubleValue,
                              expires > Date().timeIntervalSince1970 * 1000,
                              (obj["sentinel_protocol"] as? NSNumber)?.intValue == SentinelProtocol.current else {
                            completion(.failure(respError ?? NSError(domain: "io.nexilis.zta.sensitive", code: 10,
                                                                     userInfo: [NSLocalizedDescriptionKey: "Server denied or returned an invalid sensitive decision."])))
                            return
                        }
                        do {
                            SecurityAuditChain.append(event: "sensitive_decision_issued",
                                                      detail: ["transaction_type": prepared.transactionType])
                            completion(.success(try SentinelSensitiveTransaction.appendProof(prepared, token: decision)))
                        } catch { completion(.failure(error)) }
                    }.resume()
                }
            }
        }.resume()
    }

    /// Anchors the audit head whenever it moves, whenever there is a server to anchor it to.
    private static func installAuditAnchorIfNeeded() {
        guard currentAuthorizationToken != nil, SecurityAuditChain.onHeadChanged == nil else { return }
        SecurityAuditChain.onHeadChanged = { _ in
            // Coalesced deliberately: the head moves several times during a launch and each poll
            // costs a challenge, an assertion and a round trip. The next scheduled refresh carries
            // whatever the head is by then, which is the value that matters.
            auditAnchorPending = true
        }
    }

    private static var auditAnchorPending = false

    /// Starts the periodic status poll wherever a live token exists; idempotent.
    ///
    /// A `.regular` session that opened offline has no token and starts no timer. It does not pick
    /// one up later either: nothing re-runs the chain mid-session, so that session stays local
    /// until the app is opened again with a network. Deliberate — a background re-attestation is a
    /// second chain running against a session the host already believes is settled.
    private static func startStatusPollingIfNeeded() {
        guard currentAuthorizationToken != nil, statusPollTimer == nil else { return }
        installAuditAnchorIfNeeded()

        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + statusPollInterval, repeating: statusPollInterval)
        timer.setEventHandler {
            refreshSecurityStatus { ok in
                auditAnchorPending = false
                // Chained, not scheduled separately. The pack fetch and the telemetry upload both
                // need a session that the status poll has just confirmed, and giving them their own
                // timers would mean three wake-ups where one will do.
                if ok { refreshSecurityIntelligence() }
            }
        }
        timer.resume()
        statusPollTimer = timer
    }

    private static var statusPollTimer: DispatchSourceTimer?
    /// Long enough not to be a battery or backend cost, short enough that a revoked install stops
    /// holding data within a working session rather than a working day.
    private static let statusPollInterval: TimeInterval = 15 * 60

    // MARK: - Observers

    private static func startObservingIfNeeded() {
        guard !observing else { return }
        observing = true

        NotificationCenter.default.addObserver(forName: .ztaSessionRetry,
                                               object: nil,
                                               queue: .main) { _ in
            retry()
        }

        // A verification that failed while the app was being resumed - the device only just
        // unlocked, the radio only just back - is worth trying again the moment the app is in
        // front, rather than leaving the reader looking at a dead screen.
        NotificationCenter.default.addObserver(forName: UIApplication.didBecomeActiveNotification,
                                               object: nil,
                                               queue: .main) { _ in
            guard !sessionReady, attempts > 0, !inFlight else { return }
            attempts = 0
            start()
        }

        NotificationCenter.default.addObserver(forName: .ztaRuntimeCompromised,
                                               object: nil,
                                               queue: .main) { note in
            let mask = (note.userInfo?["threat_mask"] as? NSNumber)?.uint32Value ?? UInt32(RASP_THREAT_TAMPERED)
            guard NXSecurityPolicy.revokesOnRuntimeThreat() else {
                // Detection still runs and is still recorded at .regular; what it does not do is
                // end the session by itself. The host's own SecurityShield policy - which the
                // service configures - decides what happens next.
                SecurityAuditChain.append(event: "zta_runtime_threat_observed",
                                          detail: ["threat_mask": mask])
                return
            }
            revokeLocalAuthorization(reason: "runtime RASP threat mask \(mask)")
            let err = NSError(domain: NXAppAttestErrorDomain,
                              code: Int(mask),
                              userInfo: [NSLocalizedDescriptionKey: "Runtime security posture changed; authorization was revoked."])
            NotificationCenter.default.post(name: .ztaSessionError, object: nil, userInfo: ["error": err])
            onFailure?(err)
        }
    }

    // MARK: - The chain

    private static func start() {
        guard !inFlight else {
            NXLogger.appAttest.publicInfo("[AppAttest] Chain sudah berjalan, permintaan diabaikan.")
            return
        }
        inFlight = true

        // The chain is a sequence of callbacks across DeviceCheck, the Secure Enclave and five
        // network round trips. If any one of them never calls back, the flag above would stay
        // raised and every later attempt - the resume, the retry button - would be turned away at
        // the door. The watchdog is not a retry; it only takes the flag back down.
        generation &+= 1
        let armed = generation
        DispatchQueue.main.asyncAfter(deadline: .now() + chainWatchdog) {
            guard generation == armed, inFlight else { return }
            NXLogger.appAttest.publicError("[AppAttest] Chain tidak selesai dalam waktu wajar - flag dilepas.")
            inFlight = false
        }

        let config = configuration
        let serverChain = NXSecurityPolicy.requiresServerChain()

        SecurityAuditChain.append(event: "zta_verification_start")
        if NXSecurityPolicy.isHSA() {
            guard SecurityAuditChain.verifyChain() else {
                fail(NSError(domain: NXAppAttestErrorDomain, code: -7007,
                             userInfo: [NSLocalizedDescriptionKey: "Sentinel local security-audit chain is invalid."]))
                return
            }
        }

        RASPGuard.shared().configurePinning(withPrimaryPin: config.primaryPin,
                                            backupPin: config.backupPin)
        RASPGuard.shared().configureHostPinFloor(config.pinnedHostPins)
        PinSetStore.configure(rotationSignerSPKIBase64: config.rotationSignerSPKIBase64)
        SecurityPackStore.configure(signerSPKIBase64: config.securityPackSignerSPKIBase64)

        // Release identity is required only at .hsa, but a host that supplies it at any mode
        // still gets it applied - SecurityShield's tamper check reads the same verdict, and an
        // expectation that is configured is one worth comparing against.
        let identityFields = [config.expectedBundleID, config.expectedApplicationID,
                              config.expectedTeamID, config.expectedAppAttestEnvironment]
        let identityConfigured = identityFields.allSatisfy { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
        if identityConfigured {
            RASPGuard.shared().configureExpectedBundleID(config.expectedBundleID,
                                                         applicationID: config.expectedApplicationID,
                                                         teamID: config.expectedTeamID,
                                                         appAttestEnvironment: config.expectedAppAttestEnvironment)
        }

        guard serverChain else {
            // .regular: none of the preconditions below is a precondition here. The service
            // still decides whether attestation applies, and a launch with no network still
            // opens the session rather than parking the host behind a screen it cannot pass.
            NXLogger.appAttest.publicInfo("Certificate pinning: enabled (regular mode)")
            guard ZTAReachability.isConnected else {
                stateSet(NX_STATE_APPATTEST_KEY_DELIVERY)
                finish()
                return
            }
            guard config.appAttestEnabled else {
                NXLogger.appAttest.publicInfo("[AppAttest] Dimatikan oleh host, chain berhenti sebelum attestation.")
                afterFeatureAccess()
                return
            }
            fetchFeatureAccess()
            return
        }

        NXLogger.appAttest.publicInfo("Certificate pinning: hardened mode")

        // The pin-rotation signer and the release-identity expectations are .hsa preconditions.
        // At .middle the server verifies the real application identity from the App Attest
        // evidence it is already receiving, so a second local copy of that requirement would
        // only block hosts without adding a check the backend does not already make.
        let hsa = NXSecurityPolicy.isHSA()

        let threatMask = RASPGuard.shared().lastThreatMask
        guard RASPGuard.shared().deviceClean, threatMask == RASP_THREAT_NONE else {
            // The mask is the diagnosis and the code already carries it, but the failure log
            // prints only the description - so a finding at launch read as "not clean" with no
            // way to tell jailbreak from a pin mismatch. Named in the text, bit by bit.
            let names: [(UInt32, String)] = [
                (UInt32(RASP_THREAT_JAILBREAK), "jailbreak"), (UInt32(RASP_THREAT_DEBUGGER), "debugger"),
                (UInt32(RASP_THREAT_FRIDA), "frida"), (UInt32(RASP_THREAT_INJECTION), "injection"),
                (UInt32(RASP_THREAT_SIMULATOR), "simulator"), (UInt32(RASP_THREAT_REVERSE_TOOL), "reverse-tool"),
                (UInt32(RASP_THREAT_TAMPERED), "tampered"), (UInt32(RASP_THREAT_HOOK_DETECTED), "hook"),
                (UInt32(RASP_THREAT_INLINE_HOOK), "inline-hook"), (UInt32(RASP_THREAT_GOT_HOOK), "got-hook"),
            ]
            let found = names.filter { threatMask & $0.0 != 0 }.map { $0.1 }
            let detail = found.isEmpty ? "deviceClean=NO, mask=0" : found.joined(separator: ",")
            fail(NSError(domain: NXAppAttestErrorDomain, code: Int(threatMask),
                         userInfo: [NSLocalizedDescriptionKey:
                                    "Runtime security posture is not clean (\(detail), mask 0x\(String(threatMask, radix: 16)))."]))
            return
        }

        guard !config.apiKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            fail(NSError(domain: NXAppAttestErrorDomain, code: -7001,
                         userInfo: [NSLocalizedDescriptionKey: "Sentinel API key is not configured."]))
            return
        }

        guard !config.primaryPin.isEmpty, !config.backupPin.isEmpty, config.primaryPin != config.backupPin else {
            fail(NSError(domain: NXAppAttestErrorDomain, code: -7002,
                         userInfo: [NSLocalizedDescriptionKey: "Sentinel requires distinct primary and backup SPKI pins."]))
            return
        }

        #if !DEBUG
        if hsa {
            guard let rotationSigner = config.rotationSignerSPKIBase64?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !rotationSigner.isEmpty,
                  let rotationSignerDER = Data(base64Encoded: rotationSigner),
                  rotationSignerDER.count >= 65 else {
                fail(NSError(domain: NXAppAttestErrorDomain, code: -7006,
                             userInfo: [NSLocalizedDescriptionKey: "Sentinel release pin-rotation signer is not configured."]))
                return
            }
        }
        #endif

        #if DEBUG
        if identityConfigured {
            guard RASPGuard.shared().verifyCodeSignatureIntegrity() else {
                fail(NSError(domain: NXAppAttestErrorDomain, code: -7005,
                             userInfo: [NSLocalizedDescriptionKey: "Application signing/entitlement identity does not match Sentinel policy."]))
                return
            }
        }
        #else
        if hsa {
            guard identityConfigured else {
                fail(NSError(domain: NXAppAttestErrorDomain, code: -7005,
                             userInfo: [NSLocalizedDescriptionKey: "Sentinel release identity expectations are not configured."]))
                return
            }
            guard RASPGuard.shared().verifyCodeSignatureIntegrity() else {
                fail(NSError(domain: NXAppAttestErrorDomain, code: -7005,
                             userInfo: [NSLocalizedDescriptionKey: "Application signing/entitlement identity does not match Sentinel policy."]))
                return
            }
        } else if identityConfigured {
            guard RASPGuard.shared().verifyCodeSignatureIntegrity() else {
                fail(NSError(domain: NXAppAttestErrorDomain, code: -7005,
                             userInfo: [NSLocalizedDescriptionKey: "Application signing/entitlement identity does not match Sentinel policy."]))
                return
            }
        }
        #endif

        guard config.appAttestEnabled else {
            #if DEBUG && NEXILIS_ALLOW_ATTESTATION_BYPASS
            NXLogger.appAttest.publicInfo("[AppAttest] Development-only attestation bypass active.")
            #else
            fail(NSError(domain: NXAppAttestErrorDomain, code: -7003,
                         userInfo: [NSLocalizedDescriptionKey: "App Attest is mandatory in hardened builds."]))
            return
            #endif
        }

        guard ZTAReachability.isConnected else {
            // Availability failure is never authorization. Park without emitting ztaSessionReady.
            inFlight = false
            resumeWhenNetworkReturns()
            return
        }

        // The first thing this app says to the network is the attestation challenge. Nothing
        // else, not even the feature-access policy this chain used to fetch first, gets a round
        // trip before the device has proved what it is.
        //
        // Skipping that fetch costs nothing here: `attestationRequired` is unconditionally true
        // at these modes, so the only flag the answer carries - `device_check_attestation` - is
        // already known not to be read. At .regular the fetch stays exactly where it was, because
        // there the answer decides whether attestation happens at all.
        AppAttestService.shared.configure()
        startAttestFlow()
    }

    /// Asks the service whether this app, this key, is required to attest at all.
    ///
    /// Every exit from here has to reach `afterFeatureAccess`. A body that did not parse used to
    /// stop the chain dead - no verification, no error, no screen - and the launch simply never
    /// finished. An unreadable answer is treated the same as no answer: keep the setting already
    /// stored and carry on.
    private static func fetchFeatureAccess() {
        let config = configuration
        guard let url = URL(string: config.featureAccessURL) else {
            afterFeatureAccess()
            return
        }

        let body: [[String: Any]] = [[
            "apikey": config.apiKey,
            "type": "0",
            "app_id": config.appName
        ]]

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json;charset=UTF-8", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("keep-alive", forHTTPHeaderField: "Connection")
        request.httpBody = try? JSONSerialization.data(withJSONObject: body, options: [])

        pinnedSession.dataTask(with: request) { data, response, error in
            defer { onMain { afterFeatureAccess() } }

            guard error == nil,
                  (response as? HTTPURLResponse)?.statusCode == 200,
                  let data = data,
                  let parsed = try? JSONSerialization.jsonObject(with: data) as? [[String: String]] else {
                return
            }

            var flags: [String: String] = [:]
            for entry in parsed {
                var fields = entry
                fields.removeValue(forKey: "action")
                fields.removeValue(forKey: "alert_title")
                fields.removeValue(forKey: "alert_message")
                guard let key = fields.keys.first, let value = fields[key] else { continue }
                flags[key] = value
            }
            // The whole answer is cached for diagnostics and for the host's own UI. The one
            // flag the chain reads back is stored on its own, as a string, because that is
            // what `attestationRequired` looks for. At .hsa and .middle nothing reads it: a
            // cached, client-writable value can never turn mandatory attestation off.
            UserDefaults.standard.set(flags, forKey: featureAccessDetailKey)
            UserDefaults.standard.set(flags["device_check_attestation"] ?? "1", forKey: featureAccessKey)
        }.resume()
    }

    private static func afterFeatureAccess() {
        guard attestationRequired else {
            // .regular only: the service says this app does not attest. Nothing to check,
            // so nothing to fail.
            stateSet(NX_STATE_APPATTEST_KEY_DELIVERY)
            finish()
            return
        }
        AppAttestService.shared.configure()
        startAttestFlow()
    }

    /// At `.hsa` and `.middle` this is always true: App Attest is mandatory, and neither a
    /// client-writable cache nor a local configuration bit can grant a bypass.
    ///
    /// At `.regular` both switches apply again - the host's own, and the service's
    /// `device_check_attestation` - which is what lets a host integrate before its Team ID and
    /// bundle identifier are registered on the ZTA service.
    private static var attestationRequired: Bool {
        guard !NXSecurityPolicy.requiresServerChain() else { return true }
        guard configuration.appAttestEnabled else { return false }
        return (UserDefaults.standard.string(forKey: featureAccessKey) ?? "1") == "1"
    }

    private static func startAttestFlow() {
        let service = AppAttestService.shared

        // Reaching here means attestation is required - `afterFeatureAccess` has already let a
        // host through whose service switched it off. So a device that cannot attest cannot
        // satisfy the requirement, and at every mode that is a stop. It used to be waved through
        // at .regular on the grounds that failing to support a check is not the same as failing
        // it; the distinction does not survive contact with the point of the check, which is that
        // an unverified device is exactly the one worth refusing.
        guard service.isSupported else {
            fail(NSError(domain: NXAppAttestErrorDomain,
                         code: NXAppAttestError.notSupported.rawValue,
                         userInfo: [NSLocalizedDescriptionKey: "This device cannot satisfy mandatory App Attest policy."]))
            return
        }

        if service.isRegistered {
            NXLogger.appAttest.publicInfo("[AppAttest] Sudah terdaftar (keyId: \(service.keyId ?? "-")), langsung assertion.")
            assertThenDeliverKey()
        } else {
            NXLogger.appAttest.publicInfo("[AppAttest] Belum terdaftar, mulai registrasi...")
            registerThenAssertThenDeliverKey()
        }
    }

    private static func registerThenAssertThenDeliverKey(attempt: Int = 0) {
        AppAttestService.shared.registerDevice { success, error in
            guard success else {
                // A refused registration is a refused registration, at every mode. This briefly
                // tolerated a service policy refusal at .regular, on the belief that A10 hardware
                // could not attest at all - it can, and the refusal was a configuration floor set
                // above what the platform requires. Waving a device through because the service
                // said no is not tolerance, it is the check not being a check.
                NXLogger.appAttest.publicError("[AppAttest] Registrasi gagal, tidak lanjut ke assertion.")
                fail(error)
                return
            }
            assertThenDeliverKey(attempt: attempt)
        }
    }

    private static func assertThenDeliverKey(attempt: Int = 0) {
        // requestKeyDelivery performs the nonce-bound App Attest assertion and sends it to the
        // server. We intentionally do not treat local assertion generation as a verified stage.
        //
        // `tries` starts over here, and that is the intended budget: a registration that was just
        // rebuilt gets its own three transport retries. `attempt` is what stops the recursion -
        // it is already 1 on that path, so the second exhaustion fails instead of rebuilding again.
        deliverKey(attempt: attempt)
    }

    /// Whether a failed key delivery is worth sending again over the same registration.
    ///
    /// Only a request that never got an answer is. A server that *answered* has adjudicated, and a
    /// refusal is a decision - asking three more times does not change a decision, it only delays
    /// the screen the reader is owed. `NXServerError` already draws that line for us
    /// (AppAttestManager.m:74): 5xx, 408, 429 and an absent status arrive as `serverUnavailable`,
    /// every other status as `serverRejected`. This reads that verdict rather than re-deriving it.
    ///
    /// TLS trust failures are deliberately absent, and that absence is most of what "make sure the
    /// connection is safe" means here. A pin mismatch, an untrusted chain or a handshake the pinning
    /// delegate cancelled is what somebody standing in the middle of the connection looks like. The
    /// answer to that is to stop, not to offer them two more assertions.
    private static func keyDeliveryWorthRetrying(_ error: Error?) -> Bool {
        guard let error = error as NSError? else { return false }

        if error.domain == NXAppAttestErrorDomain {
            switch error.code {
            case NXAppAttestError.serverUnavailable.rawValue,
                 NXAppAttestError.networkFailed.rawValue,
                 // A challenge that expired between the Secure Enclave assertion and the POST is
                 // the signature of a slow link, not of a device with anything wrong with it - and
                 // the next try fetches its own.
                 NXAppAttestError.nonceExpired.rawValue:
                return true
            default:
                // serverRejected, pinningFailed, assertFailed, cryptoFailed, decodeFailed,
                // keyNotRegistered. Each is either a decision or a broken registration, and
                // keyNotRegistered is precisely the one the rebuild below exists for.
                return false
            }
        }

        guard error.domain == NSURLErrorDomain else { return false }
        switch error.code {
        case NSURLErrorTimedOut, NSURLErrorCannotConnectToHost, NSURLErrorCannotFindHost,
             NSURLErrorNetworkConnectionLost, NSURLErrorNotConnectedToInternet,
             NSURLErrorDNSLookupFailed, NSURLErrorInternationalRoamingOff,
             NSURLErrorDataNotAllowed, NSURLErrorCallIsActive:
            return true
        default:
            // NSURLErrorSecureConnectionFailed, ...ServerCertificateUntrusted,
            // ...ServerCertificateHasBadDate, ...ClientCertificateRejected and the -999 a pinning
            // delegate raises when it rejects a chain all land here, unretried, on purpose.
            return false
        }
    }

    /// Failures that say something about the *channel*, never about the registration.
    ///
    /// These get neither a retry nor a rebuild. A rebuild would be the worse of the two: it throws
    /// away a working Secure Enclave key on a signal an attacker can produce at will, and then
    /// attests all over again across the very connection that just failed to prove itself. The
    /// registration is not what is broken here, so it is not what gets spent.
    private static func keyDeliveryChannelCompromised(_ error: Error?) -> Bool {
        guard let error = error as NSError? else { return false }
        if error.domain == NXAppAttestErrorDomain {
            return error.code == NXAppAttestError.pinningFailed.rawValue
        }
        guard error.domain == NSURLErrorDomain else { return false }
        switch error.code {
        case NSURLErrorSecureConnectionFailed, NSURLErrorServerCertificateUntrusted,
             NSURLErrorServerCertificateHasBadDate, NSURLErrorServerCertificateHasUnknownRoot,
             NSURLErrorServerCertificateNotYetValid, NSURLErrorClientCertificateRejected,
             NSURLErrorClientCertificateRequired,
             // What URLSession reports when the pinning delegate refuses the chain it was handed.
             NSURLErrorCancelled:
            return true
        default:
            return false
        }
    }

    /// What a retry has to satisfy before it is allowed out.
    ///
    /// "Try three times" without this is just three chances to send an assertion somewhere it should
    /// not go. Three conditions, each checked at the mode that owns it:
    ///
    ///   - there is a network. Retrying into a radio that is down spends a try and learns nothing;
    ///     `fail()` already parks the whole chain on this rather than counting it as an attempt.
    ///   - the device is still clean, at the modes that revoke on a runtime threat. A threat that
    ///     arrived between two attempts must not be handed the second one.
    ///   - the pinned channel binding for this endpoint is still held, at the modes that require a
    ///     server chain. This is not fresh proof about the next handshake - it says this host has
    ///     pinned successfully at least once in this process, because RASPGuard's per-host map is
    ///     only ever written by a pin evaluation that passed. The authoritative refusal is still the
    ///     one in AppAttestManager.m, which will not send an assertion without a binding at those
    ///     modes; checking here stops the retry one round trip earlier.
    ///
    /// Both mode-gated conditions are gated on purpose. At `.regular` neither is a control the host
    /// ever had, and adding one here would turn a retry into a refusal a shipping mode 3 app never
    /// agreed to.
    private static func keyDeliveryChannelStillTrusted() -> Bool {
        guard ZTAReachability.isConnected else {
            NXLogger.appAttest.publicInfo("[AppAttest] Retry key delivery dibatalkan: jaringan tidak tersedia.")
            return false
        }
        if NXSecurityPolicy.revokesOnRuntimeThreat() {
            guard RASPGuard.shared().deviceClean,
                  RASPGuard.shared().lastThreatMask == RASP_THREAT_NONE else {
                NXLogger.appAttest.publicError("[AppAttest] Retry key delivery dibatalkan: ancaman runtime terdeteksi.")
                return false
            }
        }
        if NXSecurityPolicy.requiresServerChain() {
            let binding = RASPGuard.shared().pinnedLeafSPKI(forEndpoint: configuration.keyDeliveryEndpoint) ?? ""
            guard !binding.isEmpty else {
                NXLogger.appAttest.publicError("[AppAttest] Retry key delivery dibatalkan: channel binding TLS tidak terpasang.")
                return false
            }
        }
        return true
    }

    private static func deliverKey(attempt: Int = 0, tries: Int = 1) {
        AppAttestService.shared.requestKeyDelivery { key, error in
            guard let key else {
                NXLogger.appAttest.publicError("[AppAttest] Key delivery/server assertion failed.")

                // Nothing about a channel that failed to prove itself is evidence against the
                // registration, so this path spends neither a retry nor the key.
                if keyDeliveryChannelCompromised(error) {
                    NXLogger.appAttest.publicError(
                        "[AppAttest] Key delivery dihentikan: channel TLS tidak terbukti - registrasi tidak dibuang.")
                    fail(error)
                    return
                }

                // A dropped connection is not a broken registration, so send the same registration
                // again before spending it. This is safe against replay rather than merely
                // convenient: every call to requestKeyDelivery fetches its own challenge from the
                // server (AppAttestManager.m:807) and signs a fresh nonce-bound assertion over it,
                // so a retry is a new request and never a resend of the one that just failed.
                if tries < keyDeliveryMaxTries, keyDeliveryWorthRetrying(error) {
                    // Transport said try again; the preconditions say whether we may. When they say
                    // no - no network, a runtime threat, no pinned binding - this hands over to
                    // `fail()`, which parks the chain on reachability without counting an attempt.
                    // It deliberately does NOT fall through to the rebuild below: discarding a good
                    // registration because the radio is down is the exact behaviour this ladder
                    // exists to remove.
                    guard keyDeliveryChannelStillTrusted() else { fail(error); return }

                    let wait = keyDeliveryBackoff[min(tries - 1, keyDeliveryBackoff.count - 1)]
                    NXLogger.appAttest.publicInfo(
                        "[AppAttest] Key delivery diulang dalam \(Int(wait))s (percobaan \(tries + 1)/\(keyDeliveryMaxTries)).")
                    // Tied to this chain. The watchdog can release `inFlight` while these retries
                    // are still spaced out, and a resume or the retry button would then start a
                    // second chain; a retry belonging to the chain that lost the flag must not keep
                    // stepping on the flow state of the one that took it.
                    let armed = generation
                    DispatchQueue.main.asyncAfter(deadline: .now() + wait) {
                        guard generation == armed, !sessionReady else { return }
                        deliverKey(attempt: attempt, tries: tries + 1)
                    }
                    return
                }

                // Two ways here, and both point at the registration rather than the link: three
                // transport retries all failed while the channel held, or the server named a fault
                // no retry can clear - `keyNotRegistered` above all, which is precisely what a
                // rebuild fixes. Allowed exactly once; `attempt` is what makes that true.
                guard attempt == 0 else { fail(error); return }
                NXLogger.appAttest.publicError(
                    "[AppAttest] Key delivery gagal setelah \(tries)x - registrasi dibuang, mendaftar ulang.")
                SecurityAuditChain.append(event: "appattest_registration_rebuilt",
                                          detail: ["key_delivery_tries": tries])
                AppAttestManager.shared().clearRegistration()
                UserDefaults.standard.removeObject(forKey: "nx_appattest_env")
                let armed = generation
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                    guard generation == armed, !sessionReady else { return }
                    AppAttestService.shared.configure()
                    registerThenAssertThenDeliverKey(attempt: 1)
                }
                return
            }
            NXLogger.appAttest.publicInfo("[AppAttest] ✅ Server-verified key delivery complete (\(key.count) bytes).")
            finish()
        }
    }

    // MARK: - Ends

    /// The one way out that lets the host start its session.
    private static func finish() {
        guard stateGet() == NX_STATE_APPATTEST_KEY_DELIVERY else {
            // Fix: the domain was a sentence and the code was the internal state, so what reached
            // the screen and the support inbox was neither a domain nor a code anybody could act
            // on. A real domain, with the sentence where a message belongs.
            fail(NSError(
                domain: NXAppAttestErrorDomain,
                code: Int(stateGet()),
                userInfo: [
                    NSLocalizedDescriptionKey: "Perangkat, jaringan, sistem atau aplikasi tidak memenuhi syarat keamanan.",
                    NSLocalizedFailureReasonErrorKey: "Berhenti pada tahap \(stateGet())."
                ]
            ))
            return
        }

        // A terminal state is not an authorization. At .hsa and .middle the chain must actually
        // be holding a live server-issued token by now; at .regular reaching the end is the
        // answer, because offline and attestation-off are both legitimate ways to get here.
        if NXSecurityPolicy.requiresServerChain() {
            guard RASPGuard.shared().deviceClean,
                  RASPGuard.shared().lastThreatMask == RASP_THREAT_NONE,
                  SessionManager.shared().hasValidSession,
                  SessionManager.shared().validSessionToken() != nil else {
                fail(NSError(domain: NXAppAttestErrorDomain, code: -7004,
                             userInfo: [NSLocalizedDescriptionKey: "Terminal ZTA state reached without a live server authorization token."]))
                return
            }
        }

        onMain {
            // Once. A watchdog that released an earlier chain can leave two of them running, and
            // the host must not be told to start its session twice - that is a second APIS.connect
            // on a connection that already exists.
            guard !sessionReady else { return }

            // The chain reached its end; the next request is free to start a new one.
            inFlight = false
            sessionReady = true
            attempts = 0
            SecurityAuditChain.append(event: "zta_authorized")
            // From here the session is live, so the signals that only arrive after launch have
            // somewhere to land: a signed pin rotation, a revoked install, the audit anchor.
            startStatusPollingIfNeeded()
            // Evidence keeps its own cadence, five minutes against the status poll's fifteen. A
            // policy that is a quarter of an hour stale is fine; a compromise that is a quarter of
            // an hour unreported is not.
            SentinelTelemetryLoop.start()
            // First pack fetch of this session. It runs after `sessionReady` is set, so it can
            // only ever be a later packet than the attestation that authorised it.
            refreshSecurityIntelligence()

            // A retry can succeed while the error screen is still up - the automatic one that runs
            // when the app comes back to the foreground, for instance. Without this the reader is
            // left looking at a failure that is no longer true, and the only way past it is to
            // swipe the app away and open it again.
            dismissErrorScreen()
            ZTAErrorViewController.resetAutomaticRetryBudget()

            NotificationCenter.default.post(name: .ztaSessionReady, object: nil)
            onReady?()
        }
    }

    private static func fail(_ error: Error?) {
        // Fix: a step can report failure without an error object, and the screen then had nothing
        // to say but "an unknown error occurred" - with no code for support to work from either.
        // Where there is no error, one is made that at least names the stage it stopped at.
        let reported: Error = error ?? NSError(
            domain: NXAppAttestErrorDomain,
            code: Int(stateGet()),
            userInfo: [
                NSLocalizedDescriptionKey: "Verifikasi keamanan tidak selesai.",
                NSLocalizedFailureReasonErrorKey: "Berhenti pada tahap \(stateGet())."
            ]
        )
        NXLogger.appAttest.publicError("[AppAttest] ❌ Gagal: \(reported.localizedDescription)")

        onMain {
            // Whatever happens next starts a new chain, so this one is no longer in flight.
            inFlight = false

            // A failure with no network behind it is not a verification problem and must not spend
            // the retry budget: the chain parks and picks up the moment there is something to talk
            // to.
            guard ZTAReachability.isConnected else {
                resumeWhenNetworkReturns()
                return
            }

            attempts += 1
            // Most of these are momentary - the network is not up yet a second after a resume, or
            // Apple's attestation service is briefly busy. Trying again quietly a few times,
            // spaced out, settles almost all of them without the reader ever seeing a failure.
            guard attempts >= maxAutomaticAttempts else {
                let wait = min(pow(2.0, Double(attempts)), maxBackoff)
                NXLogger.appAttest.publicInfo("[AppAttest] Mencoba lagi dalam \(Int(wait))s (percobaan \(attempts)).")
                DispatchQueue.main.asyncAfter(deadline: .now() + wait) {
                    guard !sessionReady else { return }
                    start()
                }
                return
            }

            NotificationCenter.default.post(name: .ztaSessionError,
                                            object: nil,
                                            userInfo: ["error": reported])
            presentErrorScreen(for: reported)
            onFailure?(reported)
        }
    }

    /// Parks the chain until the device is back on a network, then resumes it. Waiting is not a
    /// failed attempt: burning the retry budget while there is demonstrably nothing to talk to is
    /// how a reader ended up at the error screen seconds after unlocking the phone.
    private static func resumeWhenNetworkReturns(after delay: TimeInterval = 2) {
        guard !waitingForNetwork else { return }
        waitingForNetwork = true
        NXLogger.appAttest.publicInfo("[AppAttest] Tidak ada jaringan - menunggu koneksi kembali.")

        func poll() {
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
                guard !sessionReady else {
                    waitingForNetwork = false
                    return
                }
                guard ZTAReachability.isConnected else {
                    // No ceiling: with no network there is nothing to report that the reader does
                    // not already know, and the moment one appears the chain picks up again.
                    poll()
                    return
                }
                waitingForNetwork = false
                attempts = 0
                inFlight = false
                start()
            }
        }
        poll()
    }

    // MARK: - The failure screen

    private static func presentErrorScreen(for error: Error, attempt: Int = 0) {
        guard showsErrorScreen else { return }
        guard let host = topViewController() else {
            // Called from `didFinishLaunchingWithOptions`, the window may not exist yet. Worth a
            // few seconds of asking again; not worth holding on to a failure forever.
            guard attempt < 10 else { return }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                presentErrorScreen(for: error, attempt: attempt + 1)
            }
            return
        }
        // Hindari double present jika ZTAErrorViewController sudah tampil.
        guard !(host is ZTAErrorViewController) else { return }

        let screen = ZTAErrorViewController(error: error) {
            host.dismiss(animated: true) { retry() }
        }
        screen.modalPresentationStyle = .overFullScreen
        screen.modalTransitionStyle = .crossDissolve
        host.present(screen, animated: true)
    }

    private static func dismissErrorScreen() {
        guard let top = topViewController(), top is ZTAErrorViewController else { return }
        top.dismiss(animated: false)
    }

    private static func topViewController() -> UIViewController? {
        let scene = UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .first { $0.activationState == .foregroundActive }
            ?? UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }.first

        guard let window = scene?.windows.first(where: { $0.isKeyWindow }) ?? scene?.windows.first,
              var top = window.rootViewController else {
            return nil
        }
        while let presented = top.presentedViewController {
            top = presented
        }
        return top
    }

    // MARK: - Plumbing

    /// One session for the feature-access call, pinned the same way every other ZTA request is.
    private static let pinnedSession: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 15
        configuration.timeoutIntervalForResource = 30
        return URLSession(configuration: configuration,
                          delegate: PinnedURLSessionDelegate(),
                          delegateQueue: nil)
    }()

    private static func onMain(_ work: @escaping () -> Void) {
        if Thread.isMainThread {
            work()
        } else {
            DispatchQueue.main.async(execute: work)
        }
    }
}
