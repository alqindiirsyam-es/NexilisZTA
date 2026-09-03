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
    private static var sessionReady = false
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
    /// Registered once, however many times `configure` is called.
    private static var observing = false

    /// Where the feature-access answer is kept between launches.
    ///
    /// Only ever consulted after a fresh attempt to fetch it, and only as the fallback for a
    /// launch that could not reach the service. Absent, it reads as "1" - attestation on - so the
    /// safe answer is also the default one.
    private static let featureAccessKey = "nx_zta_access"

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
                                 showsErrorScreen: Bool = true,
                                 onFailure: ((Error) -> Void)? = nil,
                                 onReady: @escaping () -> Void) {
        configure(NexilisZTAConfiguration(baseURL: baseURL,
                                          appName: appName,
                                          apiKey: apiKey,
                                          primaryPin: primaryPin,
                                          backupPin: backupPin,
                                          featureAccessURL: featureAccessURL),
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

        RASPGuard.shared().configurePinning(withPrimaryPin: configuration.primaryPin,
                                            backupPin: configuration.backupPin)
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
        RASPGuard.shared().configurePinning(withPrimaryPin: config.primaryPin,
                                            backupPin: config.backupPin)
        NXLogger.appAttest.publicInfo("Certificate pinning: PRODUCTION mode")

        guard ZTAReachability.isConnected else {
            // Nothing to verify against. The chain is not failed - it is skipped - and the host
            // gets its session, which is what it had before the layer existed. The moment there is
            // a network again, a resume runs the whole thing properly.
            stateSet(NX_STATE_APPATTEST_KEY_DELIVERY)
            finish()
            return
        }

        fetchFeatureAccess()
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
            UserDefaults.standard.set(flags["device_check_attestation"] ?? "1",
                                      forKey: featureAccessKey)
        }.resume()
    }

    private static func afterFeatureAccess() {
        guard attestationRequired else {
            // The service says this app does not attest. Nothing to check, so nothing to fail.
            stateSet(NX_STATE_APPATTEST_KEY_DELIVERY)
            finish()
            return
        }
        AppAttestService.shared.configure()
        startAttestFlow()
    }

    private static var attestationRequired: Bool {
        (UserDefaults.standard.string(forKey: featureAccessKey) ?? "1") == "1"
    }

    private static func startAttestFlow() {
        let service = AppAttestService.shared

        // A device that cannot do App Attest at all is not a device that failed it.
        guard service.isSupported else {
            NXLogger.appAttest.publicInfo("[AppAttest] Device tidak support, skip flow.")
            if stateGet() == NX_STATE_APPATTEST_ENDPOINT_CONFIG {
                stateSet(NX_STATE_APPATTEST_KEY_DELIVERY)
            }
            finish()
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
                NXLogger.appAttest.publicError("[AppAttest] Registrasi gagal, tidak lanjut ke assertion.")
                fail(error)
                return
            }
            assertThenDeliverKey(attempt: attempt)
        }
    }

    private static func assertThenDeliverKey(attempt: Int = 0) {
        AppAttestService.shared.performAssertion { success, error in
            guard success else {
                NXLogger.appAttest.publicError("[AppAttest] Assertion gagal, tidak lanjut ke key delivery.")
                guard attempt == 0 else {
                    fail(error)
                    return
                }
                // One registration the server no longer recognises is worth one fresh one before
                // the reader is told anything.
                AppAttestManager.shared().clearRegistration()
                UserDefaults.standard.removeObject(forKey: "nx_appattest_env")
                NXLogger.appAttest.publicInfo("Force clear — fresh registration")
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                    // The chain is being restarted from the top, so the flow state has to be put
                    // back where registration expects it. Without this the fresh registration hit
                    // its own guard and failed before it reached the network.
                    AppAttestService.shared.configure()
                    registerThenAssertThenDeliverKey(attempt: 1)
                }
                return
            }
            deliverKey()
        }
    }

    private static func deliverKey() {
        AppAttestService.shared.requestKeyDelivery { key, error in
            guard let key else {
                NXLogger.appAttest.publicError("[AppAttest] Key delivery gagal.")
                fail(error)
                return
            }
            NXLogger.appAttest.publicInfo("[AppAttest] ✅ Semua tahap selesai. Key siap (\(key.count) bytes).")
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

        onMain {
            // Once. A watchdog that released an earlier chain can leave two of them running, and
            // the host must not be told to start its session twice - that is a second APIS.connect
            // on a connection that already exists.
            guard !sessionReady else { return }

            // The chain reached its end; the next request is free to start a new one.
            inFlight = false
            sessionReady = true
            attempts = 0

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
