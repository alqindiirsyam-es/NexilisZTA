//
//  RILHostIntegration.swift
//  NexilisZTA
//
//  Everything a host used to have to write itself to switch RIL on: reading its identity out of
//  Info.plist, and the three recovery alerts (bad configuration, enrollment failed, telemetry
//  suspended). It lived in OneApp's AppDelegate and SceneDelegate first - 150 lines - and every
//  other host would have had to copy them. Here the host declares one Info.plist dictionary and
//  calls APISZTA.configure the way it always has.
//
//  A host that wants its own recovery UI sets `showsRILRecoveryUI = false` on its configuration
//  and drives `APISZTA.rilSession`, `retryRILEnrollment()` and `isRILTelemetrySuspended` itself.
//

import Foundation
import UIKit
#if SWIFT_PACKAGE
import NexilisZTACore
#endif

public extension Notification.Name {
    /// Optional hint from a host whose first screen replaces the window's root some time after
    /// launch: post it once the real interface is up and the recovery alerts stop waiting. Not
    /// required - the presenter also notices on its own when an alert it put up was carried away
    /// by a root swap, and offers it again.
    static let ztaHostInterfaceReady = Notification.Name("io.nexilis.zta.hostInterfaceReady")
}

public extension RILConfiguration {

    /// The default Info.plist key `fromInfoPlist` reads, and the one `NexilisZTAConfiguration`
    /// points at unless the host renames it.
    static let defaultInfoPlistKey = "NexilisRIL"

    /// Reads the RIL opt-in out of the host's Info.plist.
    ///
    ///     <key>NexilisRIL</key>
    ///     <dict>
    ///         <key>Enabled</key>        <true/>
    ///         <key>ApplicationID</key>  <string>TEAMID.com.example.app</string>
    ///         <key>BundleID</key>       <string>com.example.app</string>
    ///         <key>Environment</key>    <string>production</string>
    ///         <key>TenantID</key>       <string></string>
    ///     </dict>
    ///
    /// No dictionary at all means the host has not opted in - nil, and nothing changes. A
    /// dictionary that is present but wrong throws: a build that declared RIL and cannot have
    /// it must not start quietly without it. `Enabled` false is nil as well - the deployment's
    /// own switch, kept out of UserDefaults and out of any server response on purpose.
    ///
    /// The identity values are explicit build configuration, never inferred from DEBUG or read
    /// off the bundle being checked - `BundleID` has to match `Bundle.main.bundleIdentifier`,
    /// which is the one comparison that catches a repackaged app carrying the wrong plist.
    static func fromInfoPlist(bundle: Bundle = .main,
                              key: String = defaultInfoPlistKey,
                              sentinel: NexilisZTAConfiguration) throws -> RILConfiguration? {
        guard let raw = bundle.object(forInfoDictionaryKey: key) else { return nil }
        guard let settings = raw as? [String: Any] else { throw RILError.invalidConfiguration }
        return try from(settings: settings, bundle: bundle, sentinel: sentinel)
    }

    /// The same dictionary from anywhere - Info.plist, or the no-code shield's NexilisShield.plist
    /// `RIL` entry. The protection keys in it (ProtectedURLs, ...) are read by RILProtection.
    static func from(settings: [String: Any], bundle: Bundle = .main,
                     sentinel: NexilisZTAConfiguration) throws -> RILConfiguration? {
        guard let enabled = settings["Enabled"] as? Bool else { throw RILError.invalidConfiguration }
        guard enabled else { return nil }
        guard let appID = settings["ApplicationID"] as? String,
              let bundleID = settings["BundleID"] as? String,
              let environment = settings["Environment"] as? String,
              bundleID == bundle.bundleIdentifier,
              let challenge = URL(string: sentinel.challengeEndpoint),
              challenge.path.hasSuffix("/zta/challenge") else { throw RILError.invalidConfiguration }
        let tenantID = settings["TenantID"] as? String ?? ""
        let origin = try RILCore.target(challenge).origin
        let enrollment = challenge.deletingLastPathComponent()
            .appendingPathComponent("ril").appendingPathComponent("enroll")
        return try RILConfiguration(origin: origin, appID: appID, bundleID: bundleID,
                                    tenantID: tenantID, environment: environment,
                                    challengeURL: challenge, enrollmentURL: enrollment,
                                    policy: RILPolicy(maxBodyBytes: 262_144),
                                    relyingPolicy: RILPolicy(maxBodyBytes: 1_048_576))
    }
}

/// Puts up the RIL recovery alerts on whatever the host is showing, once it is showing it.
///
/// Three conditions, each offered once until it clears: the configuration was rejected at
/// startup, enrollment failed, telemetry is suspended. It re-checks whenever RIL's state
/// changes, the app comes to the front, the ZTA session becomes ready, or the host says its
/// interface is up.
///
/// The hard part is timing, and it is all here so hosts do not have to get it right: the
/// window may not exist yet at launch; the root may be a splash that a later transition
/// replaces; a presentation may already be in flight. An alert that UIKit never attached, or
/// one the root swap carried away before anyone saw it, does not count as offered.
@MainActor final class RILRecoveryPresenter {

    static let shared = RILRecoveryPresenter()

    private(set) var configurationError: Error?
    private var observers: [NSObjectProtocol] = []
    private var failureOffered = false
    private var telemetryWarningOffered = false
    private var presentationInFlight = false
    private var retry: DispatchWorkItem?
    private weak var activeAlert: UIAlertController?
    private var activeAlertAnswered = false
    /// The host's real interface is up (ztaHostInterfaceReady), or enough time has passed since
    /// the session became ready that it is not going to say so. Until then an enrollment or
    /// telemetry alert waits: put up on the splash, it is carried away by the root swap.
    private var interfaceReady = false
    private var interfaceReadyDeadline: Date?
    private static let interfaceReadyGrace: TimeInterval = 5

    private init() {}

    /// A configuration that APISZTA.configure refused. Shown as soon as anything can show it -
    /// a startup error cannot wait for a main screen that will never open.
    func configurationFailed(_ error: Error) {
        configurationError = error
        failureOffered = false
        install()
        presentIfNeeded()
    }

    func install() {
        guard observers.isEmpty else { return }
        let names: [Notification.Name] = [
            Notification.Name("io.nexilis.ril.stateChanged"),
            UIApplication.didBecomeActiveNotification,
            .ztaSessionReady,
            .ztaHostInterfaceReady,
        ]
        for name in names {
            observers.append(NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main) { [weak self] note in
                Task { @MainActor in
                    guard let self else { return }
                    if note.name == .ztaHostInterfaceReady {
                        self.interfaceReady = true
                    } else if note.name == .ztaSessionReady, !self.interfaceReady, self.interfaceReadyDeadline == nil {
                        // A host that never posts ztaHostInterfaceReady still gets its alerts,
                        // once the launch transition has had time to finish.
                        let deadline = Date().addingTimeInterval(Self.interfaceReadyGrace)
                        self.interfaceReadyDeadline = deadline
                        DispatchQueue.main.asyncAfter(deadline: .now() + Self.interfaceReadyGrace) { [weak self] in
                            Task { @MainActor in self?.presentIfNeeded() }
                        }
                    }
                    self.presentIfNeeded()
                }
            })
        }
    }

    /// Enrollment and telemetry alerts belong on the host's interface, not its splash. A
    /// configuration error is the exception: that app has no interface coming.
    private var hostInterfaceSettled: Bool {
        if interfaceReady { return true }
        if let deadline = interfaceReadyDeadline, Date() >= deadline { return true }
        return false
    }

    func presentIfNeeded() {
        retry?.cancel()
        retry = nil
        guard !presentationInFlight else { return }

        // An alert that was offered and then vanished without an answer - the splash it sat on
        // was replaced, typically - was never seen. Offer it again. The view leaving its window is
        // the reliable sign: a root swap leaves the old presenter, and the alert's link to it,
        // alive in memory for a while.
        if let alert = activeAlert, !activeAlertAnswered, alert.viewIfLoaded?.window == nil {
            alert.dismiss(animated: false)
            activeAlert = nil
            failureOffered = false
            telemetryWarningOffered = false
        }

        let session = APISZTA.rilSession
        if session?.state == .ready { failureOffered = false }
        let needsConfigurationAlert = configurationError != nil && !failureOffered
        // A key bound to a registration this install no longer has is re-enrolled by the layer itself
        // (APISZTA.recoverRILRegistration); the user is not asked about it.
        var recoveringRegistration = false
        if case RILError.registrationChanged? = session?.lastError { recoveringRegistration = true }
        let needsEnrollmentAlert = session?.state == .failed && !failureOffered && !recoveringRegistration
        let needsTelemetryAlert = APISZTA.isRILTelemetrySuspended && !telemetryWarningOffered
        guard needsConfigurationAlert || needsEnrollmentAlert || needsTelemetryAlert else { return }
        // Not on the splash. A configuration error cannot wait for an interface that will never
        // open; everything else waits until the host's own screen is up.
        if !needsConfigurationAlert, !hostInterfaceSettled {
            print("[RIL] alert ditunda: interface host belum siap (menunggu ztaHostInterfaceReady / tenggat)")
            defer_(); return
        }

        guard UIApplication.shared.applicationState == .active,
              var presenter = APISZTA.topViewController() else {
            defer_(); return
        }
        // Down to what is actually on screen, and not while any of it is moving.
        while true {
            if presenter.isBeingPresented || presenter.isBeingDismissed || presenter.transitionCoordinator != nil {
                defer_(); return
            }
            if let presented = presenter.presentedViewController { presenter = presented }
            else if let navigation = presenter as? UINavigationController, let visible = navigation.visibleViewController { presenter = visible }
            else if let tabs = presenter as? UITabBarController, let selected = tabs.selectedViewController { presenter = selected }
            else { break }
        }
        guard !(presenter is UIAlertController), presenter.viewIfLoaded?.window != nil else {
            defer_(); return
        }

        if let error = configurationError {
            let alert = UIAlertController(
                title: "Konfigurasi RIL tidak valid",
                message: "Startup dihentikan. Hubungi administrator untuk memeriksa konfigurasi build; "
                    + "aplikasi tidak beralih ke mode tanpa RIL.\n\n\(error.localizedDescription)",
                preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "Tutup", style: .cancel) { [weak self] _ in self?.activeAlertAnswered = true })
            present(alert, from: presenter) { [weak self] in self?.failureOffered = true }
            return
        }
        guard let session else { return }
        if session.state == .failed, !failureOffered, !recoveringRegistration {
            let alert = UIAlertController(
                title: "RIL belum siap",
                message: "Pengiriman request keamanan RIL ditahan. Anda dapat mencoba enrollment lagi "
                    + "setelah koneksi dan sesi ZTA tersedia. Kunci tidak akan dihapus otomatis.",
                preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "Nanti", style: .cancel) { [weak self] _ in self?.activeAlertAnswered = true })
            alert.addAction(UIAlertAction(title: "Coba lagi", style: .default) { [weak self] _ in
                self?.activeAlertAnswered = true
                Task { @MainActor in
                    self?.failureOffered = false
                    do { try await APISZTA.retryRILEnrollment() }
                    catch { self?.presentIfNeeded() }
                }
            })
            present(alert, from: presenter) { [weak self] in self?.failureOffered = true }
        } else if APISZTA.isRILTelemetrySuspended, !telemetryWarningOffered {
            let alert = UIAlertController(
                title: "Telemetry ditahan",
                message: "Hasil pengiriman sebelumnya belum pasti. Hubungi administrator untuk "
                    + "rekonsiliasi; aplikasi tidak mengirim ulang atau membuang batch secara otomatis.",
                preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "Tutup", style: .cancel) { [weak self] _ in self?.activeAlertAnswered = true })
            present(alert, from: presenter) { [weak self] in self?.telemetryWarningOffered = true }
        }
    }

    private func defer_() {
        guard retry == nil else { return }
        let work = DispatchWorkItem { [weak self] in
            Task { @MainActor in self?.presentIfNeeded() }
        }
        retry = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.35, execute: work)
    }

    private func present(_ alert: UIAlertController, from presenter: UIViewController,
                         didPresent: @escaping () -> Void) {
        print("[RIL] alert '\(alert.title ?? "")' ditampilkan di \(type(of: presenter))")
        presentationInFlight = true
        activeAlert = alert
        activeAlertAnswered = false
        presenter.present(alert, animated: true) { [weak self, weak alert] in
            self?.presentationInFlight = false
            // Offered only once UIKit has actually attached it to a visible window.
            guard alert?.viewIfLoaded?.window != nil else { self?.defer_(); return }
            didPresent()
        }
    }
}
