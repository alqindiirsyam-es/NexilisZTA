//
//  ShieldAutostart.swift
//  Nexilis iOS ZTA — no-code shielding: the ZTA chain started from a plist, not from host code
//
//  App modes 1, 2 and 3. `nexilis-shield` embeds NexilisZTA.framework into a finished
//  .xcarchive, adds a load command for it, and drops `NexilisShield.plist` into the app bundle.
//  NXShieldBootstrap (+load) sees the plist and calls `start()` once the app has launched; nothing
//  in the host was written for NexilisZTA and nothing in it has to change.
//
//      NexilisShield.plist
//        Mode                  1 (HSA), 2 (Middle) or 3 (Regular, the default)
//        BaseURL               https://nexilis.io/zta-ios
//        AppName               <identity known to the ZTA service>
//        APIKey                <ZTA API key>
//        PrimaryPin/BackupPin  sha256/...                optional; the compiled-in pair otherwise
//        FeatureAccessURL      optional
//        PinnedHostPins        { host: [sha256/...] }    optional
//        BlockUntilVerified    Bool, default true        cover the host UI until the chain ends
//        PrivacyShield         Bool, or { Inactive, ScreenRecording, Screenshot } (each Bool,
//                              default true) - the Sentinel privacy screen; false for a host
//                              that has its own. See SentinelPrivacy.
//        ExpectedBundleID      optional at 3, required at 1  compared with the running bundle
//        ExpectedTeamID        required at 1               \
//        ExpectedApplicationID required at 1                } release identity, filled in by the
//        AppAttestEnvironment  required at 1               /  CLI from the provisioning profile
//        RotationSignerSPKI    required at 1 (Release)     pin-rotation signer
//        SecurityPackSignerSPKI optional                   security-pack signer
//        OwnershipRelayURL     optional, http://<mac>:port  one-off console ownership proof, see
//                                                        tools/nexilis-shield/ownership_relay.py
//        OwnershipViaUSB       Bool, default false       the same proof through the app's Documents
//                                                        folder over USB (ownership_relay.py --usb)
//        RIL                   { Enabled, ApplicationID, BundleID, Environment, TenantID,
//                                ProtectedURLs, ExcludedURLs, ProtectionMode, ProtectNexilisLite }
//                              the RIL opt-in, same keys as Info.plist NexilisRIL; with
//                              ProtectedURLs / ProtectNexilisLite every HTTPS request to those
//                              URLs leaves RIL-signed (see RILProtection). Needs ZTA.
//        SecurityShield        Bool or { AppName, APIKey }  run the SecurityShield policy after ZTA
//                                                        (NexilisSecurityShield.framework embedded)
//        NexilisLite           { AppName, APIKey, ShowFloatingButton }  open the NexilisLite
//                                                        session after ZTA and SecurityShield
//                                                        (NexilisLite.framework and its deps)
//
//        ZTA                   Bool, default true        run the ZTA verification chain; false
//                                                        is Mode 3 only and needs a stage below
//        NexilisLite.SecurityShield  Bool, default true  run SecurityShield before the session
//        NexilisLite.BootstrapSignIn Bool, default false  Mode 1/2: NexilisLite's Login/TFA form runs
//                                                        inside the chain, before key delivery, over
//                                                        HTTPS to CPaaS /idp/v1/authn (LiteBootstrapAuth)
//        NexilisLite.Notifications   Bool, default false push notifications (APNs)
//        NexilisLite.VoIP            Bool, default false VoIP calls (PushKit + CallKit)
//                                    both installed at launch, before the ZTA chain - see ShieldPush
//
//  Every stage can be switched on its own - ZTA, SecurityShield, NexilisLite, in that order, each
//  only once the one before passed. SecurityShield shows its own policy alerts ("exit" ends the
//  app); NexilisLite connects and then shows the floating button. The cover lifts once the last
//  gating stage (SecurityShield, or ZTA without it) has passed. NexilisZTA.framework is embedded
//  whatever runs: the other two depend on it, and this autostart lives in it. With ZTA off it
//  still pins, still runs Barrier #1 (which never blocks at Mode 3) - only App Attest, key
//  delivery and the server token are skipped. Neither is imported - both
//  depend on NexilisZTA - they are reached by name: NXSecurityShieldBridge, NXLiteShieldBridge.
//
//  What a wrapper can and cannot do, at mode 3: it can run RASP, Barrier #1, App Attest, key
//  delivery, telemetry and the blocking screen, because none of those needs the host's
//  cooperation. It cannot hold the host's own logic until authorization - the host's code is
//  already running - so `BlockUntilVerified` covers the UI rather than gating the session, and
//  mode 3 opens the session offline exactly as it does for a linked host.
//
//  At modes 1 and 2 the cover is not optional and does not lift on failure. The overlay becomes
//  the key window for the length of the chain, so the ZTA failure screen - with its retry -
//  presents on the overlay rather than on the host, and the host is uncovered only by `onReady`:
//  a live server token and, where the mode requires it, Barrier #2's proof. No network parks the
//  chain behind the cover. A configuration the shield cannot use blocks as well, instead of
//  running the app unprotected. What stays true at every mode: the host's own code has already
//  started, so what a wrapper gates is the UI and the session, not the host's first instructions.
//  User authentication through an IdP needs the host's cooperation and is not available here.
//

import Foundation
import UIKit
import CryptoKit
import DeviceCheck
#if SWIFT_PACKAGE
import NexilisZTACore
#endif

public extension Notification.Name {
    /// Posted once the shield's chain has finished (passed, or opened offline at mode 3).
    static let nexilisShieldReady = Notification.Name("io.nexilis.shield.ready")
}

@objc(NXShieldAutostart)
public final class NXShieldAutostart: NSObject {

    private static var started = false
    private static var overlay: UIWindow?
    private static var sceneObserver: NSObjectProtocol?
    private static var keyObserver: NSObjectProtocol?
    /// Modes 1 and 2: the cover holds until the chain authorizes, and keeps the key window.
    private static var strict = false

    /// What runs after the ZTA chain, from NexilisShield.plist.
    private struct Stages {
        var chain = true
        var shield: (appName: String, apiKey: String)?
        var lite: (appName: String, apiKey: String, showButton: Bool, securityShield: Bool)?
    }
    private static var stages = Stages()
    /// Set once the cover has been lifted - a cover the scene delivers later must not come back.
    private static var released = false

    @objc public static func start() {
        guard !started else { return }
        started = true
        let declaredMode = ((try? loadSettings())?["Mode"] as? NSNumber)?.intValue ?? 3
        strict = declaredMode == 1 || declaredMode == 2
        do {
            let settings = try loadSettings()
            let config = try configuration(from: settings)
            // Before the cover goes up: a stage the plist asks for without its framework is a
            // configuration error, and at mode 3 that must leave the host usable, not covered.
            stages = try stagesFrom(settings)
            log("autostart: mode \(declaredMode), base=\(config.baseURL)")
            if strict || ((settings["BlockUntilVerified"] as? Bool) ?? true) { whenSceneAvailable(showOverlay) }
            if let relay = (settings["OwnershipRelayURL"] as? String).flatMap(URL.init(string:)) {
                OwnershipProof.run(relay: relay)
            }
            if (settings["OwnershipViaUSB"] as? Bool) == true { OwnershipProof.runViaFiles() }
            installPushIfAsked(settings)
            if stages.chain {
                APIS_configure(config)
            } else {
                // No chain: what the other stages need from NexilisZTA without it - the pins for
                // their HTTPS, the pin-rotation store, and Barrier #1's latch, which the SDK's
                // pinned sessions wait on and which Mode 3 always opens.
                APISZTA.applyConfiguration(config)
                PinSetStore.configure(rotationSignerSPKIBase64: config.rotationSignerSPKIBase64)
                _ = try? SentinelOfflinePreflight.run(configuration: config)
                log("rantai ZTA dilewati (ZTA = false)")
                DispatchQueue.main.async { afterZTA() }
            }
        } catch {
            // A wrapped app with a broken shield config must not run unprotected silently. At mode
            // 3 it is not blocked either: the finding is logged and the app carries on, the same
            // tolerance a linked mode-3 host has. At modes 1 and 2 the cover stays and says why.
            log("konfigurasi ditolak: \(error.localizedDescription)")
            NXLogger.general.publicError("[NexilisShield] configuration rejected: \(error.localizedDescription)")
            if strict {
                whenSceneAvailable { (scene: UIWindowScene) in
                    showOverlay(on: scene)
                    guard let root = overlay?.rootViewController, root.presentedViewController == nil else { return }
                    let screen = ZTAErrorViewController(error: error, onRetry: nil)
                    screen.modalPresentationStyle = .overFullScreen
                    root.present(screen, animated: false)
                }
            }
        }
    }

    private static func log(_ text: String) {
        print("[NexilisShield] \(text)")
        NXLogger.appAttest.publicInfo("[NexilisShield] \(text)")
    }

    // MARK: - Configuration

    private static func loadSettings() throws -> [String: Any] {
        guard let url = Bundle.main.url(forResource: "NexilisShield", withExtension: "plist"),
              let dict = NSDictionary(contentsOf: url) as? [String: Any] else {
            throw failure(1, "NexilisShield.plist unreadable")
        }
        return dict
    }

    private static func configuration(from s: [String: Any]) throws -> NexilisZTAConfiguration {
        let mode = (s["Mode"] as? NSNumber)?.intValue ?? 3
        let appMode: NXAppMode
        switch mode {
        case 1: appMode = .HSA
        case 2: appMode = .middle
        case 3: appMode = .regular
        default: throw failure(2, "NexilisShield.plist: Mode must be 1, 2 or 3")
        }
        let chain = (s["ZTA"] as? Bool) ?? true
        if !chain, mode != 3 {
            throw failure(9, "NexilisShield.plist: ZTA = false is allowed at Mode 3 only - modes 1 and 2 need the server token")
        }
        let fallback = ["BaseURL": "https://nexilis.io/zta-ios", "AppName": "shield", "APIKey": ""]
        func required(_ key: String) throws -> String {
            guard let v = (s[key] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines), !v.isEmpty else {
                // Without the chain the ZTA identity is not used for anything but the pins.
                if !chain, let value = fallback[key] { return value }
                throw failure(3, "NexilisShield.plist: \(key) is required")
            }
            return v
        }
        let optional: (String) -> String? = { key in
            let v = (s[key] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
            return (v?.isEmpty ?? true) ? nil : v
        }
        if mode == 1 {
            for key in ["ExpectedBundleID", "ExpectedTeamID", "ExpectedApplicationID", "AppAttestEnvironment"] {
                _ = try required(key)
            }
            guard ProtectedAssetStore.isAvailable() else {
                throw failure(5, "Mode 1 needs SentinelProtectedAssets.spa in the bundle (nexilis-shield --asset)")
            }
        }
        if let expected = optional("ExpectedBundleID"), expected != Bundle.main.bundleIdentifier {
            throw failure(4, "ExpectedBundleID does not match the running bundle")
        }
        var config = NexilisZTAConfiguration(baseURL: try required("BaseURL"),
                                             appName: try required("AppName"),
                                             apiKey: try required("APIKey"),
                                             primaryPin: optional("PrimaryPin"),
                                             backupPin: optional("BackupPin"),
                                             featureAccessURL: optional("FeatureAccessURL"),
                                             appAttestEnabled: true,
                                             appMode: appMode,
                                             rotationSignerSPKIBase64: optional("RotationSignerSPKI"))
        // Release identity: required at 1, applied at any mode that supplies all four.
        if let bundle = optional("ExpectedBundleID"), let team = optional("ExpectedTeamID"),
           let appID = optional("ExpectedApplicationID"), let env = optional("AppAttestEnvironment") {
            config.expectedBundleID = bundle
            config.expectedTeamID = team
            config.expectedApplicationID = appID
            config.expectedAppAttestEnvironment = env
        }
        config.securityPackSignerSPKIBase64 = optional("SecurityPackSignerSPKI")
        // Installed by APISZTA with the rest of the configuration, on either path (chain or not).
        if let flag = s["PrivacyShield"] as? Bool {
            config.privacyShield = flag ? .all : .off
        } else if let d = s["PrivacyShield"] as? [String: Any] {
            config.privacyShield = PrivacyShieldOptions(inactive: (d["Inactive"] as? Bool) ?? true,
                                                        screenRecording: (d["ScreenRecording"] as? Bool) ?? true,
                                                        screenshot: (d["Screenshot"] as? Bool) ?? true)
        }
        if let pins = s["PinnedHostPins"] as? [String: [String]], !pins.isEmpty { config.pinnedHostPins = pins }
        // A wrapped host has no Info.plist RIL opt-in and no recovery UI of its own to offer: the
        // opt-in, if any, is the shield plist's own `RIL` entry.
        config.rilInfoPlistKey = nil
        // The shield covers the host with its own overlay (showOverlay), for the stages after ZTA too.
        config.showsSecurityCheckingCover = false
        // Pre-asset sign-in (NexilisLite.BootstrapSignIn, modes 1/2): NexilisLite's Login/TFA form
        // runs as the chain's user-authentication step. The shield does not link NexilisLite, so the
        // step is handed over by name (NXLiteBootstrapAuthBridge).
        if let lite = s["NexilisLite"] as? [String: Any], lite["BootstrapSignIn"] as? Bool == true {
            guard mode != 3 else { throw failure(11, "NexilisShield.plist: NexilisLite.BootstrapSignIn is for Mode 1 and 2") }
            guard let bridge = NSClassFromString("NXLiteBootstrapAuthBridge"),
                  let method = class_getClassMethod(bridge, NSSelectorFromString("authenticateWithKeyId:completion:")) else {
                throw failure(11, "NexilisLite.BootstrapSignIn needs NexilisLite.framework (NXLiteBootstrapAuthBridge)")
            }
            typealias Authenticate = @convention(c) (AnyClass, Selector, NSString,
                                                     @escaping @convention(block) (NSString?, NSError?) -> Void) -> Void
            let call = unsafeBitCast(method_getImplementation(method), to: Authenticate.self)
            config.bootstrapAuthentication = { keyID, completion in
                call(bridge, NSSelectorFromString("authenticateWithKeyId:completion:"), keyID as NSString) { assertion, error in
                    if let assertion { completion(.success(assertion as String)) }
                    else { completion(.failure(error ?? failure(12, "pre-asset sign-in returned nothing"))) }
                }
            }
            config.userAuthenticationRequired = true
            // The form's result is applied by NexilisLite in this process; a credential from an
            // earlier launch would open the session with none to apply.
            config.userAuthenticationPerLaunch = true
        }
        if let ril = s["RIL"] {
            guard let settings = ril as? [String: Any] else { throw failure(10, "NexilisShield.plist: RIL must be a dictionary") }
            guard chain else { throw failure(10, "NexilisShield.plist: RIL needs the ZTA chain (ZTA = true) - the key is enrolled with the ZTA session") }
            config.rilSettings = settings
        }
        return config
    }

    private static func APIS_configure(_ config: NexilisZTAConfiguration) {
        APISZTA.configure(config, showsErrorScreen: true, onFailure: { error in
            log("chain gagal: \(error.localizedDescription)")
            // Mode 3 lets the host through; 1 and 2 keep it covered - the failure screen, and its
            // retry, are on the overlay because the overlay holds the key window.
            if strict { log("mode ketat - host tetap tertutup") } else { afterZTA() }
        }, onReady: {
            log("chain selesai")
            afterZTA()
        })
    }

    // MARK: - After ZTA: SecurityShield, NexilisLite

    private static var afterStarted = false

    private static func afterZTA() {
        guard !afterStarted else { return }
        afterStarted = true
        if let lite = stages.lite {
            log(lite.securityShield ? "NexilisLite: SecurityShield lalu connect" : "NexilisLite: connect (tanpa SecurityShield)")
            startLite(lite) { ok, message in
                if ok { release() } else { blocked(message ?? "NexilisLite tidak dapat dimulai") }
            }
        } else if let shield = stages.shield {
            log("SecurityShield: menjalankan kebijakan")
            runSecurityShield(shield) { ok in
                if ok { release() } else { blocked("SecurityShield: perangkat tidak memenuhi kebijakan keamanan.") }
            }
        } else {
            release()
        }
    }

    private static func release() {
        released = true
        log("host dilepas")
        removeOverlay()
        NotificationCenter.default.post(name: .nexilisShieldReady, object: nil)
    }

    /// Modes 1 and 2 keep the cover and say why; mode 3 lets the host through, as for ZTA itself.
    private static func blocked(_ message: String) {
        log(message)
        guard strict else { release(); return }
        DispatchQueue.main.async {
            guard let root = overlay?.rootViewController, root.presentedViewController == nil else { return }
            let error = failure(10, message)
            let screen = ZTAErrorViewController(error: error, onRetry: nil)
            screen.modalPresentationStyle = .overFullScreen
            root.present(screen, animated: true)
        }
    }

    // +[NXLiteShieldBridge installPushWithNotifications:voip:]
    private typealias LitePush = @convention(c) (AnyClass, Selector, Bool, Bool) -> Void

    /// At launch, not after the chain: iOS terminates an app woken by a VoIP push that does not
    /// report the call to CallKit at once, and stops delivering them.
    private static func installPushIfAsked(_ s: [String: Any]) {
        guard let lite = s["NexilisLite"] as? [String: Any] else { return }
        let notifications = (lite["Notifications"] as? Bool) ?? false
        let voip = (lite["VoIP"] as? Bool) ?? false
        guard notifications || voip,
              let (cls, sel, imp) = classMethod("NXLiteShieldBridge", "installPushWithNotifications:voip:") else { return }
        log("NexilisLite: push\(notifications ? " notifikasi" : "")\(voip ? " VoIP" : "") dipasang")
        unsafeBitCast(imp, to: LitePush.self)(cls, sel, notifications, voip)
    }

    // +[NXSecurityShieldBridge runWithAppName:apiKey:completion:]
    private typealias ShieldRun = @convention(c) (AnyClass, Selector, NSString, NSString,
                                                  @escaping @convention(block) (Bool) -> Void) -> Void
    // +[NXLiteShieldBridge startWithAppName:apiKey:showButton:securityShield:completion:]
    private typealias LiteStart = @convention(c) (AnyClass, Selector, NSString, NSString, Bool, Bool,
                                                  @escaping @convention(block) (Bool, NSString?) -> Void) -> Void

    private static func classMethod(_ className: String, _ selector: String) -> (AnyClass, Selector, IMP)? {
        let sel = NSSelectorFromString(selector)
        guard let cls = NSClassFromString(className), let method = class_getClassMethod(cls, sel) else { return nil }
        return (cls, sel, method_getImplementation(method))
    }

    private static func runSecurityShield(_ s: (appName: String, apiKey: String), _ done: @escaping (Bool) -> Void) {
        guard let (cls, sel, imp) = classMethod("NXSecurityShieldBridge", "runWithAppName:apiKey:completion:") else {
            done(false); return
        }
        let run = unsafeBitCast(imp, to: ShieldRun.self)
        let block: @convention(block) (Bool) -> Void = { ok in DispatchQueue.main.async { done(ok) } }
        run(cls, sel, s.appName as NSString, s.apiKey as NSString, block)
    }

    private static func startLite(_ l: (appName: String, apiKey: String, showButton: Bool, securityShield: Bool),
                                  _ done: @escaping (Bool, String?) -> Void) {
        guard let (cls, sel, imp) = classMethod("NXLiteShieldBridge", "startWithAppName:apiKey:showButton:securityShield:completion:") else {
            done(false, "NexilisLite.framework tidak termuat"); return
        }
        let start = unsafeBitCast(imp, to: LiteStart.self)
        let block: @convention(block) (Bool, NSString?) -> Void = { ok, message in
            DispatchQueue.main.async { done(ok, message as String?) }
        }
        start(cls, sel, l.appName as NSString, l.apiKey as NSString, l.showButton, l.securityShield, block)
    }

    /// The post-ZTA stages the plist asks for, refused up front when the framework is not there -
    /// a wrapped app that asked for SecurityShield must not silently run without it.
    private static func stagesFrom(_ s: [String: Any]) throws -> Stages {
        func text(_ d: [String: Any], _ k: String) -> String? {
            let v = (d[k] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
            return (v?.isEmpty ?? true) ? nil : v
        }
        var out = Stages()
        out.chain = (s["ZTA"] as? Bool) ?? true
        if let lite = s["NexilisLite"] as? [String: Any] {
            guard let name = text(lite, "AppName"), let key = text(lite, "APIKey") else {
                throw failure(6, "NexilisShield.plist: NexilisLite needs AppName and APIKey")
            }
            guard NSClassFromString("NXLiteShieldBridge") != nil else {
                throw failure(7, "NexilisShield.plist asks for NexilisLite, but NexilisLite.framework is not embedded")
            }
            // NexilisLite links NexilisSecurityShield, so the framework is there even when the
            // stage is switched off.
            guard NSClassFromString("NXSecurityShieldBridge") != nil else {
                throw failure(8, "NexilisLite needs NexilisSecurityShield.framework, which is not embedded")
            }
            let withShield = (lite["SecurityShield"] as? Bool) ?? true
            out.lite = (name, key, (lite["ShowFloatingButton"] as? Bool) ?? true, withShield)
            if withShield { out.shield = (name, key) }
        }
        if out.lite == nil, let flag = s["SecurityShield"] {
            var pair: (String, String)?
            if let dict = flag as? [String: Any], let name = text(dict, "AppName"), let key = text(dict, "APIKey") {
                pair = (name, key)
            } else if (flag as? Bool) == true, let name = text(s, "AppName"), let key = text(s, "APIKey") {
                pair = (name, key)
            }
            if let pair {
                guard NSClassFromString("NXSecurityShieldBridge") != nil else {
                    throw failure(8, "NexilisShield.plist asks for SecurityShield, but NexilisSecurityShield.framework is not embedded")
                }
                out.shield = pair
            }
        }
        if !out.chain, out.shield == nil, out.lite == nil {
            throw failure(11, "NexilisShield.plist: ZTA = false with no SecurityShield or NexilisLite leaves nothing to run")
        }
        return out
    }

    // MARK: - Covering the host until the chain ends

    private static func showOverlay(on scene: UIWindowScene) {
        guard overlay == nil, !released else { return }
        let window = UIWindow(windowScene: scene)
        window.windowLevel = SentinelSecurityCover.windowLevel
        let controller = ShieldCoverViewController()
        window.rootViewController = controller
        overlay = window
        if strict {
            // Key window for the length of the chain: the ZTA failure screen presents on the key
            // window's top controller, and at modes 1 and 2 that must be the cover, never the
            // host. A host that makes its own window key later is answered by taking it back.
            window.makeKeyAndVisible()
            keyObserver = NotificationCenter.default.addObserver(forName: UIWindow.didBecomeKeyNotification,
                                                                 object: nil, queue: .main) { note in
                // Host windows only: an SDK window above the cover - the pre-asset sign-in form - keeps
                // the key it needs for its keyboard.
                guard let cover = overlay,
                      SentinelSecurityCover.shouldReclaimKey(from: note.object as? UIWindow, cover: cover) else { return }
                cover.makeKey()
            }
        } else {
            // Visible without becoming key: at mode 3 the ZTA error screen presents on the key
            // window's top controller, which must stay the host's.
            window.isHidden = false
        }
    }

    private static func removeOverlay() {
        DispatchQueue.main.async {
            if let token = keyObserver { NotificationCenter.default.removeObserver(token); keyObserver = nil }
            let cover = overlay
            cover?.isHidden = true
            overlay = nil
            // Hand the key window back to the host.
            if let host = cover?.windowScene?.windows.first(where: { $0 !== cover && $0.rootViewController != nil }) {
                host.makeKey()
            }
        }
    }

    // MARK: - Scene plumbing

    /// Runs `body` with the app's window scene - now if one is connected, otherwise when the first
    /// one activates. Apps with and without a scene manifest both end up with one.
    private static func whenSceneAvailable(_ body: @escaping (UIWindowScene) -> Void) {
        if let scene = UIApplication.shared.connectedScenes.compactMap({ $0 as? UIWindowScene }).first {
            body(scene); return
        }
        var token: NSObjectProtocol?
        token = NotificationCenter.default.addObserver(forName: UIScene.willConnectNotification,
                                                       object: nil, queue: .main) { note in
            guard let scene = note.object as? UIWindowScene else { return }
            if let token { NotificationCenter.default.removeObserver(token) }
            DispatchQueue.main.async { body(scene) }
        }
    }

    private static func whenSceneAvailable(_ body: @escaping (UIWindow) -> Void) {
        whenSceneAvailable { (scene: UIWindowScene) in
            // The host's own window, once it has one.
            func attempt(_ tries: Int) {
                if let window = scene.windows.first(where: { $0 !== overlay && $0.rootViewController != nil }) {
                    body(window)
                } else if tries < 20 {
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { attempt(tries + 1) }
                }
            }
            attempt(0)
        }
    }

    private static func failure(_ code: Int, _ message: String) -> NSError {
        NSError(domain: "io.nexilis.shield", code: code, userInfo: [NSLocalizedDescriptionKey: message])
    }
}

/// Console ownership proof for a wrapped app, without the tenant's console key on the device.
///
/// The console verifies ownership with an App Attest attestation over a nonce that lives 60 s, so
/// the nonce cannot be baked into a build. The relay on the owner's Mac holds the console key,
/// fetches the challenge when the app asks, and forwards the attestation to /verify. The app only
/// ever sees the nonce and sends back what Apple signed; a build carrying this key is a one-off
/// verification build and never ships.
enum OwnershipProof {
    static func run(relay: URL) {
        log("mulai: relay=\(relay.absoluteString)")
        guard DCAppAttestService.shared.isSupported else { log("App Attest tidak didukung"); return }
        fetchChallenge(relay, tries: 0) { nonce, nonceID in
            attest(nonce: nonce) { keyID, attestation in
                let body: [String: Any] = ["key_id": keyID, "attestation_object": attestation, "nonce_id": nonceID]
                call(relay.appendingPathComponent("attestation"), body: body) { json in
                    log("SELESAI: \(json?["status"] ?? json?["error"] ?? "?")")
                }
            }
        }
    }

    /// The same proof with the Mac on the other end of the USB cable instead of the LAN: the relay
    /// drops the challenge into Documents (house_arrest), the app answers with a file beside it,
    /// the relay collects it. Needs a development-signed build, which a verification build is.
    static func runViaFiles() {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let challengeURL = docs.appendingPathComponent("nexilis-ownership-challenge.json")
        let answerURL = docs.appendingPathComponent("nexilis-ownership-attestation.json")
        log("mulai: menunggu challenge lewat USB di Documents")
        guard DCAppAttestService.shared.isSupported else { log("App Attest tidak didukung"); return }
        func poll(_ tries: Int) {
            if let data = try? Data(contentsOf: challengeURL),
               let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let n = json["nonce"] as? String, let nonce = Data(base64Encoded: n),
               let nonceID = json["nonce_id"] as? String {
                try? FileManager.default.removeItem(at: challengeURL)
                log("challenge diterima lewat USB")
                attest(nonce: nonce) { keyID, attestation in
                    let body: [String: Any] = ["key_id": keyID, "attestation_object": attestation, "nonce_id": nonceID]
                    if let out = try? JSONSerialization.data(withJSONObject: body) {
                        try? out.write(to: answerURL, options: .atomic)
                        log("attestation ditulis - relay akan mengambilnya")
                    }
                }
                // A later challenge (the relay retries when one expires) is answered too.
                DispatchQueue.global().asyncAfter(deadline: .now() + 1) { poll(0) }
                return
            }
            guard tries < 600 else { log("tidak ada challenge dalam 10 menit - berhenti"); return }
            DispatchQueue.global().asyncAfter(deadline: .now() + 1) { poll(tries + 1) }
        }
        poll(0)
    }

    private static func attest(nonce: Data, _ done: @escaping (String, String) -> Void) {
        DCAppAttestService.shared.generateKey { keyID, error in
            guard let keyID else { log("generateKey gagal: \(error?.localizedDescription ?? "?")"); return }
            DCAppAttestService.shared.attestKey(keyID, clientDataHash: Data(SHA256.hash(data: nonce))) { att, error in
                guard let att else { log("attestKey gagal: \(error?.localizedDescription ?? "?")"); return }
                done(keyID, att.base64EncodedString())
            }
        }
    }

    /// The first request to a LAN address triggers iOS's Local Network prompt and fails while it is
    /// open, so the challenge is retried for a minute - long enough to answer the prompt.
    private static func fetchChallenge(_ relay: URL, tries: Int, _ done: @escaping (Data, String) -> Void) {
        call(relay.appendingPathComponent("challenge"), body: nil) { json in
            if let n = json?["nonce"] as? String, let nonce = Data(base64Encoded: n),
               let nonceID = json?["nonce_id"] as? String {
                done(nonce, nonceID); return
            }
            guard tries < 20 else { log("challenge tidak terbaca - relay tidak terjangkau"); return }
            if tries == 0 { log("relay belum terjangkau - izinkan Local Network bila diminta, mencoba ulang…") }
            DispatchQueue.global().asyncAfter(deadline: .now() + 3) { fetchChallenge(relay, tries: tries + 1, done) }
        }
    }

    private static func call(_ url: URL, body: [String: Any]?, _ done: @escaping ([String: Any]?) -> Void) {
        var r = URLRequest(url: url, timeoutInterval: 30)
        if let body {
            r.httpMethod = "POST"
            r.setValue("application/json", forHTTPHeaderField: "Content-Type")
            r.httpBody = try? JSONSerialization.data(withJSONObject: body)
        }
        // A plain ephemeral session: the relay is on the LAN, outside the SDK's pinned sessions.
        URLSession(configuration: .ephemeral).dataTask(with: r) { data, response, error in
            let code = (response as? HTTPURLResponse)?.statusCode ?? 0
            let json = data.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
            if error != nil || code != 200 { log("\(url.lastPathComponent): HTTP \(code) \(error?.localizedDescription ?? "") \(json ?? [:])") }
            done(code == 200 ? json : nil)
        }.resume()
    }

    private static func log(_ text: String) {
        print("[NexilisShield] ownership \(text)")
        NXLogger.appAttest.publicInfo("[NexilisShield] ownership \(text)")
    }
}

/// The cover a wrapped app shows while the chain runs: the Sentinel screen (SentinelBrandView) with
/// its mark breathing and a spinner.
final class ShieldCoverViewController: UIViewController {
    override func loadView() {
        view = SentinelBrandView(title: "Sentinel Security Checking...", activity: true)
    }
}

/// Scene lifecycle for a wrapped host that has none. iOS 26 refuses to launch an app built with the
/// Xcode 27 SDK that does not adopt UIScene ("UIScene lifecycle required", signal 5) - which is
/// every Flutter app from a template before 3.35 and every UIKit app from before iOS 13 templates.
/// `nexilis-shield` adds a UIApplicationSceneManifest naming this class and the host's own main
/// storyboard; UIKit then builds the window from that storyboard exactly as the app delegate used
/// to, and nothing in the host has to know it is running in a scene.
@objc(NXShieldSceneDelegate)
public final class NXShieldSceneDelegate: UIResponder, UIWindowSceneDelegate {
    public var window: UIWindow?
}
