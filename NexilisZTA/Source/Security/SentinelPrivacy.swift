//
//  SentinelPrivacy.swift
//  Nexilis iOS ZTA — what the app shows while it is inactive, recorded or captured
//
//  Three independent switches, for a host that has its own privacy screen or wants none:
//
//    inactive         the app switcher snapshot, Control Centre, an incoming call: the Sentinel
//                     screen covers the app until it is active again.
//    screenRecording  screen recording, mirroring, AirPlay: covered for as long as it lasts.
//    screenshot       screenshots (and recordings) show the Sentinel screen instead of the app.
//
//  The first two are a cover window (PrivacyShield). Screenshots need something else: iOS tells an
//  app about a screenshot only after it has been taken, so nothing can be put in front of it in
//  time. What works is the layer iOS itself blanks in captures - the one a secure text field draws
//  in. The host window's layer is moved into it, and the Sentinel screen is placed underneath; a
//  capture drops the secure layer and shows what is beneath. Public API only; the view hierarchy,
//  touches and the host's own layout are untouched.
//
//  Installed by APISZTA (embedded hosts, from NexilisZTAConfiguration.privacyShield) and by the
//  no-code shield (NexilisShield.plist `PrivacyShield`). Idempotent: a later call updates the switches.
//

import UIKit
import ObjectiveC
#if SWIFT_PACKAGE
import NexilisZTACore
#endif

/// Which privacy covers are on. All on by default; `.off` for a host that has its own.
public struct PrivacyShieldOptions: Equatable {
    public var inactive: Bool
    public var screenRecording: Bool
    public var screenshot: Bool

    public init(inactive: Bool = true, screenRecording: Bool = true, screenshot: Bool = true) {
        self.inactive = inactive
        self.screenRecording = screenRecording
        self.screenshot = screenshot
    }

    public static let all = PrivacyShieldOptions()
    public static let off = PrivacyShieldOptions(inactive: false, screenRecording: false, screenshot: false)
    public var isOff: Bool { !inactive && !screenRecording && !screenshot }
}

public enum SentinelPrivacy {

    public static let coverTitle = "Sentinel Privacy Protection"
    public static let coverSubtitle = "Content is hidden while the app is inactive, recorded or captured"

    private static var options = PrivacyShieldOptions.off
    private static var sceneObserver: NSObjectProtocol?

    /// Applies `options` to the app's window - now if it has one, otherwise as soon as a scene
    /// becomes active. Safe to call again; the last call wins.
    public static func install(_ options: PrivacyShieldOptions, window: UIWindow? = nil) {
        let apply = {
            Self.options = options
            let shield = PrivacyShield.shared()
            shield.coverOnInactive = options.inactive
            shield.coverOnCapture = options.screenRecording
            shield.coverProvider = { SentinelBrandView(title: coverTitle, subtitle: coverSubtitle) }
            if let target = window ?? hostWindow() {
                shield.install(with: target)
                ScreenshotProtection.set(options.screenshot, on: target)
                NXLogger.general.publicInfo("[Privacy] inactive=\(options.inactive) screenRecording=\(options.screenRecording) screenshot=\(options.screenshot)")
            } else {
                // Launch, before the host has a window: once a scene is active, apply to it.
                shield.install(with: nil)
                guard sceneObserver == nil else { return }
                sceneObserver = NotificationCenter.default.addObserver(forName: UIScene.didActivateNotification,
                                                                       object: nil, queue: .main) { _ in
                    guard let target = hostWindow() else { return }
                    if let token = sceneObserver { NotificationCenter.default.removeObserver(token) }
                    sceneObserver = nil
                    install(Self.options, window: target)
                }
            }
        }
        if Thread.isMainThread { apply() } else { DispatchQueue.main.async(execute: apply) }
    }

    /// The host's own window: the key window at normal level, or the first normal-level one.
    static func hostWindow() -> UIWindow? {
        let windows = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }.flatMap { $0.windows }
        return windows.first { $0.isKeyWindow && $0.windowLevel == .normal && $0.rootViewController != nil }
            ?? windows.first { $0.windowLevel == .normal && $0.rootViewController != nil }
    }
}

/// The secure-layer part: captures show the Sentinel screen instead of the window's content.
///
/// What is moved into the secure layer is the window's layer when it has a parent layer, and
/// otherwise - the usual case, a window's layer being the root of its context - the root view
/// controller's view, which covers everything the host draws in that window.
enum ScreenshotProtection {

    private final class Record {
        let field: UITextField
        let backdrop: SentinelBrandView
        weak var protectedLayer: CALayer?
        weak var originalParent: CALayer?
        init(field: UITextField, backdrop: SentinelBrandView) { self.field = field; self.backdrop = backdrop }
    }
    private static var protected: [ObjectIdentifier: Record] = [:]

    static func set(_ on: Bool, on window: UIWindow) {
        let key = ObjectIdentifier(window)
        if on {
            guard protected[key] == nil else { return }
            // The layer to hide, the view it belongs to, and the layer it hangs from.
            let content: CALayer, parent: CALayer, host: UIView, what: String
            if let superlayer = window.layer.superlayer {
                content = window.layer; parent = superlayer; host = window; what = "window"
            } else if let root = window.rootViewController?.view, let superlayer = root.layer.superlayer {
                content = root.layer; parent = superlayer; host = root.superview ?? window; what = "root view"
            } else {
                NXLogger.general.publicError("[Privacy] belum ada view untuk dilindungi - perlindungan screenshot ditunda")
                return
            }
            let field = UITextField()
            field.isSecureTextEntry = true
            field.isUserInteractionEnabled = false
            host.addSubview(field)
            host.sendSubviewToBack(field)
            field.layoutIfNeeded()
            // The secure container is the field's canvas; its layer is the one iOS blanks in captures.
            guard let secure = field.layer.sublayers?.first(where: { layer in
                        layer.delegate.map { String(describing: type(of: $0)).contains("Canvas") } ?? false })
                    ?? field.layer.sublayers?.last else {
                field.removeFromSuperview()
                NXLogger.general.publicError("[Privacy] secure layer tidak ditemukan - perlindungan screenshot tidak aktif")
                return
            }
            // What a capture shows in place of the app: the Sentinel screen, under the secure layer.
            let backdrop = SentinelBrandView(title: SentinelPrivacy.coverTitle, subtitle: SentinelPrivacy.coverSubtitle)
            backdrop.frame = window.bounds
            backdrop.setNeedsLayout()
            backdrop.layoutIfNeeded()
            let index = parent.sublayers?.firstIndex(of: content).map(UInt32.init) ?? 0
            parent.insertSublayer(field.layer, at: index)
            parent.insertSublayer(backdrop.layer, below: field.layer)
            secure.addSublayer(content)
            let record = Record(field: field, backdrop: backdrop)
            record.protectedLayer = content
            record.originalParent = parent
            protected[key] = record
            NXLogger.general.publicInfo("[Privacy] perlindungan screenshot aktif (\(what), secure layer \(secure.delegate.map { String(describing: type(of: $0)) } ?? String(describing: type(of: secure))))")
        } else if let record = protected.removeValue(forKey: key) {
            // Put the content back where it was.
            if let content = record.protectedLayer, let parent = record.originalParent {
                parent.insertSublayer(content, above: record.field.layer)
            }
            record.backdrop.layer.removeFromSuperlayer()
            record.field.layer.removeFromSuperlayer()
            record.field.removeFromSuperview()
        }
    }
}
