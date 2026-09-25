//
//  SentinelSecurityCover.swift
//  Nexilis iOS ZTA — the "Sentinel Security Checking..." cover the chain runs behind
//
//  At modes 1 and 2 the host's interface stays covered until the chain has authorized the device:
//  the Sentinel screen (SentinelBrandView) in a window of its own above the host. The no-code
//  shield has always done this (ShieldAutostart's overlay); embedded hosts get the same from
//  APISZTA.configure, lifted just before `onReady`. What the chain puts up on the way - the
//  pre-asset sign-in form (NexilisLite's LiteBootstrapAuth), which lives in a window ABOVE this one -
//  appears over it; a failure keeps the cover and the ZTA error screen presents on it.
//
//  Key window: the cover is key for the length of the chain, so the error screen presents on it
//  and never on the host. A host window that makes itself key is answered by taking the key back;
//  an SDK window above the cover (the sign-in form, which needs the keyboard) is left alone.
//

import UIKit

public enum SentinelSecurityCover {

    /// The level the covers use - the shield's overlay and this one. Windows above it belong to the SDK.
    public static let windowLevel = UIWindow.Level.alert + 1

    @MainActor private static var window: UIWindow?
    @MainActor private static var keyObserver: NSObjectProtocol?
    @MainActor private static var wanted = false

    @MainActor public static var isShowing: Bool { window != nil }

    /// Puts the cover up - now if the app has a scene, otherwise as soon as one connects.
    @MainActor public static func show() {
        wanted = true
        guard window == nil else { return }
        if let scene = activeScene() { install(on: scene); return }
        var token: NSObjectProtocol?
        token = NotificationCenter.default.addObserver(forName: UIScene.willConnectNotification, object: nil,
                                                       queue: .main) { note in
            if let token { NotificationCenter.default.removeObserver(token) }
            guard let scene = note.object as? UIWindowScene else { return }
            DispatchQueue.main.async { if wanted { install(on: scene) } }
        }
    }

    /// Takes the cover down and hands the key window back to the host.
    @MainActor public static func hide() {
        wanted = false
        if let token = keyObserver { NotificationCenter.default.removeObserver(token); keyObserver = nil }
        guard let cover = window else { return }
        window = nil
        cover.isHidden = true
        cover.windowScene?.windows.first { $0 !== cover && !$0.isHidden && $0.rootViewController != nil
            && $0.windowLevel < windowLevel }?.makeKey()
    }

    /// Whether a window that just became key should be answered by taking the key back: host windows,
    /// at or below the cover, yes; SDK windows above it (the sign-in form), no.
    public static func shouldReclaimKey(from other: UIWindow?, cover: UIWindow) -> Bool {
        guard let other, other !== cover else { return false }
        return other.windowLevel <= cover.windowLevel
    }

    /// After an SDK window above the covers is dismissed: the topmost visible window becomes key again -
    /// the cover while the chain runs, the host otherwise - so what presents next lands where it is seen.
    @MainActor public static func restoreKeyWindow(in scene: UIWindowScene?) {
        let windows = (scene ?? activeScene())?.windows.filter { !$0.isHidden && $0.rootViewController != nil } ?? []
        windows.max { $0.windowLevel < $1.windowLevel }?.makeKey()
    }

    @MainActor private static func install(on scene: UIWindowScene) {
        guard window == nil else { return }
        let cover = UIWindow(windowScene: scene)
        cover.windowLevel = windowLevel
        cover.rootViewController = SentinelSecurityCoverViewController()
        window = cover
        cover.makeKeyAndVisible()
        keyObserver = NotificationCenter.default.addObserver(forName: UIWindow.didBecomeKeyNotification, object: nil,
                                                             queue: .main) { note in
            MainActor.assumeIsolated {
                guard let cover = window, shouldReclaimKey(from: note.object as? UIWindow, cover: cover) else { return }
                cover.makeKey()
            }
        }
    }

    @MainActor private static func activeScene() -> UIWindowScene? {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        return scenes.first { $0.activationState == .foregroundActive } ?? scenes.first
    }
}

/// The Sentinel screen with its mark breathing and a spinner - the same one the shield shows.
final class SentinelSecurityCoverViewController: UIViewController {
    override func loadView() {
        view = SentinelBrandView(title: "Sentinel Security Checking...", activity: true)
    }
}
