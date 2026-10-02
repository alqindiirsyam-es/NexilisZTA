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
    /// How the cover that goes up is drawn - see SentinelCoverStyle.
    @MainActor private static var style = SentinelCoverStyle.fullScreen

    @MainActor public static var isShowing: Bool { window != nil }

    /// Puts the cover up - now if the app has a scene, otherwise as soon as one connects.
    @MainActor public static func show(style: SentinelCoverStyle = .fullScreen) {
        wanted = true
        self.style = style
        guard window == nil else { return }
        if let scene = activeScene() { install(on: scene); return }
        var token: NSObjectProtocol?
        token = NotificationCenter.default.addObserver(forName: UIScene.willConnectNotification, object: nil,
                                                       queue: .main) { note in
            if let token { NotificationCenter.default.removeObserver(token) }
            guard let scene = note.object as? UIWindowScene else { return }
            // In the same turn the scene connects in. Fix: this waited a turn, and in that turn
            // the host's window - made visible as the scene connected - was drawn on its own, so
            // its splash came up before the cover. The cover sits above whatever level the host
            // gives its window, so building it first or second makes no difference to what is on
            // top; only the waiting did.
            MainActor.assumeIsolated { if wanted { install(on: scene) } }
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
        cover.rootViewController = coverController()
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

    /// What the cover shows: the host's launch screen with the pill over it when that was asked for
    /// and the host has one, the Sentinel screen otherwise.
    @MainActor private static func coverController() -> UIViewController {
        if style == .overLaunchScreen, let launch = hostLaunchScreen() {
            return SentinelLaunchScreenCoverViewController(launch: launch)
        }
        return SentinelSecurityCoverViewController()
    }

    /// The host's launch screen, built from its launch storyboard - the same thing iOS drew before
    /// the app ran. Nil for a host that names none, or one whose launch screen is the Info.plist
    /// `UILaunchScreen` dictionary rather than a storyboard. The storyboard is looked for before it
    /// is opened: opening one that is not there is an exception, not a nil.
    @MainActor private static func hostLaunchScreen() -> UIViewController? {
        guard let name = Bundle.main.object(forInfoDictionaryKey: "UILaunchStoryboardName") as? String,
              !name.isEmpty,
              Bundle.main.path(forResource: name, ofType: "storyboardc") != nil else {
            return nil
        }
        return UIStoryboard(name: name, bundle: .main).instantiateInitialViewController()
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

/// `.overLaunchScreen`: the host's launch screen, exactly as iOS drew it before the app ran, with the
/// Sentinel pill near the foot of it - the host's splash stays where it is from launch until the check
/// has passed, and all that changes is the pill appearing and going.
final class SentinelLaunchScreenCoverViewController: UIViewController {
    private let launch: UIViewController

    init(launch: UIViewController) {
        self.launch = launch
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not used") }

    override func viewDidLoad() {
        super.viewDidLoad()
        addChild(launch)
        launch.view.frame = view.bounds
        launch.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(launch.view)
        launch.didMove(toParent: self)

        let pill = SentinelCheckingPill()
        view.addSubview(pill)
        pill.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            pill.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            pill.leadingAnchor.constraint(greaterThanOrEqualTo: view.leadingAnchor, constant: 24),
            pill.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -32)
        ])
    }
}

/// The small "Sentinel Security Checking..." capsule: the Sentinel mark breathing, the words and a
/// spinner, on the Sentinel ground - so it reads as the same check the full cover stands for.
final class SentinelCheckingPill: UIView {
    private let mark = UIView()

    init() {
        super.init(frame: .zero)
        overrideUserInterfaceStyle = .dark
        backgroundColor = SentinelBrandView.Palette.background.withAlphaComponent(0.9)
        layer.cornerRadius = 20
        layer.shadowColor = UIColor.black.cgColor
        layer.shadowOpacity = 0.25
        layer.shadowRadius = 12
        layer.shadowOffset = CGSize(width: 0, height: 4)

        mark.backgroundColor = SentinelBrandView.Palette.sentinel
        mark.layer.cornerRadius = 4
        mark.layer.shadowColor = SentinelBrandView.Palette.sentinel.cgColor
        mark.layer.shadowOpacity = 0.9
        mark.layer.shadowRadius = 6
        mark.layer.shadowOffset = .zero

        let title = UILabel()
        title.text = "Sentinel Security Checking..."
        title.font = SentinelBrandView.serif(size: 15, weight: .medium)
        title.textColor = SentinelBrandView.Palette.ink
        title.adjustsFontSizeToFitWidth = true
        title.minimumScaleFactor = 0.8

        let spinner = UIActivityIndicatorView(style: .medium)
        spinner.color = SentinelBrandView.Palette.inkDim
        spinner.startAnimating()

        let row = UIStackView(arrangedSubviews: [mark, title, spinner])
        row.axis = .horizontal
        row.alignment = .center
        row.spacing = 10
        addSubview(row)
        row.translatesAutoresizingMaskIntoConstraints = false
        mark.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            mark.widthAnchor.constraint(equalToConstant: 8),
            mark.heightAnchor.constraint(equalToConstant: 8),
            row.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 16),
            row.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -14),
            row.topAnchor.constraint(equalTo: topAnchor, constant: 10),
            row.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -10)
        ])
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not used") }

    override func didMoveToWindow() {
        super.didMoveToWindow()
        guard window != nil, mark.layer.animation(forKey: "breathe") == nil else { return }
        // The full cover's breathing, at the pill's size.
        let pulse = CABasicAnimation(keyPath: "transform.scale")
        pulse.fromValue = 0.8
        pulse.toValue = 1.0
        let glow = CABasicAnimation(keyPath: "shadowRadius")
        glow.fromValue = 3
        glow.toValue = 8
        let group = CAAnimationGroup()
        group.animations = [pulse, glow]
        group.duration = 1.1
        group.autoreverses = true
        group.repeatCount = .infinity
        group.timingFunction = CAMediaTimingFunction(name: .easeInEaseOut)
        mark.layer.add(group, forKey: "breathe")
    }
}
