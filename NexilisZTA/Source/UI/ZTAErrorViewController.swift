//
//  ZTAErrorViewController.swift
//  NexilisZTA
//
//  The screen a reader is left with when verification will not pass.
//
//  It used to live in OneApp, which meant every other host had to write its own or show nothing at
//  all. It is part of the layer now: `APISZTA.configure` puts it up by itself unless the host asks
//  it not to, and a host that wants its own screen turns that off and presents whatever it likes
//  from `onFailure`.
//

import UIKit
import SystemConfiguration

#if SWIFT_PACKAGE
// CocoaPods builds Swift and Objective-C as one mixed-language target, so these
// types are already in scope. SwiftPM has no mixed target, so the Objective-C and
// C half is its own module and has to be imported.
import NexilisZTACore
#endif

public class ZTAErrorViewController: UIViewController {

    // MARK: - Properties
    private let error: Error?
    /// A failed verification ends the app: the screen says why, counts down and closes it. There is
    /// no retry from here - not by a button, not by a timer - so a device the chain refused cannot
    /// keep knocking until something gives.
    private static let exitCountdownSeconds = 5
    private var exitSecondsLeft = ZTAErrorViewController.exitCountdownSeconds
    private var exitTimer: Timer?

    /// Kept for source compatibility; the screen no longer retries, so there is no budget to reset.
    public static func resetAutomaticRetryBudget() {}

    // MARK: - UI Components
    private let scrollView: UIScrollView = {
        let sv = UIScrollView()
        sv.translatesAutoresizingMaskIntoConstraints = false
        return sv
    }()

    private let contentView: UIView = {
        let view = UIView()
        view.translatesAutoresizingMaskIntoConstraints = false
        return view
    }()

    private let iconView: UIImageView = {
        let config = UIImage.SymbolConfiguration(pointSize: 56, weight: .thin)
        let iv = UIImageView(image: UIImage(systemName: "exclamationmark.shield.fill",
                                            withConfiguration: config))
        iv.tintColor = UIColor(red: 1.0, green: 0.35, blue: 0.35, alpha: 1)
        iv.translatesAutoresizingMaskIntoConstraints = false
        return iv
    }()

    private let titleLabel: UILabel = {
        let label = UILabel()
        label.text = SentinelErrorText.title
        label.font = UIFont.systemFont(ofSize: 24, weight: .bold)
        label.textColor = .white
        label.textAlignment = .center
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()

    private let messageLabel: UILabel = {
        let label = UILabel()
        label.font = UIFont.systemFont(ofSize: 15, weight: .regular)
        label.textColor = UIColor.white.withAlphaComponent(0.7)
        label.textAlignment = .center
        label.numberOfLines = 0
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()

    private let errorCodeLabel: UILabel = {
        let label = UILabel()
        label.font = UIFont.systemFont(ofSize: 13, weight: .regular)
        label.textColor = UIColor.white.withAlphaComponent(0.5)
        label.textAlignment = .center
        label.numberOfLines = 0
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()

    private let exitButton: UIButton = {
        let button = UIButton(type: .system)
        button.setTitle("Keluar (\(ZTAErrorViewController.exitCountdownSeconds))", for: .normal)
        button.setImage(UIImage(systemName: "xmark.circle"), for: .normal)
        button.tintColor = .white
        button.setTitleColor(.white, for: .normal)
        button.titleLabel?.font = UIFont.monospacedDigitSystemFont(ofSize: 17, weight: .semibold)
        button.backgroundColor = UIColor(red: 0.85, green: 0.25, blue: 0.25, alpha: 1)
        button.layer.cornerRadius = 14
        button.contentEdgeInsets = UIEdgeInsets(top: 14, left: 28, bottom: 14, right: 28)
        button.semanticContentAttribute = .forceLeftToRight

        // Image padding (replaces config.imagePadding = 8)
        button.imageEdgeInsets = UIEdgeInsets(top: 0, left: -4, bottom: 0, right: 4)
        button.titleEdgeInsets = UIEdgeInsets(top: 0, left: 4, bottom: 0, right: -4)

        button.translatesAutoresizingMaskIntoConstraints = false
        return button
    }()

    private let contactButton: UIButton = {
        let button = UIButton(type: .system)
        button.setTitle("Hubungi Support", for: .normal)
        button.setTitleColor(UIColor.white.withAlphaComponent(0.5), for: .normal)
        button.translatesAutoresizingMaskIntoConstraints = false
        return button
    }()

    private let dividerView: UIView = {
        let view = UIView()
        view.backgroundColor = UIColor.white.withAlphaComponent(0.08)
        view.translatesAutoresizingMaskIntoConstraints = false
        return view
    }()

    // MARK: - Init
    /// `onRetry` is ignored: the screen exits the app instead of retrying. Kept so existing callers build.
    public init(error: Error?, onRetry: (() -> Void)? = nil) {
        self.error = error
        super.init(nibName: nil, bundle: nil)
    }

    deinit { exitTimer?.invalidate() }

    required init?(coder: NSCoder) {
        self.error = nil
        super.init(coder: coder)
    }

    // MARK: - Lifecycle
    public override func viewDidLoad() {
        super.viewDidLoad()
        setupBackground()
        setupLayout()
        configureContent()
        setupActions()
    }

    public override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        runEntryAnimation()
        startExitCountdown()
    }

    /// Five seconds to read the reason, then the app closes. Started once; a second appearance
    /// (the screen re-presented over a new host) keeps the countdown already running.
    private func startExitCountdown() {
        guard exitTimer == nil else { return }
        NXLogger.appAttest.publicInfo("[AppAttest] Verifikasi gagal - aplikasi ditutup dalam \(exitSecondsLeft) detik.")
        let timer = Timer(timeInterval: 1, repeats: true) { [weak self] _ in
            guard let self else { return }
            self.exitSecondsLeft -= 1
            if self.exitSecondsLeft <= 0 { self.exitApp() } else { self.updateExitTitle() }
        }
        RunLoop.main.add(timer, forMode: .common)
        exitTimer = timer
    }

    private func updateExitTitle() {
        UIView.performWithoutAnimation {
            exitButton.setTitle("Keluar (\(exitSecondsLeft))", for: .normal)
            exitButton.layoutIfNeeded()
        }
    }

    private func exitApp() {
        exitTimer?.invalidate()
        exitTimer = nil
        NXLogger.appAttest.publicInfo("[AppAttest] Aplikasi ditutup setelah verifikasi gagal.")
        exit(0)
    }

    // MARK: - Background
    private func setupBackground() {
        let gradient = CAGradientLayer()
        gradient.frame = view.bounds
        gradient.colors = [
            UIColor(red: 0.10, green: 0.04, blue: 0.06, alpha: 1).cgColor,
            UIColor(red: 0.05, green: 0.08, blue: 0.18, alpha: 1).cgColor
        ]
        gradient.startPoint = CGPoint(x: 0, y: 0)
        gradient.endPoint   = CGPoint(x: 1, y: 1)
        view.layer.insertSublayer(gradient, at: 0)
    }

    // MARK: - Layout
    private func setupLayout() {
        view.addSubview(scrollView)
        scrollView.addSubview(contentView)

        [iconView, titleLabel, messageLabel,
         dividerView, errorCodeLabel,
         exitButton, contactButton].forEach { contentView.addSubview($0) }

        NSLayoutConstraint.activate([
            scrollView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            scrollView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            scrollView.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor),

            contentView.topAnchor.constraint(equalTo: scrollView.topAnchor),
            contentView.leadingAnchor.constraint(equalTo: scrollView.leadingAnchor),
            contentView.trailingAnchor.constraint(equalTo: scrollView.trailingAnchor),
            contentView.bottomAnchor.constraint(equalTo: scrollView.bottomAnchor),
            contentView.widthAnchor.constraint(equalTo: scrollView.widthAnchor),

            // Icon
            iconView.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 64),
            iconView.centerXAnchor.constraint(equalTo: contentView.centerXAnchor),
            iconView.widthAnchor.constraint(equalToConstant: 80),
            iconView.heightAnchor.constraint(equalToConstant: 80),

            // Title
            titleLabel.topAnchor.constraint(equalTo: iconView.bottomAnchor, constant: 24),
            titleLabel.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 24),
            titleLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -24),

            // Message
            messageLabel.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 12),
            messageLabel.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 32),
            messageLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -32),

            // Divider
            dividerView.topAnchor.constraint(equalTo: messageLabel.bottomAnchor, constant: 32),
            dividerView.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 48),
            dividerView.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -48),
            dividerView.heightAnchor.constraint(equalToConstant: 1),

            // Error code
            errorCodeLabel.topAnchor.constraint(equalTo: dividerView.bottomAnchor, constant: 16),
            errorCodeLabel.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 32),
            errorCodeLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -32),

            // Exit button
            exitButton.topAnchor.constraint(equalTo: errorCodeLabel.bottomAnchor, constant: 40),
            exitButton.centerXAnchor.constraint(equalTo: contentView.centerXAnchor),
            exitButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 200),

            // Contact button
            contactButton.topAnchor.constraint(equalTo: exitButton.bottomAnchor, constant: 8),
            contactButton.centerXAnchor.constraint(equalTo: contentView.centerXAnchor),
            contactButton.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -48),
        ])
    }

    // MARK: - Configure content berdasarkan error type
    private func configureContent() {
        guard let nsError = error as? NSError else {
            // Nothing should reach here any more - every failure now carries an error.
            messageLabel.text = "Terjadi kesalahan yang tidak diketahui."
            errorCodeLabel.isHidden = true
            contactButton.isHidden = true
            return
        }

        // Fix: the screen named the failure by the layer that raised it - "io.nexilis.zta.protected
        // (…) · state …" under the message, with the error's raw description and reason after it,
        // which could be a class name or a server's JSON. The reader is owed what Android shows them
        // (SplashActivity.userFacingError), and nothing of how the app is built: one sentence and the
        // code from the Sentinel error-code list, which is what support looks up. The details go to
        // the log instead.
        let code = SentinelErrorText.code(for: nsError)
        titleLabel.text = SentinelErrorText.title
        messageLabel.text = SentinelErrorText.message(forCode: code)
        errorCodeLabel.text = SentinelErrorText.countdown
        NXLogger.general.publicError("[ErrorScreen] kode \(code) <- \(nsError.domain) (\(nsError.code)) \(nsError.localizedDescription) | \(nsError.localizedFailureReason ?? "")")

        // The exit button is always there. Support stays reachable whenever the server was the one
        // saying no.
        let serverRejected = nsError.domain == NXAppAttestErrorDomain
            && nsError.code == NXAppAttestError.serverRejected.rawValue
        contactButton.isHidden = !serverRejected && code != 3945 && !(9829...9836).contains(code)
    }

    // MARK: - Actions
    private func setupActions() {
        exitButton.addTarget(self, action: #selector(exitTapped), for: .touchUpInside)
        contactButton.addTarget(self, action: #selector(contactTapped), for: .touchUpInside)
    }

    @objc private func exitTapped() {
        exitApp()
    }

    @objc private func contactTapped() {
        let email = APISZTA.configuration.supportEmail
        if let url = URL(string: "mailto:\(email)") {
            UIApplication.shared.open(url)
        }
    }

    // MARK: - Entry Animation
    private func runEntryAnimation() {
        let views: [UIView] = [iconView, titleLabel, messageLabel,
                                dividerView, errorCodeLabel,
                                exitButton, contactButton]
        views.forEach {
            $0.alpha = 0
            $0.transform = CGAffineTransform(translationX: 0, y: 16)
        }

        for (i, view) in views.enumerated() {
            UIView.animate(withDuration: 0.4,
                           delay: Double(i) * 0.08,
                           usingSpringWithDamping: 0.85,
                           initialSpringVelocity: 0.3,
                           options: []) {
                view.alpha = 1
                view.transform = .identity
            }
        }

        // Pulse animation pada icon error
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) {
            self.pulseIcon()
        }
    }

    private func pulseIcon() {
        UIView.animate(withDuration: 0.6,
                       delay: 0,
                       usingSpringWithDamping: 0.4,
                       initialSpringVelocity: 0.5,
                       options: []) {
            self.iconView.transform = CGAffineTransform(scaleX: 1.15, y: 1.15)
        } completion: { _ in
            UIView.animate(withDuration: 0.4) {
                self.iconView.transform = .identity
            }
        }
    }
}

/// What a failed verification is called on screen, written the way Android writes it
/// (zta-l-sdk SplashActivity) and numbered from the Sentinel error-code list
/// ("Daftar Kode Error Lingkungan Perangkat"): one sentence and a four-digit code, never a class,
/// a domain or a server's raw reply.
enum SentinelErrorText {

    static let title = "Pemeriksaan Keamanan Gagal"
    static let countdown = "Aplikasi akan ditutup secara otomatis dalam 5 detik."
    private static let sentence = "Perangkat/jaringan/OS/aplikasi tidak memenuhi syarat keamanan."

    /// The line under the title. 7301 and 7302 say what they are, as Android does; every other code
    /// is the one sentence with the code after it.
    static func message(forCode code: Int) -> String {
        switch code {
        case 7301: return "Perangkat tidak memiliki akses internet.(7301)."
        case 7302: return "Layanan tidak dapat diakses.(7302)."
        default: return "\(sentence)(\(code))."
        }
    }

    /// The code for a failure: one the error already carries - a server reply says "(8429)" - and
    /// otherwise the code the list gives the condition iOS found.
    static func code(for error: NSError) -> Int {
        if let carried = carriedCode(in: error) {
            return carried
        }
        switch error.domain {
        case NXAppAttestErrorDomain:
            switch error.code {
            case 1004: return 8429                         // the server refused this device
            case 1002, 1008, 1012: return reachable() ? 7302 : 7301
            case 1013: return 9825                          // the connection is being intercepted
            case 1001, 1003, 1005, 1006, 1007, 1009, 1010: return 9829  // an internal check broke off
            case 1011: return 9831
            default: return threatCode() ?? 3945
            }
        case "io.nexilis.zta.preflight":
            switch error.code {
            case -7410: return 9829                         // the local audit chain is broken
            case -7411: return 9813                         // not the official release
            case -7412: return UIScreen.screens.count > 1 ? 9823 : 9824
            case -7413, -7414: return 9825                  // proxy / untrusted VPN
            case -7415: return 3945
            case let mask where mask > 0: return threatCode(mask: UInt32(truncatingIfNeeded: mask)) ?? 3945
            default: return threatCode() ?? 3945
            }
        case "io.nexilis.zta.protected":
            return threatCode() ?? 9833
        case "io.nexilis.zta.highassurance":
            return 4367                                     // not the approved release
        case NSURLErrorDomain:
            return reachable() ? 7302 : 7301
        default:
            return threatCode() ?? 3945
        }
    }

    /// The list's code for what the device's own checks last found, most serious first.
    private static func threatCode(mask: UInt32 = RASPGuard.shared().lastThreatMask) -> Int? {
        let order: [(UInt32, Int)] = [
            (UInt32(RASP_THREAT_JAILBREAK), 9805),           // root / jailbreak
            (UInt32(RASP_THREAT_DEBUGGER), 9801),            // debugger attached
            (UInt32(RASP_THREAT_FRIDA), 9803),               // Frida
            (UInt32(RASP_THREAT_INJECTION), 9804),           // injected library
            (UInt32(RASP_THREAT_HOOK_DETECTED), 9804),
            (UInt32(RASP_THREAT_INLINE_HOOK), 9804),
            (UInt32(RASP_THREAT_GOT_HOOK), 9804),
            (UInt32(RASP_THREAT_REVERSE_TOOL), 9835),        // reverse-engineering tools
            (UInt32(RASP_THREAT_SIMULATOR), 9818),           // simulator / emulator
            (UInt32(RASP_THREAT_TAMPERED), 9813)             // app re-signed or modified
        ]
        return order.first(where: { mask & $0.0 != 0 })?.1
    }

    /// A four-digit code in brackets anywhere in the error or what it wraps - how the server and
    /// Android write one.
    private static func carriedCode(in error: NSError, depth: Int = 0) -> Int? {
        guard depth < 4 else {
            return nil
        }
        var texts = [error.localizedDescription, error.localizedFailureReason ?? ""]
        texts += error.userInfo.values.compactMap { $0 as? String }
        for text in texts {
            if let range = text.range(of: "\\((\\d{4})\\)", options: .regularExpression) {
                let digits = text[range].dropFirst().dropLast()
                if let code = Int(digits) {
                    return code
                }
            }
        }
        if let underlying = error.userInfo[NSUnderlyingErrorKey] as? NSError {
            return carriedCode(in: underlying, depth: depth + 1)
        }
        return nil
    }

    /// Whether the phone has a route to the internet at all - which decides between "no internet"
    /// (7301) and "the service cannot be reached" (7302).
    private static func reachable() -> Bool {
        guard let reachability = SCNetworkReachabilityCreateWithName(nil, "apple.com") else {
            return false
        }
        var flags = SCNetworkReachabilityFlags()
        guard SCNetworkReachabilityGetFlags(reachability, &flags) else {
            return false
        }
        return flags.contains(.reachable) && !flags.contains(.connectionRequired)
    }
}
