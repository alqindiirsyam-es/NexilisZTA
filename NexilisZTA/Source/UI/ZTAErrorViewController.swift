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

#if SWIFT_PACKAGE
// CocoaPods builds Swift and Objective-C as one mixed-language target, so these
// types are already in scope. SwiftPM has no mixed target, so the Objective-C and
// C half is its own module and has to be imported.
import NexilisZTACore
#endif

public class ZTAErrorViewController: UIViewController {

    // MARK: - Properties
    private let error: Error?
    private var onRetry: (() -> Void)?
    /// Whether this screen still owes the reader one attempt of its own.
    private var automaticRetryPending = false
    /// How long the screen waits before trying once by itself.
    private static let automaticRetryDelay: TimeInterval = 15
    /// Automatic attempts left across every appearance of this screen, not just this instance. A
    /// failure the server means permanently - it does not accept this build, this team, this
    /// device - fails again every time, and a screen that re-arms itself on each appearance would
    /// hammer the server forever on a reader's behalf and never tell them anything new. The button
    /// below is never limited; only the trying-by-itself is.
    private static var automaticRetryBudget = 3

    /// Called once a session finally comes up, so the next bad patch starts with a full budget.
    public static func resetAutomaticRetryBudget() {
        automaticRetryBudget = 3
    }

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
        label.text = "Verifikasi Gagal"
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
        label.font = UIFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        label.textColor = UIColor.white.withAlphaComponent(0.35)
        label.textAlignment = .center
        label.numberOfLines = 0
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()

    private let retryButton: UIButton = {
        let button = UIButton(type: .system)
        button.setTitle("Coba Lagi", for: .normal)
        button.setImage(UIImage(systemName: "arrow.clockwise"), for: .normal)
        button.tintColor = .white
        button.setTitleColor(.white, for: .normal)
        button.backgroundColor = UIColor(red: 0.2, green: 0.5, blue: 1.0, alpha: 1)
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
    public init(error: Error?, onRetry: (() -> Void)? = nil) {
        self.error = error
        self.onRetry = onRetry
        super.init(nibName: nil, bundle: nil)
    }

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
        scheduleAutomaticRetry()
    }

    /// Tries once more without being asked. A busy backend or a minute of bad signal fixes itself,
    /// and until now the only thing that noticed was the reader swiping the app away and opening
    /// it again - so the app made them do by hand what it could have done by itself. Exactly one
    /// attempt, and only where an attempt makes sense: a device that cannot do App Attest at all
    /// will not do it in fifteen seconds either.
    private func scheduleAutomaticRetry() {
        guard !retryButton.isHidden, !automaticRetryPending else { return }
        guard ZTAErrorViewController.automaticRetryBudget > 0 else {
            NXLogger.appAttest.publicInfo("[AppAttest] Jatah percobaan otomatis habis - menunggu pembaca.")
            return
        }
        ZTAErrorViewController.automaticRetryBudget -= 1
        automaticRetryPending = true
        DispatchQueue.main.asyncAfter(deadline: .now() + ZTAErrorViewController.automaticRetryDelay) { [weak self] in
            guard let self = self, self.automaticRetryPending, self.viewIfLoaded?.window != nil else { return }
            self.automaticRetryPending = false
            self.performRetry()
        }
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
         retryButton, contactButton].forEach { contentView.addSubview($0) }

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

            // Retry button
            retryButton.topAnchor.constraint(equalTo: errorCodeLabel.bottomAnchor, constant: 40),
            retryButton.centerXAnchor.constraint(equalTo: contentView.centerXAnchor),
            retryButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 200),

            // Contact button
            contactButton.topAnchor.constraint(equalTo: retryButton.bottomAnchor, constant: 8),
            contactButton.centerXAnchor.constraint(equalTo: contentView.centerXAnchor),
            contactButton.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -48),
        ])
    }

    // MARK: - Configure content berdasarkan error type
    private func configureContent() {
        guard let nsError = error as? NSError else {
            // Nothing should reach here any more - every failure now carries an error - but if one
            // ever does, the reader still gets a way forward instead of a screen with two buttons
            // whose state was never decided.
            messageLabel.text = "Terjadi kesalahan yang tidak diketahui. Silakan coba lagi."
            errorCodeLabel.isHidden = true
            retryButton.isHidden = false
            contactButton.isHidden = true
            return
        }

        // Map error code ke pesan yang user-friendly
        let (title, message, isRetryable) = errorMessage(for: nsError)
        titleLabel.text  = title
        messageLabel.text = message
        // Tampilkan error code di debug / untuk support.
        //
        // The reason line matters more than it looks. The mapped sentence above is deliberately
        // generic, and it used to be the ONLY thing that survived: a photo of this screen showed
        // "io.nexilis.appattest (1004)" and nothing else, so nobody could tell a gateway having a
        // bad minute from the server genuinely refusing this device - two problems with opposite
        // answers. The underlying failure carries the HTTP status and the server's own message;
        // that is what support actually needs, so it is printed here.
        var codeLine = "Error: \(nsError.domain) (\(nsError.code))"
        if nsError.domain != NXAppAttestErrorDomain {
            codeLine += " · state \(stateErrorCode(Int32(stateGet())))"
        }
        let reason = nsError.localizedDescription
        if !reason.isEmpty, reason != message {
            codeLine += "\n\(reason)"
        }
        if let failureReason = nsError.localizedFailureReason, !failureReason.isEmpty {
            codeLine += "\n\(failureReason)"
        }
        errorCodeLabel.text = codeLine

        // Sembunyikan retry jika tidak bisa di-retry. Only a genuinely permanent condition - a
        // device that cannot do App Attest at all - reaches this with retry hidden; everything
        // else leaves the reader something to press, because a screen whose only cure was killing
        // the app from the switcher is not an error screen, it is a wall.
        retryButton.isHidden    = !isRetryable
        // Support stays reachable whenever the server was the one saying no, retryable or not.
        let serverRejected = nsError.domain == NXAppAttestErrorDomain
            && nsError.code == NXAppAttestError.serverRejected.rawValue
        contactButton.isHidden  = isRetryable && !serverRejected
    }

    private let stateErrorTable: [(state: Int32, errorCode: Int32)] = [
        (0, 2622),
        (1, 6850),
        (2, 3941),
        (3, 1873),
        (4, 9799),
        (5, 2221),
        (6, 4367),
        (7, 2480),
        (8, 1836),
        (9, 9077),
        (10, 5769),
        (11, 4428),
        (12, 8405),
        (13, 8383),
        (14, 5673),
        (15, 2708),
        (21, 2423),
        (22, 2019),
        (23, 5874)
    ]

    private func stateErrorCode(_ state: Int32) -> Int32 {
        return stateErrorTable.first(where: { $0.state == state })?.errorCode ?? 0
    }

    private func errorMessage(for error: NSError) -> (title: String, message: String, retryable: Bool) {
        guard error.domain == NXAppAttestErrorDomain else {
            return (
                "Koneksi Gagal",
                "Tidak dapat terhubung ke server. Periksa koneksi internet Anda.",
                true
            )
        }

        switch error.code {
        case 1000:
            return (
                "Perangkat Tidak Didukung",
                "Fitur keamanan App Attest membutuhkan iPhone dengan chip A12 atau lebih baru.",
                false
            )
        case 1001:
            return (
                "Gagal Membuat Kunci",
                "Terjadi kesalahan saat menyiapkan kunci keamanan. Coba restart aplikasi.",
                true
            )
        case 1002:
            return (
                "Verifikasi Apple Gagal",
                "Apple tidak dapat memverifikasi keaslian aplikasi ini. Pastikan perangkat terhubung ke internet.",
                true
            )
        case 1004:
            // Retryable now: "Coba Lagi" revokes the registration the server rejected and registers
            // the device afresh, which is exactly the remedy for a record the server no longer
            // recognises - the usual state of affairs after the app has sat closed for days. The
            // support link stays visible below for the case where it really is not recoverable.
            return (
                "Server Menolak Permintaan",
                "Server tidak dapat memverifikasi perangkat Anda. Coba lagi, atau hubungi support jika masalah berlanjut.",
                true
            )
        case 1007:
            return (
                "Secure Enclave Error",
                "Terjadi kesalahan pada komponen keamanan perangkat. Coba restart perangkat Anda.",
                true
            )
        case 1008:
            return (
                "Koneksi Gagal",
                "Tidak dapat terhubung ke server keamanan. Periksa koneksi internet Anda.",
                true
            )
        case 1005:
            return (
                "Sesi Kedaluwarsa",
                "Token verifikasi telah expired. Silakan coba lagi.",
                true
            )
        case 1010:
            return (
                "Enkripsi Gagal",
                "Terjadi kesalahan pada proses kriptografi. Coba restart aplikasi.",
                true
            )
        case 1011:
            return (
                "Verifikasi Belum Selesai",
                "Proses verifikasi keamanan terputus sebelum selesai. Silakan coba lagi.",
                true
            )
        case 1012:
            return (
                "Server Sedang Sibuk",
                "Server keamanan sedang tidak dapat melayani permintaan. Coba lagi sebentar.",
                true
            )
        default:
            return (
                "Verifikasi Gagal",
                "Terjadi kesalahan saat memverifikasi keamanan aplikasi.",
                true
            )
        }
    }

    // MARK: - Actions
    private func setupActions() {
        retryButton.addTarget(self, action: #selector(retryTapped), for: .touchUpInside)
        contactButton.addTarget(self, action: #selector(contactTapped), for: .touchUpInside)
    }

    @objc private func retryTapped() {
        // The reader beat the timer to it; the screen no longer owes them an attempt. Their own
        // press also says they are still here and still waiting, so the automatic budget is worth
        // restoring - the limit exists to stop the app trying on its own forever, not to punish
        // someone who is actively trying.
        automaticRetryPending = false
        ZTAErrorViewController.resetAutomaticRetryBudget()

        // Animasi button
        UIView.animate(withDuration: 0.1, animations: {
            self.retryButton.transform = CGAffineTransform(scaleX: 0.95, y: 0.95)
        }) { _ in
            UIView.animate(withDuration: 0.1) {
                self.retryButton.transform = .identity
            }
        }
        performRetry()
    }

    private func performRetry() {
        if let onRetry {
            // Jika ada custom retry handler
            onRetry()
        } else {
            // Default: restart attest flow via notification
            NotificationCenter.default.post(
                name: .ztaSessionRetry,
                object: nil
            )
        }
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
                                retryButton, contactButton]
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
