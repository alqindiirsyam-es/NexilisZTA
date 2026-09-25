//
//  SentinelBrandView.swift
//  Nexilis iOS ZTA — the Sentinel screen, in the Nexilis portal's palette (nexilis.io/portal)
//
//  One view for every full-screen Sentinel state: the no-code shield's "Sentinel Security
//  Checking..." cover and the privacy cover shown while the app is inactive, recorded or
//  captured. The deep navy ground with the Sentinel-red and Enclave-teal glows, the portal's mark -
//  a glowing Sentinel-red dot - above the title, and "Powered by • Nexilis" at the foot. Always
//  dark, whatever the device appearance. Only the words differ between uses.
//

import UIKit

public final class SentinelBrandView: UIView {

    enum Palette {
        static let background = UIColor(red: 0x0B / 255, green: 0x14 / 255, blue: 0x20 / 255, alpha: 1) // --bg
        static let ink = UIColor(red: 0xED / 255, green: 0xE4 / 255, blue: 0xD3 / 255, alpha: 1)        // --ink
        static let inkDim = UIColor(red: 0xA8 / 255, green: 0xA0 / 255, blue: 0x90 / 255, alpha: 1)     // --ink-dim
        static let inkFaint = UIColor(red: 0x5A / 255, green: 0x64 / 255, blue: 0x72 / 255, alpha: 1)   // --ink-faint
        static let sentinel = UIColor(red: 0xC9 / 255, green: 0x4A / 255, blue: 0x3F / 255, alpha: 1)  // --sentinel
        static let enclave = UIColor(red: 0x3D / 255, green: 0x8B / 255, blue: 0x9E / 255, alpha: 1)   // --enclave
    }

    private let redGlow = CAGradientLayer()
    private let tealGlow = CAGradientLayer()
    private let mark = UIView()
    private let breathing: Bool

    /// - Parameters:
    ///   - title: the line under the mark.
    ///   - subtitle: an optional smaller line under it.
    ///   - activity: a spinner under the text, and the mark breathing - for a state that ends.
    public init(title: String, subtitle: String? = nil, activity: Bool = false) {
        breathing = activity
        super.init(frame: UIScreen.main.bounds)
        overrideUserInterfaceStyle = .dark
        backgroundColor = Palette.background
        autoresizingMask = [.flexibleWidth, .flexibleHeight]

        // The portal hero's two radial glows: red at 20%/40%, teal at 85%/70%.
        for (layer, color, alpha) in [(redGlow, Palette.sentinel, 0.16), (tealGlow, Palette.enclave, 0.12)] {
            layer.type = .radial
            layer.colors = [color.withAlphaComponent(alpha).cgColor, color.withAlphaComponent(0).cgColor]
            layer.startPoint = CGPoint(x: 0.5, y: 0.5)
            layer.endPoint = CGPoint(x: 1, y: 1)
            self.layer.addSublayer(layer)
        }

        mark.backgroundColor = Palette.sentinel
        mark.layer.cornerRadius = 11
        mark.layer.shadowColor = Palette.sentinel.cgColor
        mark.layer.shadowOpacity = 0.9
        mark.layer.shadowRadius = 18
        mark.layer.shadowOffset = .zero
        mark.translatesAutoresizingMaskIntoConstraints = false

        let titleLabel = UILabel()
        titleLabel.text = title
        titleLabel.font = Self.serif(size: 22, weight: .medium)
        titleLabel.textColor = Palette.ink
        titleLabel.textAlignment = .center
        titleLabel.numberOfLines = 2
        titleLabel.adjustsFontSizeToFitWidth = true
        titleLabel.minimumScaleFactor = 0.7

        var rows: [UIView] = [mark, titleLabel]
        if let subtitle {
            let sub = UILabel()
            sub.text = subtitle
            sub.font = .systemFont(ofSize: 14, weight: .regular)
            sub.textColor = Palette.inkDim
            sub.textAlignment = .center
            sub.numberOfLines = 0
            rows.append(sub)
        }
        if activity {
            let spinner = UIActivityIndicatorView(style: .medium)
            spinner.color = Palette.inkDim
            spinner.startAnimating()
            rows.append(spinner)
        }
        let stack = UIStackView(arrangedSubviews: rows)
        stack.axis = .vertical
        stack.alignment = .center
        stack.spacing = 14
        stack.setCustomSpacing(28, after: mark)
        if activity { stack.setCustomSpacing(22, after: rows[rows.count - 2]) }
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)

        // Footer: "Powered by  • Nexilis", the portal's wordmark with its dot.
        let powered = UILabel()
        powered.text = "Powered by"
        powered.font = .systemFont(ofSize: 12, weight: .regular)
        powered.textColor = Palette.inkFaint
        let dot = UIView()
        dot.backgroundColor = Palette.sentinel
        dot.layer.cornerRadius = 3.5
        dot.layer.shadowColor = Palette.sentinel.cgColor
        dot.layer.shadowOpacity = 0.6
        dot.layer.shadowRadius = 6
        dot.layer.shadowOffset = .zero
        dot.translatesAutoresizingMaskIntoConstraints = false
        let brand = UILabel()
        brand.text = "Nexilis"
        brand.font = Self.serif(size: 17, weight: .medium)
        brand.textColor = Palette.ink
        let wordmark = UIStackView(arrangedSubviews: [dot, brand])
        wordmark.alignment = .center
        wordmark.spacing = 7
        let footer = UIStackView(arrangedSubviews: [powered, wordmark])
        footer.alignment = .center
        footer.spacing = 8
        footer.translatesAutoresizingMaskIntoConstraints = false
        addSubview(footer)

        NSLayoutConstraint.activate([
            mark.widthAnchor.constraint(equalToConstant: 22),
            mark.heightAnchor.constraint(equalToConstant: 22),
            dot.widthAnchor.constraint(equalToConstant: 7),
            dot.heightAnchor.constraint(equalToConstant: 7),
            stack.centerXAnchor.constraint(equalTo: centerXAnchor),
            stack.centerYAnchor.constraint(equalTo: centerYAnchor),
            stack.leadingAnchor.constraint(greaterThanOrEqualTo: leadingAnchor, constant: 32),
            stack.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -32),
            footer.centerXAnchor.constraint(equalTo: centerXAnchor),
            footer.bottomAnchor.constraint(equalTo: safeAreaLayoutGuide.bottomAnchor, constant: -24),
        ])
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not used") }

    public override func didMoveToWindow() {
        super.didMoveToWindow()
        guard breathing, window != nil, mark.layer.animation(forKey: "breathe") == nil else { return }
        let pulse = CABasicAnimation(keyPath: "transform.scale")
        pulse.fromValue = 0.82
        pulse.toValue = 1.0
        let glow = CABasicAnimation(keyPath: "shadowRadius")
        glow.fromValue = 8
        glow.toValue = 22
        let group = CAAnimationGroup()
        group.animations = [pulse, glow]
        group.duration = 1.1
        group.autoreverses = true
        group.repeatCount = .infinity
        group.timingFunction = CAMediaTimingFunction(name: .easeInEaseOut)
        mark.layer.add(group, forKey: "breathe")
    }

    public override func layoutSubviews() {
        super.layoutSubviews()
        let b = bounds
        CATransaction.begin()
        CATransaction.setDisableActions(true)
        redGlow.frame = CGRect(x: b.width * 0.2 - b.width * 0.8, y: b.height * 0.4 - b.height * 0.5,
                               width: b.width * 1.6, height: b.height)
        tealGlow.frame = CGRect(x: b.width * 0.85 - b.width * 0.6, y: b.height * 0.7 - b.height * 0.5,
                                width: b.width * 1.2, height: b.height)
        CATransaction.commit()
    }

    static func serif(size: CGFloat, weight: UIFont.Weight) -> UIFont {
        let base = UIFont.systemFont(ofSize: size, weight: weight)
        guard let descriptor = base.fontDescriptor.withDesign(.serif) else { return base }
        return UIFont(descriptor: descriptor, size: size)
    }
}
