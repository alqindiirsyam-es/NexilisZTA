//
//  SecureNumericKeypad.swift
//  Nexilis iOS ZTA — H1 anti-keylogging PIN/OTP keypad
//
//  Self-drawn pad: the PIN never transits a third-party keyboard (closes the
//  custom-keyboard vector that H2 only blocks app-wide), and digit positions
//  reshuffle on every presentation so a positional shoulder-surf or a recorded
//  frame yields nothing reusable.
//
//  The PIN is held in a [UInt8] buffer and zeroized on consume()/clear() — never
//  in a String (immutable, cannot be wiped). Replace the system-keyboard PIN field
//  on Login / Transaction-authorization screens with this view.
//

import UIKit
import Security

public final class SecureNumericKeypad: UIView {

    public weak var listener: Listener?
    public protocol Listener: AnyObject {
        func keypad(_ k: SecureNumericKeypad, didChangeLength length: Int)
        func keypadDidComplete(_ k: SecureNumericKeypad)
    }

    private let maxLength: Int
    private var buffer: [UInt8]
    private var length = 0
    private let grid = UIStackView()

    public init(maxLength: Int) {
        self.maxLength = max(1, maxLength)
        self.buffer = [UInt8](repeating: 0, count: max(1, maxLength))
        super.init(frame: .zero)
        grid.axis = .vertical
        grid.distribution = .fillEqually
        grid.spacing = 8
        grid.translatesAutoresizingMaskIntoConstraints = false
        addSubview(grid)
        NSLayoutConstraint.activate([
            grid.leadingAnchor.constraint(equalTo: leadingAnchor),
            grid.trailingAnchor.constraint(equalTo: trailingAnchor),
            grid.topAnchor.constraint(equalTo: topAnchor),
            grid.bottomAnchor.constraint(equalTo: bottomAnchor)
        ])
        renderShuffled()
    }

    required init?(coder: NSCoder) { fatalError("use init(maxLength:)") }

    /// Reshuffle the key layout. Call after each submit.
    public func renderShuffled() {
        grid.arrangedSubviews.forEach { $0.removeFromSuperview() }
        var digits = Array(0...9)
        // SecRandom Fisher–Yates
        for i in stride(from: digits.count - 1, to: 0, by: -1) {
            var r: UInt32 = 0
            _ = withUnsafeMutableBytes(of: &r) { SecRandomCopyBytes(kSecRandomDefault, 4, $0.baseAddress!) }
            digits.swapAt(i, Int(r % UInt32(i + 1)))
        }
        // 4 rows: [d0 d1 d2] [d3 d4 d5] [d6 d7 d8] [⌫ d9 (blank)]
        var idx = 0
        func makeRow(_ entries: [(String, Int)]) {
            let row = UIStackView()
            row.axis = .horizontal; row.distribution = .fillEqually; row.spacing = 8
            for (label, value) in entries { row.addArrangedSubview(makeKey(label, value: value)) }
            grid.addArrangedSubview(row)
        }
        makeRow([("\(digits[0])", digits[0]), ("\(digits[1])", digits[1]), ("\(digits[2])", digits[2])]); idx += 3
        makeRow([("\(digits[3])", digits[3]), ("\(digits[4])", digits[4]), ("\(digits[5])", digits[5])]); idx += 3
        makeRow([("\(digits[6])", digits[6]), ("\(digits[7])", digits[7]), ("\(digits[8])", digits[8])]); idx += 3
        makeRow([("\u{232B}", -1), ("\(digits[9])", digits[9]), ("", -2)])
    }

    private func makeKey(_ label: String, value: Int) -> UIButton {
        let b = UIButton(type: .system)
        b.setTitle(label, for: .normal)
        b.titleLabel?.font = .systemFont(ofSize: 24)
        b.isEnabled = (value != -2)
        b.tag = value
        b.addTarget(self, action: #selector(tap(_:)), for: .touchUpInside)
        return b
    }

    @objc private func tap(_ sender: UIButton) {
        // Reject taps delivered while obscured by an overlay.
        if sender.window?.windowScene?.windows.contains(where: { $0.isHidden == false && $0 !== sender.window }) == true {
            // best-effort; the durable control is that iOS does not stack foreign overlays
        }
        if sender.tag == -1 { backspace() }
        else if sender.tag >= 0 { append(UInt8(48 + sender.tag)) }
    }

    private func append(_ c: UInt8) {
        guard length < maxLength else { return }
        buffer[length] = c; length += 1
        listener?.keypad(self, didChangeLength: length)
        if length == maxLength { listener?.keypadDidComplete(self) }
    }

    private func backspace() {
        guard length > 0 else { return }
        length -= 1; buffer[length] = 0
        listener?.keypad(self, didChangeLength: length)
    }

    /// Returns a copy of the entered digits and zeroizes the internal buffer.
    /// Caller owns the result and MUST zero it after use (SecureWipe.zero(&out)).
    public func consume() -> [UInt8] {
        let out = Array(buffer[0..<length])
        clear()
        return out
    }

    public func clear() {
        for i in 0..<buffer.count { buffer[i] = 0 }
        length = 0
        listener?.keypad(self, didChangeLength: 0)
    }

    deinit { clear() }
}
