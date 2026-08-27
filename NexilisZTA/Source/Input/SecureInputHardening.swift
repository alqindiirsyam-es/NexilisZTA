//
//  SecureInputHardening.swift
//  Nexilis iOS ZTA — secure input & UI surface hardening
//
//  Closes, on iOS:
//   H2 — block third-party keyboards app-wide (rejectCustomKeyboards, wired in AppDelegate)
//   H3 — disable copy/cut/paste/share on sensitive fields (SensitiveTextField)
//   H4 — suppress accessibility leakage of sensitive values (hideFromAccessibility)
//   F5 — clear pasteboard on sensitive-screen exit / after OTP (clearPasteboard, expiringCopy)
//   F11 — disable keyboard cache / autofill / suggestions on sensitive fields (configureSensitive)
//
//  H1 (the PIN itself) is handled by SecureNumericKeypad; this covers free-text
//  sensitive fields (account number, beneficiary) and value-bearing labels.
//

import UIKit

// MARK: - H3 / F11 — sensitive text field

public final class SensitiveTextField: UITextField {

    public override init(frame: CGRect) { super.init(frame: frame); configureSensitive() }
    public required init?(coder: NSCoder) { super.init(coder: coder); configureSensitive() }

    /// F11 — no cache, no autofill leakage, no predictive bar.
    public func configureSensitive() {
        isSecureTextEntry = true
        autocorrectionType = .no
        spellCheckingType = .no
        smartDashesType = .no
        smartQuotesType = .no
        smartInsertDeleteType = .no
        textContentType = nil          // set to .oneTimeCode only on OTP fields
        keyboardType = .asciiCapable
    }

    /// H3 — deny the editing menu (copy / cut / paste / share / lookup).
    public override func canPerformAction(_ action: Selector, withSender sender: Any?) -> Bool {
        let blocked: [Selector] = [
            #selector(UIResponderStandardEditActions.copy(_:)),
            #selector(UIResponderStandardEditActions.cut(_:)),
            #selector(UIResponderStandardEditActions.paste(_:)),
            #selector(UIResponderStandardEditActions.select(_:)),
            #selector(UIResponderStandardEditActions.selectAll(_:)),
            #selector(UIResponderStandardEditActions.delete(_:))
        ]
        if blocked.contains(action) { return false }
        // ✅ Fix — gunakan NSSelectorFromString untuk informal selector
        if #available(iOS 15.0, *), action == NSSelectorFromString("share:") { return false }
        return super.canPerformAction(action, withSender: sender)
    }
}

// MARK: - H2 / H4 / F5 helpers

public enum SecureInput {

    /// H2 — call from AppDelegate.application(_:shouldAllowExtensionPointIdentifier:).
    /// Returns false for the keyboard extension point to block all third-party keyboards.
    public static func rejectCustomKeyboards(_ id: UIApplication.ExtensionPointIdentifier) -> Bool {
        return id != .keyboard
    }

    /// H4 — exclude a value-bearing view (balance, PAN) from the accessibility tree,
    /// or mask its spoken value.
    public static func hideFromAccessibility(_ view: UIView, maskedValue: String? = nil) {
        if let masked = maskedValue {
            view.accessibilityLabel = masked
            view.accessibilityValue = nil
        } else {
            view.accessibilityElementsHidden = true
        }
    }

    /// F5 — clear the general pasteboard. Call on a sensitive screen's
    /// viewWillDisappear and after an OTP is consumed.
    public static func clearPasteboard() {
        UIPasteboard.general.items = []
    }

    /// F5 — copy a secret with a short expiry so it does not linger on the pasteboard.
    public static func expiringCopy(_ value: String, seconds: TimeInterval = 30) {
        UIPasteboard.general.setItems(
            [[UIPasteboard.typeAutomatic: value]],
            options: [.expirationDate: Date().addingTimeInterval(seconds)])
    }
}
