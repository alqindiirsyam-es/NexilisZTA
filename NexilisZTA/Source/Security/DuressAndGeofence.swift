//
//  DuressAndGeofence.swift
//  Nexilis iOS ZTA — DuressManager (L4), GeofencePolicy (L5)
//

import Foundation
import Security
import CoreLocation
import CommonCrypto

// MARK: - L4 — duress / panic

public enum DuressManager {

    public enum Verdict { case normal, duress, reject }

    private static let salt = "nx_duress_salt"
    private static let hNormal = "nx_duress_h_normal"
    private static let hDuress = "nx_duress_h_duress"
    private static let iterations: UInt32 = 120_000

    public static func enroll(normal: [UInt8], duress: [UInt8]) {
        var s = [UInt8](repeating: 0, count: 16)
        _ = s.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
        UserDefaults.standard.set(Data(s).base64EncodedString(), forKey: salt)
        UserDefaults.standard.set(pbkdf2(normal, s), forKey: hNormal)
        UserDefaults.standard.set(pbkdf2(duress, s), forKey: hDuress)
        var n = normal, d = duress
        SecureWipe.zero(&n); SecureWipe.zero(&d)
    }

    /// On DURESS this performs the wipe itself so the caller cannot branch on it and
    /// leak timing. Treat NORMAL as success; treat BOTH duress and reject as the same
    /// ordinary failure / empty state with no observable difference.
    public static func verifyAndAct(_ entered: [UInt8]) -> Verdict {
        defer { var e = entered; SecureWipe.zero(&e) }
        guard let sB64 = UserDefaults.standard.string(forKey: salt),
              let s = Data(base64Encoded: sB64) else { return .reject }
        let h = pbkdf2(entered, [UInt8](s))
        if constEq(h, UserDefaults.standard.string(forKey: hDuress)) {
            SecureWipe.secureWipe(hard: true)        // silent
            return .duress
        }
        return constEq(h, UserDefaults.standard.string(forKey: hNormal)) ? .normal : .reject
    }

    public static func panic() { SecureWipe.secureWipe(hard: true) }

    private static func pbkdf2(_ pw: [UInt8], _ salt: [UInt8]) -> String {
        var out = [UInt8](repeating: 0, count: 32)
        let pwStr = pw.map { Character(UnicodeScalar($0)) }.map(String.init).joined()
        _ = pwStr.withCString { pwPtr in
            salt.withUnsafeBufferPointer { sPtr in
                CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), pwPtr, strlen(pwPtr),
                                     sPtr.baseAddress, sPtr.count,
                                     CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                                     iterations, &out, out.count)
            }
        }
        return Data(out).base64EncodedString()
    }

    private static func constEq(_ a: String, _ b: String?) -> Bool {
        guard let b = b else { return false }
        let x = [UInt8](a.utf8), y = [UInt8](b.utf8)
        if x.count != y.count { return false }
        var diff: UInt8 = 0
        for i in 0..<x.count { diff |= x[i] ^ y[i] }
        return diff == 0
    }
}

// MARK: - L5 — geo-fence / region lock (soft control)

public enum GeofencePolicy {

    /// Coarse region check against the allowed list from the signed policy bundle.
    /// Consent-gated; combine with the VPN (E5) and jailbreak (A2) signals — a
    /// jailbroken device can spoof location, so treat as step-up, not hard-block.
    public static func outsideAllowedRegion(allowedISOCountries: Set<String>,
                                            current: CLLocation?,
                                            placemarkCountryISO: String?) -> Bool {
        guard let iso = placemarkCountryISO?.uppercased(), !iso.isEmpty else {
            return false // unknown region: do not lock out; let the server decide
        }
        return !allowedISOCountries.contains(iso)
    }
}
