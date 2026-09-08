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

    private static let salt = "nx_duress_salt_v2"
    private static let hNormal = "nx_duress_h_normal_v2"
    private static let hDuress = "nx_duress_h_duress_v2"
    private static let keyService = "io.nexilis.zta.duress"
    private static let keyAccount = "pepper"
    private static let iterations: UInt32 = 180_000

    public static func enroll(normal: [UInt8], duress: [UInt8]) {
        guard let pepper = pepperKey() else { return }
        var s = [UInt8](repeating: 0, count: 16)
        guard s.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }) == errSecSuccess else { return }
        UserDefaults.standard.set(Data(s).base64EncodedString(), forKey: salt)
        UserDefaults.standard.set(verifier(normal, salt: s, pepper: pepper), forKey: hNormal)
        UserDefaults.standard.set(verifier(duress, salt: s, pepper: pepper), forKey: hDuress)
        var n = normal, d = duress
        SecureWipe.zero(&n); SecureWipe.zero(&d); SecureWipe.zero(&s)
    }

    /// The stored verifier is useless for offline grinding unless the device-bound Keychain pepper
    /// is also available. Duress still performs its wipe inside this routine to minimize branching.
    public static func verifyAndAct(_ entered: [UInt8]) -> Verdict {
        defer { var e = entered; SecureWipe.zero(&e) }
        guard let sB64 = UserDefaults.standard.string(forKey: salt),
              let saltData = Data(base64Encoded: sB64),
              let pepper = pepperKey(createIfMissing: false) else { return .reject }
        let h = verifier(entered, salt: Array(saltData), pepper: pepper)
        if constEq(h, UserDefaults.standard.string(forKey: hDuress)) {
            SecureWipe.secureWipe(hard: true)
            return .duress
        }
        return constEq(h, UserDefaults.standard.string(forKey: hNormal)) ? .normal : .reject
    }

    public static func panic() { SecureWipe.secureWipe(hard: true) }

    private static func verifier(_ pw: [UInt8], salt: [UInt8], pepper: Data) -> String {
        var derived = [UInt8](repeating: 0, count: 32)
        let status: Int32 = pw.withUnsafeBytes { pwBuf in
            salt.withUnsafeBytes { saltBuf in
                CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                     pwBuf.bindMemory(to: Int8.self).baseAddress, pw.count,
                                     saltBuf.bindMemory(to: UInt8.self).baseAddress, salt.count,
                                     CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                                     iterations, &derived, derived.count)
            }
        }
        guard status == kCCSuccess else { return "" }
        var mac = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        pepper.withUnsafeBytes { keyBuf in
            derived.withUnsafeBytes { msgBuf in
                CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256),
                       keyBuf.baseAddress, pepper.count,
                       msgBuf.baseAddress, derived.count,
                       &mac)
            }
        }
        SecureWipe.zero(&derived)
        return Data(mac).base64EncodedString()
    }

    private static func pepperKey(createIfMissing: Bool = true) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keyService,
            kSecAttrAccount as String: keyAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        if SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
           let data = item as? Data, data.count == 32 { return data }
        guard createIfMissing else { return nil }
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { return nil }
        let data = Data(bytes)
        var add = query
        add.removeValue(forKey: kSecReturnData as String)
        add.removeValue(forKey: kSecMatchLimit as String)
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        SecItemDelete(query as CFDictionary)
        guard SecItemAdd(add as CFDictionary, nil) == errSecSuccess else { return nil }
        SecureWipe.zero(&bytes)
        return data
    }

    private static func constEq(_ a: String, _ b: String?) -> Bool {
        guard let b else { return false }
        let x = [UInt8](a.utf8), y = [UInt8](b.utf8)
        guard x.count == y.count else { return false }
        var diff: UInt8 = 0
        for i in x.indices { diff |= x[i] ^ y[i] }
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
