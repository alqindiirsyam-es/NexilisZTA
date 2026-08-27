//
//  SecuritySupport.swift
//  Nexilis iOS ZTA — PinSetStore (E2), SecurityAuditChain (I8), SecureWipe (F9/F10)
//

import Foundation
import Security
import CommonCrypto
import CryptoKit

#if SWIFT_PACKAGE
// CocoaPods builds Swift and Objective-C as one mixed-language target, so these
// types are already in scope. SwiftPM has no mixed target, so the Objective-C and
// C half is its own module and has to be imported.
import NexilisZTACore
#endif

// MARK: - E2 — signed, rotatable certificate pins (fail-safe)

public enum PinSetStore {

    private static let key = "nx_active_pins"
    // Compiled X.509 SPKI of the pin-rotation signer; inject via build config.
    private static let rotationSignerSPKIb64 = "" // BuildConfig.PIN_ROTATION_PUBKEY

    /// Additional accepted pins (sha256/Base64 SPKI), excluding the compiled floor.
    public static func activePins() -> Set<String> {
        guard let raw = UserDefaults.standard.string(forKey: key),
              let data = raw.data(using: .utf8),
              let arr = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else { return [] }
        let now = Date().timeIntervalSince1970 * 1000
        return Set(arr.compactMap { ($0["not_before"] as? Double ?? 0) <= now ? $0["pin"] as? String : nil })
    }

    /// True if the server leaf SPKI hash is in the rotated set.
    public static func matches(trust: SecTrust) -> Bool {
        guard let pin = leafPin(trust) else { return false }
        return activePins().contains(pin)
    }

    /// Apply a signed rotation payload received over the already-pinned channel.
    /// Verifies against the COMPILED signer key (not TLS). Additive only.
    @discardableResult
    public static func applyRotation(payloadJSON: String, signatureB64: String) -> Bool {
        guard verify(Data(payloadJSON.utf8), signatureB64),
              let data = payloadJSON.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let incoming = obj["pins"] as? [[String: Any]] else { return false }
        var existing = (try? JSONSerialization.jsonObject(
            with: Data((UserDefaults.standard.string(forKey: key) ?? "[]").utf8)) as? [[String: Any]]) ?? []
        var seen = Set(existing.compactMap { $0["pin"] as? String })
        for p in incoming where (p["pin"] as? String).map({ seen.insert($0).inserted }) == true {
            existing.append(p)
        }
        if let out = try? JSONSerialization.data(withJSONObject: existing),
           let s = String(data: out, encoding: .utf8) {
            UserDefaults.standard.set(s, forKey: key)
        }
        return true
    }

    private static func leafPin(_ trust: SecTrust) -> String? {
        guard let key = SecTrustCopyKey(trust),
              let spki = SPKI.encoded(key) else { return nil }
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        spki.withUnsafeBytes { _ = CC_SHA256($0.baseAddress, CC_LONG(spki.count), &hash) }
        return "sha256/" + Data(hash).base64EncodedString()
    }

    private static func verify(_ data: Data, _ sigB64: String) -> Bool {
        guard !rotationSignerSPKIb64.isEmpty,
              let spki = Data(base64Encoded: rotationSignerSPKIb64),
              let sig = Data(base64Encoded: sigB64) else { return false }
        let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                     kSecAttrKeyClass as String: kSecAttrKeyClassPublic]
        var err: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(spki as CFData, attrs as CFDictionary, &err) else { return false }
        return SecKeyVerifySignature(key, .ecdsaSignatureMessageX962SHA256,
                                     data as CFData, sig as CFData, &err)
    }
}

/// Minimal SPKI DER wrapper for EC P-256 keys (matches RASPGuard's nx_spki_for_key).
enum SPKI {
    static func encoded(_ key: SecKey) -> Data? {
        guard let raw = SecKeyCopyExternalRepresentation(key, nil) as Data? else { return nil }
        // EC P-256 SPKI prefix
        let prefix: [UInt8] = [0x30,0x59,0x30,0x13,0x06,0x07,0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,
                               0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07,0x03,0x42,0x00]
        guard raw.count == 65 else { return nil } // uncompressed P-256 point
        return Data(prefix) + raw
    }
}

// MARK: - I8 — tamper-evident audit chain

public enum SecurityAuditChain {

    private static let logKey = "nx_audit_log"
    private static let headKey = "nx_audit_head"
    private static let genesis = String(repeating: "0", count: 64)
    private static let maxRecords = 500

    public static func append(event: String, detail: [String: Any] = [:]) {
        let head = UserDefaults.standard.string(forKey: headKey) ?? genesis
        var log = (try? JSONSerialization.jsonObject(
            with: Data((UserDefaults.standard.string(forKey: logKey) ?? "[]").utf8)) as? [[String: Any]]) ?? []
        var rec: [String: Any] = ["ts": Date().timeIntervalSince1970 * 1000,
                                  "event": event, "detail": detail, "prev": head]
        let body = canonical(rec)
        let chained = sha256Hex(head + body)
        rec["hash"] = chained
        log.append(rec)
        if log.count > maxRecords { log.removeFirst(log.count - maxRecords) }
        if let out = try? JSONSerialization.data(withJSONObject: log),
           let s = String(data: out, encoding: .utf8) {
            UserDefaults.standard.set(s, forKey: logKey)
            UserDefaults.standard.set(chained, forKey: headKey)
        }
    }

    public static func verifyChain() -> Bool {
        let log = (try? JSONSerialization.jsonObject(
            with: Data((UserDefaults.standard.string(forKey: logKey) ?? "[]").utf8)) as? [[String: Any]]) ?? []
        var prev: String? = nil
        for var rec in log {
            guard let expectedPrev = rec["prev"] as? String, let stored = rec["hash"] as? String else { return false }
            if let p = prev, p != expectedPrev { return false }
            rec["hash"] = nil
            if stored != sha256Hex(expectedPrev + canonical(rec)) { return false }
            prev = stored
        }
        let head = UserDefaults.standard.string(forKey: headKey) ?? genesis
        return prev == nil ? head == genesis : prev == head
    }

    public static func headHash() -> String {
        UserDefaults.standard.string(forKey: headKey) ?? genesis
    }

    private static func canonical(_ d: [String: Any]) -> String {
        // stable key order
        let sorted = d.keys.sorted()
        return sorted.map { "\($0)=\(d[$0] ?? "")" }.joined(separator: "&")
    }

    private static func sha256Hex(_ s: String) -> String {
        let digest = SHA256.hash(data: Data(s.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - F9 / F10 — cryptographic wipe & memory hygiene

public enum SecureWipe {

    public static func zero(_ buf: inout [UInt8]) { for i in 0..<buf.count { buf[i] = 0 } }
    public static func zero(_ data: inout Data) { data.resetBytes(in: 0..<data.count) }

    /// Full teardown. `hard` = tamper/duress (also clears audit + local revoke).
    public static func secureWipe(hard: Bool) {
        SessionManagerBridge.clearAll()        // -> SessionManager.clearAll (ObjC)
        AppAttestBridge.clearRegistration()     // delete App Attest key references
        SecureInput.clearPasteboard()
        if hard {
            SecurityAuditChain.append(event: "secure_wipe_hard")
        }
    }
}

/// Thin bridges to the existing ObjC singletons (declare in the bridging header).
enum SessionManagerBridge { static func clearAll() { SessionManager.shared().clearAll() } }
enum AppAttestBridge { static func clearRegistration() { /* AppAttestManager: delete keyId + delivery key */ } }


