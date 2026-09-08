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

    // Store signed envelopes, never bare accepted pins. A hostile local preference edit must not
    // be able to manufacture an accepted SPKI without the offline rotation private key.
    private static let key = "nx_active_pin_envelopes_v3"
    private static let lock = NSLock()
    private static var rotationSignerSPKIb64: String?

    public static func configure(rotationSignerSPKIBase64: String?) {
        lock.lock()
        rotationSignerSPKIb64 = rotationSignerSPKIBase64?.trimmingCharacters(in: .whitespacesAndNewlines)
        lock.unlock()
        syncAllToRASP()
    }

    /// Additional signature-verified pins for a host, excluding the primary/backup floor.
    public static func activePins(forHost host: String) -> Set<String> {
        let wanted = host.lowercased()
        let now = Date().timeIntervalSince1970 * 1000
        return Set(validPinEntries().compactMap { entry in
            guard (entry["domain"] as? String)?.lowercased() == wanted,
                  let pin = entry["pin"] as? String,
                  let notBefore = number(entry["not_before"]), notBefore <= now else { return nil }
            if let notAfter = number(entry["not_after"]), notAfter > 0, now > notAfter { return nil }
            return pin
        })
    }

    public static func matches(trust: SecTrust, host: String) -> Bool {
        guard let pin = leafPin(trust) else { return false }
        return activePins(forHost: host).contains(pin)
    }

    /// Apply an additive signed rotation payload. The exact signed payload + signature are stored;
    /// every later read re-verifies them, so UserDefaults compromise can cause at most pin loss/DoS,
    /// never acceptance of an attacker-injected SPKI.
    @discardableResult
    public static func applyRotation(payloadJSON: String, signatureB64: String) -> Bool {
        guard verify(Data(payloadJSON.utf8), signatureB64),
              let pins = validatedPins(from: payloadJSON), !pins.isEmpty else { return false }

        var envelopes = storedEnvelopes()
        if !envelopes.contains(where: { ($0["payload"] as? String) == payloadJSON &&
                                        ($0["signature"] as? String) == signatureB64 }) {
            envelopes.append(["payload": payloadJSON, "signature": signatureB64])
        }
        guard let out = try? JSONSerialization.data(withJSONObject: envelopes),
              let encoded = String(data: out, encoding: .utf8) else { return false }
        UserDefaults.standard.set(encoded, forKey: key)
        syncAllToRASP()
        SecurityAuditChain.append(event: "pin_rotation_applied", detail: ["entries": pins.count])
        return true
    }

    private static func storedEnvelopes() -> [[String: Any]] {
        guard let raw = UserDefaults.standard.string(forKey: key),
              let data = raw.data(using: .utf8),
              let arr = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else { return [] }
        return arr
    }

    private static func validPinEntries() -> [[String: Any]] {
        var result: [[String: Any]] = []
        for envelope in storedEnvelopes() {
            guard let payload = envelope["payload"] as? String,
                  let signature = envelope["signature"] as? String,
                  verify(Data(payload.utf8), signature),
                  let pins = validatedPins(from: payload) else { continue }
            result.append(contentsOf: pins)
        }
        return result
    }

    private static func validatedPins(from payloadJSON: String) -> [[String: Any]]? {
        guard let data = payloadJSON.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let incoming = obj["pins"] as? [[String: Any]], !incoming.isEmpty else { return nil }
        let validated: [[String: Any]] = incoming.compactMap { entry in
            guard let domain = entry["domain"] as? String, !domain.isEmpty,
                  let pin = entry["pin"] as? String, pin.hasPrefix("sha256/"),
                  let pinBytes = Data(base64Encoded: String(pin.dropFirst("sha256/".count))), pinBytes.count == 32,
                  number(entry["not_before"]) != nil else { return nil }
            if let notAfter = number(entry["not_after"]),
               let notBefore = number(entry["not_before"]), notAfter > 0, notAfter <= notBefore { return nil }
            var out = entry
            out["domain"] = domain.lowercased()
            return out
        }
        return validated.count == incoming.count ? validated : nil
    }

    private static func syncAllToRASP() {
        let entries = validPinEntries()
        let hosts = Set(entries.compactMap { ($0["domain"] as? String)?.lowercased() })
        for host in hosts {
            RASPGuard.shared().configureAdditionalPins(Array(activePins(forHost: host)), forHost: host)
        }
    }

    private static func number(_ any: Any?) -> Double? {
        if let n = any as? NSNumber { return n.doubleValue }
        if let s = any as? String { return Double(s) }
        return nil
    }

    private static func leafPin(_ trust: SecTrust) -> String? {
        guard let key = SecTrustCopyKey(trust),
              let spki = SPKI.encoded(key) else { return nil }
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        spki.withUnsafeBytes { _ = CC_SHA256($0.baseAddress, CC_LONG(spki.count), &hash) }
        return "sha256/" + Data(hash).base64EncodedString()
    }

    private static func verify(_ data: Data, _ sigB64: String) -> Bool {
        lock.lock(); let signer = rotationSignerSPKIb64; lock.unlock()
        guard let signer, !signer.isEmpty,
              let spki = Data(base64Encoded: signer), spki.count >= 65,
              let sig = Data(base64Encoded: sigB64) else { return false }
        let raw = Data(spki.suffix(65))
        guard raw.first == 0x04 else { return false }
        let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                     kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                                     kSecAttrKeySizeInBits as String: 256]
        var err: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(raw as CFData, attrs as CFDictionary, &err) else { return false }
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

    private static let logKey = "nx_audit_log_v2"
    private static let headKey = "nx_audit_head_v2"
    private static let keyService = "io.nexilis.zta.audit.hmac"
    private static let keyAccount = "device"
    private static let genesis = String(repeating: "0", count: 64)
    private static let maxRecords = 500

    /// Called whenever the head moves, so it can be anchored somewhere the device cannot
    /// rewrite. Set by APISZTA at the modes that have a server to anchor it to; nil elsewhere,
    /// and appending is unaffected either way.
    public static var onHeadChanged: ((String) -> Void)?

    public static func append(event: String, detail: [String: Any] = [:]) {
        guard let key = auditKey() else { return }
        let head = UserDefaults.standard.string(forKey: headKey) ?? genesis
        var log = (try? JSONSerialization.jsonObject(
            with: Data((UserDefaults.standard.string(forKey: logKey) ?? "[]").utf8)) as? [[String: Any]]) ?? []
        var rec: [String: Any] = ["ts": Date().timeIntervalSince1970 * 1000,
                                  "event": event, "detail": detail, "prev": head]
        let body = canonical(rec)
        let chained = hmacHex(key: key, message: head + body)
        rec["mac"] = chained
        log.append(rec)
        if log.count > maxRecords { log.removeFirst(log.count - maxRecords) }
        if let out = try? JSONSerialization.data(withJSONObject: log),
           let encoded = String(data: out, encoding: .utf8) {
            UserDefaults.standard.set(encoded, forKey: logKey)
            UserDefaults.standard.set(chained, forKey: headKey)
            onHeadChanged?(chained)
        }
    }

    public static func verifyChain() -> Bool {
        guard let key = auditKey(createIfMissing: false) else { return false }
        let log = (try? JSONSerialization.jsonObject(
            with: Data((UserDefaults.standard.string(forKey: logKey) ?? "[]").utf8)) as? [[String: Any]]) ?? []
        var prev: String? = nil
        for var rec in log {
            guard let expectedPrev = rec["prev"] as? String,
                  let stored = rec["mac"] as? String else { return false }
            if let p = prev, p != expectedPrev { return false }
            rec.removeValue(forKey: "mac")
            if !constantTimeEqual(stored, hmacHex(key: key, message: expectedPrev + canonical(rec))) { return false }
            prev = stored
        }
        let head = UserDefaults.standard.string(forKey: headKey) ?? genesis
        return prev == nil ? head == genesis : prev == head
    }

    public static func headHash() -> String {
        UserDefaults.standard.string(forKey: headKey) ?? genesis
    }

    /// Cryptographic destruction for duress/hard wipe. The final wipe event should be anchored
    /// before this is called if a backend anchor is configured.
    public static func destroyLocalState() {
        UserDefaults.standard.removeObject(forKey: logKey)
        UserDefaults.standard.removeObject(forKey: headKey)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keyService,
            kSecAttrAccount as String: keyAccount
        ]
        SecItemDelete(query as CFDictionary)
    }

    private static func canonical(_ d: [String: Any]) -> String {
        let sorted = d.keys.sorted()
        return sorted.map { "\($0)=\(d[$0] ?? "")" }.joined(separator: "&")
    }

    private static func hmacHex(key: SymmetricKey, message: String) -> String {
        let mac = HMAC<SHA256>.authenticationCode(for: Data(message.utf8), using: key)
        return Data(mac).map { String(format: "%02x", $0) }.joined()
    }

    private static func constantTimeEqual(_ a: String, _ b: String) -> Bool {
        let x = Array(a.utf8), y = Array(b.utf8)
        guard x.count == y.count else { return false }
        var diff: UInt8 = 0
        for i in x.indices { diff |= x[i] ^ y[i] }
        return diff == 0
    }

    private static func auditKey(createIfMissing: Bool = true) -> SymmetricKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keyService,
            kSecAttrAccount as String: keyAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        if SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
           let data = item as? Data, data.count == 32 {
            return SymmetricKey(data: data)
        }
        guard createIfMissing else { return nil }
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { return nil }
        let data = Data(bytes)
        var add = query
        add.removeValue(forKey: kSecReturnData as String)
        add.removeValue(forKey: kSecMatchLimit as String)
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        SecItemDelete(query as CFDictionary)
        guard SecItemAdd(add as CFDictionary, nil) == errSecSuccess else { return nil }
        return SymmetricKey(data: data)
    }
}

// MARK: - F9 / F10 — cryptographic wipe & memory hygiene

public extension Notification.Name {
    static let ztaHardWipeRequested = Notification.Name("io.nexilis.zta.hardWipeRequested")
}

public enum SecureWipe {

    public static func zero(_ buf: inout [UInt8]) { for i in 0..<buf.count { buf[i] = 0 } }
    public static func zero(_ data: inout Data) { data.resetBytes(in: 0..<data.count) }

    /// Full teardown. `hard` = tamper/duress (also clears audit + local revoke).
    public static func secureWipe(hard: Bool) {
        SessionManagerBridge.clearAll()        // -> SessionManager.clearAll (ObjC)
        if hard {
            AppAttestBridge.clearRegistrationImmediately() // duress: local destruction must not wait on network
        } else {
            AppAttestBridge.clearRegistration()             // graceful path may attempt server revocation first
        }
        SecureInput.clearPasteboard()
        if hard {
            SecurityAuditChain.append(event: "secure_wipe_hard")
            NotificationCenter.default.post(name: .ztaHardWipeRequested, object: nil)
            SecurityAuditChain.destroyLocalState()
        }
    }
}

/// Thin bridges to the existing ObjC singletons (declare in the bridging header).
enum SessionManagerBridge { static func clearAll() { SessionManager.shared().clearAll() } }
enum AppAttestBridge {
    static func clearRegistration() { AppAttestManager.shared().clearRegistration() }
    static func clearRegistrationImmediately() { AppAttestManager.shared().clearLocalRegistrationImmediately() }
}



// MARK: - Sentinel v2 — protocol version
//
// Code-owned, never negotiated upward. A signed pack may declare that it needs no more than this
// value; one that needs more is refused rather than partially applied, because a policy this
// build cannot express is a policy this build cannot enforce.
public enum SentinelProtocol {
    public static let current = 2
    public static let name    = "sentinel-trust-v2"

    /// What this build can actually do, named so a pack can say what it needs. A pack whose
    /// `compatibility.required_features` names anything outside this set is refused whole rather
    /// than applied by a client that will quietly not do the thing the pack was written to
    /// require — the same fail-closed rule as `current`, at feature granularity.
    public static let supportedFeatures: Set<String> = [
        "semantic_decision",
        "bounded_telemetry",
        "signed_threat_intel",
        "behavior_correlation",
        "on_device_statistical_model",
    ]
}

// MARK: - A1 — signed Security Pack (OTA policy)
//
// The same shape and the same rule as `PinSetStore`: the payload and its signature are stored
// together and re-verified on every read, so a hostile preference edit can cost the device its
// pack but can never write one. The signer is an offline key; the ZTA service is a courier.
//
// Two things a pack can never do, enforced in `sanitise` below rather than trusted to the signer:
// it cannot loosen a threshold past what this build compiled in, and it cannot go backwards in
// version. Signed does not mean unconditionally obeyed — a signing key that leaks would otherwise
// become a remote switch for turning the client's own floors off.
public enum SecurityPackStore {

    private static let packKey  = "nx_security_pack_envelope_v1"
    private static let epochKey = "nx_security_pack_server_epoch_ms"
    private static let lock     = NSLock()
    private static var signerSPKIb64: String?
    private static var cache: [String: Any]?

    /// Compiled floors. A pack may move each of these only in the tightening direction.
    private static let compiledDenyAt   = 70
    private static let compiledRevokeAt = 95

    public static func configure(signerSPKIBase64: String?) {
        lock.lock()
        signerSPKIb64 = signerSPKIBase64?.trimmingCharacters(in: .whitespacesAndNewlines)
        cache = nil
        lock.unlock()
    }

    /// The pack in force, or nil. Every read re-verifies the stored signature.
    public static func current() -> [String: Any]? {
        lock.lock()
        if let cache { lock.unlock(); return cache }
        lock.unlock()

        guard let raw = UserDefaults.standard.string(forKey: packKey),
              let data = raw.data(using: .utf8),
              let envelope = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let payload = envelope["payload"] as? String,
              let signature = envelope["signature"] as? String,
              verify(Data(payload.utf8), signature),
              let pack = sanitise(payload) else { return nil }

        lock.lock(); cache = pack; lock.unlock()
        return pack
    }

    /// Applies a freshly fetched pack. Returns false for anything it refuses, and refusing leaves
    /// the previous pack in force — a failed refresh must never be a way to clear the policy.
    @discardableResult
    public static func apply(payloadJSON: String, signatureB64: String) -> Bool {
        guard verify(Data(payloadJSON.utf8), signatureB64),
              let incoming = sanitise(payloadJSON) else {
            SecurityAuditChain.append(event: "security_pack_rejected")
            return false
        }
        let incomingVersion = (incoming["version"] as? NSNumber)?.intValue ?? 0
        let currentVersion  = (current()?["version"] as? NSNumber)?.intValue ?? 0
        guard incomingVersion > currentVersion else {
            // Not an error on a re-fetch of the same pack, but never accepted as an update: an
            // old signed pack replayed by a compromised courier is the rollback this blocks.
            return incomingVersion == currentVersion
        }
        guard let out = try? JSONSerialization.data(withJSONObject: ["payload": payloadJSON, "signature": signatureB64]),
              let encoded = String(data: out, encoding: .utf8) else { return false }
        UserDefaults.standard.set(encoded, forKey: packKey)
        lock.lock(); cache = nil; lock.unlock()
        SecurityAuditChain.append(event: "security_pack_applied", detail: ["version": incomingVersion])
        return true
    }

    /// The server's own clock, remembered so a device clock moved backwards cannot revive an
    /// expired pack. Monotonic: a smaller value than the one already stored is ignored.
    public static func recordServerTime(_ epochMs: Double) {
        guard epochMs > 0 else { return }
        let stored = UserDefaults.standard.double(forKey: epochKey)
        if epochMs > stored { UserDefaults.standard.set(epochMs, forKey: epochKey) }
    }

    /// The later of the device clock and the last server timestamp seen.
    static func referenceTimeMs() -> Double {
        max(Date().timeIntervalSince1970 * 1000, UserDefaults.standard.double(forKey: epochKey))
    }

    public static func denyAt()   -> Int { threshold("deny_at",   floor: compiledDenyAt) }
    public static func revokeAt() -> Int { threshold("revoke_at", floor: compiledRevokeAt) }

    private static func threshold(_ name: String, floor: Int) -> Int {
        guard let response = current()?["response"] as? [String: Any],
              let value = (response[name] as? NSNumber)?.intValue else { return floor }
        // Tightening only. A pack that asks for a higher threshold is asking this build to accept
        // more risk than it was compiled to accept, which is exactly the direction not to trust.
        return max(1, min(floor, value))
    }

    private static func sanitise(_ payloadJSON: String) -> [String: Any]? {
        guard let data = payloadJSON.data(using: .utf8),
              let pack = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }

        // The signature proved where the pack came from. This proves it is a pack this build can
        // actually enforce — version, protocol, lifetime, weights, thresholds, indicators and
        // model parameters all inside the bounds compiled in here. Whole-pack and fail-closed: a
        // pack with one bad member is refused entirely rather than applied in part.
        //
        // The two limits the signer is never trusted with stay where they were: `threshold` only
        // ever tightens, and `apply` never installs a pack that does not move the version forward.
        guard SecurityPackPolicyValidator.validate(pack, now: referenceTimeMs()) else { return nil }

        return pack
    }

    private static func verify(_ data: Data, _ sigB64: String) -> Bool {
        lock.lock(); let signer = signerSPKIb64; lock.unlock()
        guard let signer, !signer.isEmpty,
              let spki = Data(base64Encoded: signer), spki.count >= 65,
              let sig = Data(base64Encoded: sigB64) else { return false }
        let raw = Data(spki.suffix(65))
        guard raw.first == 0x04 else { return false }
        let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                    kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                                    kSecAttrKeySizeInBits as String: 256]
        var err: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(raw as CFData, attrs as CFDictionary, &err) else { return false }
        return SecKeyVerifySignature(key, .ecdsaSignatureMessageX962SHA256, data as CFData, sig as CFData, &err)
    }
}

// MARK: - A2 — normalized threat telemetry
//
// Privacy-minimized by construction: sensors, categories and scores, never message contents,
// credentials or transaction bodies. What goes on the wire is what a risk engine can act on and
// nothing a support ticket would have to redact.
public enum SentinelThreatTelemetry {

    public static func currentEvents() -> [[String: Any]] {
        var events: [[String: Any]] = []
        let now = Date().timeIntervalSince1970 * 1000

        let guardState = RASPGuard.shared()
        if !guardState.deviceClean || guardState.lastThreatMask != RASP_THREAT_NONE {
            events.append(event(sensor: "rasp", category: "runtime_instrumentation",
                                severity: 95, confidence: 95, now: now,
                                attributes: ["threat_code": String(guardState.lastThreatMask)]))
        }

        let network = NetworkPosture.currentPosture()
        if (network["vpn_risky"] as? NSNumber)?.boolValue == true {
            events.append(event(sensor: "network:vpn", category: "network",
                                severity: 35, confidence: 90, now: now,
                                attributes: ["network_type": "risky_vpn"]))
        }
        if (network["http_proxy_enabled"] as? NSNumber)?.boolValue == true ||
           (network["https_proxy_enabled"] as? NSNumber)?.boolValue == true ||
           (network["socks_proxy_enabled"] as? NSNumber)?.boolValue == true {
            events.append(event(sensor: "network:proxy", category: "network",
                                severity: 45, confidence: 90, now: now,
                                attributes: ["network_type": "proxy"]))
        }

        // Intelligence first, correlation second. An indicator match is itself a signal the
        // correlator is entitled to reason about, so enriching afterwards would leave the
        // strongest evidence out of exactly the rules written to act on it.
        events.append(contentsOf: SentinelThreatIntelMatcher.enrich(events: events,
                                                                    pack: SecurityPackStore.current(),
                                                                    now: now))
        events.append(contentsOf: SentinelBehaviorCorrelator.derive(events: events, now: now))
        return events
    }

    /// The device's own opinion, used to refuse a sensitive transaction before it is even asked
    /// for. It is advisory: the server scores the same evidence and its number is the one that can
    /// revoke. Both directions matter — a device that is clearly compromised should not need the
    /// network's permission to stop.
    public static func localRiskScore(events: [[String: Any]]) -> Int {
        let pack    = SecurityPackStore.current()
        let weights = pack?["risk_weights"] as? [String: Any]
        let hard    = Set((pack?["hard_block_categories"] as? [String]) ?? [])
        let now     = SecurityPackStore.referenceTimeMs()

        var strongest: [String: Int] = [:]
        var hardBlock = false
        for e in events {
            let category   = e["category"] as? String ?? "other"
            let severity   = clamp((e["severity"]   as? NSNumber)?.intValue ?? 0)
            let confidence = clamp((e["confidence"] as? NSNumber)?.intValue ?? 0)
            let weight     = (weights?[category] as? NSNumber)?.intValue ?? defaultWeight(category)
            let observed   = (e["observed_at_ms"] as? NSNumber)?.doubleValue ?? now
            let decay      = decayFactor(category: category, ageMs: max(0, now - observed))
            let value      = Int((Double(weight) * Double(severity) / 100 * Double(confidence) / 100 * decay).rounded())

            let attrs = e["attributes"] as? [String: Any]
            let key   = [category, e["sensor"] as? String ?? "",
                         attrs?["rule_id"] as? String ?? "",
                         attrs?["indicator_sha256"] as? String ?? ""].joined(separator: "|")
            strongest[key] = max(strongest[key] ?? 0, value)

            if hard.contains(category) && severity >= 90 && confidence >= 80 { hardBlock = true }
        }
        // Bounded, explainable augmentation from the signed pack's own parameters. It can only
        // add, and only up to the ceiling the pack was validated against, so a model that is
        // simply wrong costs false positives rather than a missed compromise. With no model in
        // the pack this adds exactly nothing.
        let model = SentinelOnDeviceStatisticalModel.evaluate(events: events, pack: pack, now: now)
        var score = min(100, strongest.values.reduce(0, +) + model.addedRisk)
        if hardBlock { score = max(score, 95) }
        return score
    }

    private static func clamp(_ v: Int) -> Int { min(100, max(0, v)) }

    private static func defaultWeight(_ c: String) -> Int {
        switch c {
        case "transaction_manipulation":               return 100
        case "runtime_instrumentation", "app_integrity": return 85
        case "rat", "malware":                          return 80
        case "attestation":                             return 75
        case "external_mtd":                            return 70
        case "device_integrity":                        return 60
        case "overlay", "accessibility", "screen_capture", "automation": return 55
        case "phishing":                                return 45
        case "network":                                 return 35
        default:                                        return 10
        }
    }

    /// Old evidence counts less, but the categories that mean the process itself is untrustworthy
    /// never decay to nothing inside the window — a debugger seen an hour ago is not a debugger
    /// that went away.
    private static func decayFactor(category: String, ageMs: Double) -> Double {
        let pack     = SecurityPackStore.current()?["risk_decay"] as? [String: Any]
        let half     = Double(min(1440, max(5, (pack?["half_life_minutes"]     as? NSNumber)?.intValue ?? 60)))
        let maxAge   = Double(min(1440, max(5, (pack?["max_event_age_minutes"] as? NSNumber)?.intValue ?? 120)))
        var floor    = Double(min(80,  max(10, (pack?["floor_percent"]         as? NSNumber)?.intValue ?? 25)))
        if ageMs > maxAge * 60000 { return 0 }
        if ["runtime_instrumentation", "app_integrity", "rat", "malware",
            "transaction_manipulation", "external_mtd"].contains(category) { floor = max(50, floor) }
        return max(floor / 100, pow(0.5, ageMs / (half * 60000)))
    }

    /// `evidence` is the hash the event is *about* — the indicator that matched, where one did.
    /// It is the field the server contract reconciles a client event against, and it is empty for
    /// a sensor reading that is not about a specific hashed artefact.
    static func event(sensor: String, category: String, severity: Int, confidence: Int,
                      now: Double, evidence: String = "", attributes: [String: Any]) -> [String: Any] {
        ["event_id": "tev_" + UUID().uuidString, "sensor": sensor, "category": category,
         "severity": severity, "confidence": confidence, "observed_at_ms": now,
         "evidence_sha256": evidence, "attributes": attributes]
    }
}

// MARK: - A3 — behaviour correlation (ruleset v2)
//
// One weak signal is noise. Two weak signals of different kinds, at the same moment, are a
// pattern — and the pattern deserves a weight neither of its halves earns alone.
//
// Two things make this a ruleset rather than a pile of conditions. Every rule is *windowed*: it
// asks whether the signals were seen together, not merely whether both appear somewhere in the
// buffer, because a debugger this morning and a proxy this afternoon are two facts, not one
// attack. And two rules are *ordered*: remote control followed by a payment is a different event
// from a payment followed by remote control, and only the first is the shape of a fraud.
//
// Everything derived here only ever adds risk. The server correlates the same evidence and its
// conclusion is the one that can revoke; this exists so a device can refuse a transaction on its
// own evidence without waiting to be told.
public enum SentinelBehaviorCorrelator {

    /// Carried on every derived event as `model_version`, so a decision can be traced back to the
    /// rules that produced it after those rules have moved on.
    public static let rulesetVersion = "behavior-v2"

    private static let fiveMinutes: Double  = 5 * 60_000
    private static let tenMinutes: Double   = 10 * 60_000
    private static let fifteenMinutes: Double = 15 * 60_000

    /// The four ways a device gets driven or watched by something that is not its user.
    private static let remoteControl: Set<String> = ["accessibility", "overlay", "screen_capture", "automation"]

    /// The categories that mean the process itself is no longer trustworthy.
    private static let compromisedRuntime: Set<String> = ["runtime_instrumentation", "app_integrity", "rat", "malware", "device_integrity"]

    public static func derive(events: [[String: Any]], now: Double) -> [[String: Any]] {
        guard events.count >= 2 else { return [] }
        var derived: [[String: Any]] = []

        // A tampered runtime that also fails its own integrity check is not two problems. It is
        // one problem that has been confirmed twice, and there is no benign reading of it.
        if has(events, "runtime_instrumentation", now, fiveMinutes),
           has(events, "app_integrity", now, fiveMinutes) {
            derived.append(correlation("instrumentation_plus_integrity", "runtime_instrumentation", 98, 95, now))
        }

        // Someone else is driving the screen while money is moving. This is the shape the whole
        // sensitive-transaction path exists to stop.
        if hasAny(events, remoteControl.union(["rat"]), now, fiveMinutes),
           has(events, "transaction_manipulation", now, fiveMinutes) {
            derived.append(correlation("rat_plus_transaction", "transaction_manipulation", 100, 98, now))
        }

        // Three of the four remote-control signals at once is a toolkit, not a coincidence. Any
        // one of them has an innocent explanation; three together do not.
        if distinct(events, remoteControl, now, tenMinutes) >= 3 {
            derived.append(correlation("remote_control_cluster", "rat", 92, 90, now))
        }

        // A third-party MTD product and this app's own sensors reaching the same conclusion is
        // worth more than either alone — two independent vendors are hard to fool at once.
        if has(events, "external_mtd", now, fifteenMinutes),
           hasAny(events, compromisedRuntime, now, fifteenMinutes) {
            derived.append(correlation("external_mtd_corroborated", "external_mtd", 95, 95, now))
        }

        // The classic instrument-and-exfiltrate shape: a runtime that has been tampered with, on a
        // network arranged to carry what it finds.
        if has(events, "network", now, fiveMinutes),
           hasAny(events, ["runtime_instrumentation", "app_integrity", "attestation"], now, fiveMinutes) {
            derived.append(correlation("network_plus_runtime", "runtime_instrumentation", 90, 85, now))
        }

        // A phishing signal plus something able to read or drive the screen is a credential
        // harvest with a delivery mechanism attached.
        if has(events, "phishing", now, tenMinutes),
           hasAny(events, ["overlay", "accessibility", "automation"], now, tenMinutes) {
            derived.append(correlation("phishing_plus_overlay", "phishing", 88, 85, now))
        }

        // Ordered. Remote control *then* a transaction is a session being driven into a payment;
        // the reverse order is a user who was already paying when an accessibility service woke
        // up, and it does not deserve the same weight.
        if ordered(events, first: remoteControl, second: "transaction_manipulation", now: now, window: tenMinutes) {
            derived.append(correlation("remote_control_then_transaction", "transaction_manipulation", 100, 97, now))
        }

        // Ordered. Phishing, then an accessibility service, with an overlay in the same window:
        // lure, then the means to read what the lure collects.
        if ordered(events, first: ["phishing"], second: "accessibility", now: now, window: tenMinutes),
           has(events, "overlay", now, tenMinutes) {
            derived.append(correlation("credential_interception_chain", "phishing", 96, 92, now))
        }

        // Retained from ruleset v1. `remote_control_cluster` needs three of the four signals, so
        // dropping this would lose the two-signal case this build has been catching since v1:
        // something watching the screen while something else drives it.
        if has(events, "screen_capture", now, fiveMinutes),
           has(events, "accessibility", now, fiveMinutes) {
            derived.append(correlation("observed_and_driven", "rat", 80, 70, now))
        }

        return derived
    }

    // MARK: - Predicates
    //
    // All of them are windowed against `now`. `fresh` is the single definition of what "recent"
    // means, so a rule cannot accidentally reason about evidence older than it intended.

    private static func has(_ events: [[String: Any]], _ category: String,
                            _ now: Double, _ window: Double) -> Bool {
        hasAny(events, [category], now, window)
    }

    private static func hasAny(_ events: [[String: Any]], _ categories: Set<String>,
                               _ now: Double, _ window: Double) -> Bool {
        events.contains { categories.contains($0["category"] as? String ?? "") && fresh($0, now, window) }
    }

    private static func distinct(_ events: [[String: Any]], _ categories: Set<String>,
                                 _ now: Double, _ window: Double) -> Int {
        Set(events.compactMap { event -> String? in
            let category = event["category"] as? String ?? ""
            return categories.contains(category) && fresh(event, now, window) ? category : nil
        }).count
    }

    /// True when something in `first` was seen, and `second` was seen at or after it, both inside
    /// the window. Latest-of-each on purpose: a stale earlier occurrence must not be able to make
    /// an unrelated later event look like a sequence.
    private static func ordered(_ events: [[String: Any]], first: Set<String>, second: String,
                                now: Double, window: Double) -> Bool {
        var latestFirst: Double = -1
        var latestSecond: Double = -1
        for event in events where fresh(event, now, window) {
            let at = (event["observed_at_ms"] as? NSNumber)?.doubleValue ?? 0
            let category = event["category"] as? String ?? ""
            if first.contains(category) { latestFirst = max(latestFirst, at) }
            if category == second { latestSecond = max(latestSecond, at) }
        }
        return latestFirst > 0 && latestSecond >= latestFirst && latestSecond - latestFirst <= window
    }

    /// Inside the window, and not stamped implausibly far ahead of it. A future timestamp is the
    /// cheapest way to make a signal look permanently fresh, so it is tolerated to the same five
    /// minutes of clock skew allowed everywhere else and ignored beyond that.
    private static func fresh(_ event: [String: Any], _ now: Double, _ window: Double) -> Bool {
        let at = (event["observed_at_ms"] as? NSNumber)?.doubleValue ?? 0
        return at > 0 && at <= now + 300_000 && now - at <= window
    }

    private static func correlation(_ rule: String, _ category: String,
                                    _ severity: Int, _ confidence: Int, _ now: Double) -> [String: Any] {
        SentinelThreatTelemetry.event(
            sensor: "behavior:" + rule, category: category, severity: severity,
            confidence: confidence, now: now,
            attributes: ["rule_id": rule, "model_version": rulesetVersion,
                         "source": "local_behavior_correlation"])
    }
}

// MARK: - A4 — bounded telemetry buffer
//
// Bounded on purpose. A device under attack produces more evidence, not less, so an unbounded
// buffer turns a security signal into a memory problem.
//
// Bounded by *identity*, not by arrival. `currentEvents()` re-reads live sensors on every tick, so
// a device that has been jailbroken for an hour reports the same jailbreak twelve times. Keyed by
// what the event is about — category, sensor, rule, matched indicator — the twelfth report
// replaces the first instead of joining it, and the queue holds twelve distinct problems rather
// than one problem twelve times. The key is deliberately the same tuple `localRiskScore` scores
// by, so the buffer and the scorer agree on what counts as one signal.
//
// Nothing is persisted. The queue lives in process memory and dies with the process, because
// security evidence written to disk is security evidence an attacker can read and edit.
public enum SentinelTelemetryBuffer {

    /// Past this, evidence has stopped describing the device. The scorer's own decay handles
    /// gradual ageing; this is the hard edge where an unsent event is dropped rather than
    /// delivered as though it were still true.
    private static let ttlMs: Double = 30 * 60 * 1000

    private static let capacity = 128
    private static let batchSize = 32

    private static let lock = NSLock()
    private static var pending: [String: [String: Any]] = [:]

    public static func offer(_ events: [[String: Any]]) {
        guard !events.isEmpty else { return }
        lock.lock()
        defer { lock.unlock() }
        pruneLocked()

        for event in events { pending[identity(event)] = event }

        // Oldest goes first. The newest evidence is the evidence that still describes the device.
        if pending.count > capacity {
            let stale = pending.sorted { observed($0.value) < observed($1.value) }
                               .prefix(pending.count - capacity)
            for (key, _) in stale { pending.removeValue(forKey: key) }
        }
    }

    /// Oldest first, so a queue that never fully drains still delivers in the order things
    /// happened rather than leaving the earliest evidence permanently at the back.
    public static func batch() -> [[String: Any]] {
        lock.lock()
        defer { lock.unlock() }
        pruneLocked()
        return Array(pending.values.sorted { observed($0) < observed($1) }.prefix(batchSize))
    }

    /// Removes exactly what the server accepted, matched by identity rather than by event id.
    ///
    /// By id would leak: a signal re-offered while the request was in flight lands under the same
    /// identity with a fresh `event_id`, so an id-matched ack would miss it and send it again. If
    /// the replacement was a newer observation of the same signal, dropping it costs nothing —
    /// the sensors still report it, so the next tick puts it straight back.
    public static func ack(_ sent: [[String: Any]]) {
        guard !sent.isEmpty else { return }
        lock.lock()
        for event in sent { pending.removeValue(forKey: identity(event)) }
        lock.unlock()
    }

    public static func clear() { lock.lock(); pending.removeAll(); lock.unlock() }

    /// Queue depth. Test and diagnostic use.
    public static var count: Int {
        lock.lock(); defer { lock.unlock() }
        pruneLocked()
        return pending.count
    }

    private static func pruneLocked() {
        let now = Date().timeIntervalSince1970 * 1000
        pending = pending.filter { now - observed($0.value) <= ttlMs }
    }

    private static func observed(_ event: [String: Any]) -> Double {
        (event["observed_at_ms"] as? NSNumber)?.doubleValue ?? Date().timeIntervalSince1970 * 1000
    }

    /// What makes two reports the same signal. Identical to the de-duplication key in
    /// `localRiskScore`, so an event that scores once is also queued once.
    private static func identity(_ event: [String: Any]) -> String {
        let attributes = event["attributes"] as? [String: Any]
        return [event["category"] as? String ?? "other",
                event["sensor"] as? String ?? "",
                attributes?["rule_id"] as? String ?? "",
                attributes?["indicator_sha256"] as? String ?? ""].joined(separator: "|")
    }
}

// MARK: - C1 — semantic transaction proof
//
// The point of this type is that the server never has to trust the client's description of what
// the user approved. The client sends the fields; the server recomputes the same hash from them
// and refuses if it differs. So a compromised process can change the amount, but it cannot change
// the amount *and* keep a decision that was issued for the original.
//
// `appendProof` preserves the original business JSON bytes exactly and appends three members at
// the end, so the relying party can strip them, hash what remains, and get back the same
// `payload_sha256` the decision was issued against.
public enum SentinelSensitiveTransaction {

    public struct Prepared {
        public let originalJSON: String
        public let payloadSHA256: String
        public let semanticSHA256: String
        public let transactionID: String
        public let transactionType: String
        public let sourceAccountID: String
        public let beneficiaryID: String
        public let beneficiaryBank: String
        public let merchantID: String
        public let amountMinor: Int64
        public let currency: String
    }

    public static func prepare(_ originalJSON: String) throws -> Prepared {
        guard let bytes = originalJSON.data(using: .utf8),
              let object = try JSONSerialization.jsonObject(with: bytes) as? [String: Any] else {
            throw error("transaction JSON object required")
        }
        // A body that already carries proof fields is a body somebody else has been shaping.
        if object.keys.contains(where: { $0.hasPrefix("_sentinel_") }) {
            throw error("reserved Sentinel proof field present")
        }
        let payload     = sha256Hex(bytes)
        let txid        = first(object, ["transaction_id", "trx_id", "reference_id", "reference", "ref_id"])
        let type        = firstDefault(object, ["transaction_type", "type", "operation_type"], "ppob_transaction")
        let source      = first(object, ["source_account_id", "from_account", "account_from", "source_account", "sourceAccount"])
        let beneficiary = first(object, ["beneficiary_id", "beneficiary_account", "destination_account", "to_account", "account_to", "msisdn"])
        let bank        = first(object, ["beneficiary_bank", "beneficiary_bank_code", "bank_code", "destination_bank"])
        let merchant    = first(object, ["merchant_id", "biller_id", "merchant", "biller"])
        let amount      = firstLong(object, ["amount_minor", "amount"], 0)
        let currency    = firstDefault(object, ["currency"], "IDR")

        let fields: [String: String] = [
            "amount_minor": String(amount), "beneficiary_bank": bank, "beneficiary_id": beneficiary,
            "currency": currency, "merchant_id": merchant, "payload_sha256": payload,
            "source_account_id": source, "transaction_id": txid, "transaction_type": type,
        ]
        return Prepared(originalJSON: originalJSON, payloadSHA256: payload,
                        semanticSHA256: sha256Hex(Data(canonicalPercent(fields).utf8)),
                        transactionID: txid, transactionType: type, sourceAccountID: source,
                        beneficiaryID: beneficiary, beneficiaryBank: bank, merchantID: merchant,
                        amountMinor: amount, currency: currency)
    }

    /// What the Secure Enclave approval key signs: the summary the user was shown, bound to this
    /// session and this challenge. Separate from the App Attest assertion on purpose — they answer
    /// different questions, this device and this transaction.
    public static func approvalCanonical(_ body: [String: Any]) -> Data {
        var fields: [String: String] = [
            "audit_chain_head":     string(body["audit_chain_head"]),
            "nonce_id":             string(body["nonce_id"]),
            "payload_sha256":       string(body["payload_sha256"]),
            "semantic_sha256":      string(body["semantic_sha256"]),
            "session_token_sha256": string(body["session_token_sha256"]),
            "timestamp_ms":         string(body["timestamp_ms"]),
        ]
        if body["sentinel_protocol"] != nil { fields["sentinel_protocol"] = string(body["sentinel_protocol"]) }
        return Data(("NEXILIS-IOS-SENSITIVE-V1\n" + canonicalPercent(fields)).utf8)
    }

    /// Recursive sorted compact JSON, byte-identical to `NXCanonicalJSONData` on the ObjC side and
    /// to the server's `canonicalize`. The assertion is worthless if the three disagree by a byte.
    public static func canonicalJSON(_ object: [String: Any]) throws -> Data {
        guard JSONSerialization.isValidJSONObject(object) else { throw error("invalid canonical JSON object") }
        var out = ""
        appendCanonical(object, &out)
        guard let d = out.data(using: .utf8) else { throw error("canonical UTF-8 failure") }
        return d
    }

    public static func appendProof(_ prepared: Prepared, token: String) throws -> String {
        guard token.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil else {
            throw error("decision token encoding invalid")
        }
        let trimmed = prepared.originalJSON.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.first == "{", trimmed.last == "}" else { throw error("transaction JSON object required") }
        return String(trimmed.dropLast())
            + ",\"_sentinel_decision_token\":\"\(token)\""
            + ",\"_sentinel_payload_sha256\":\"\(prepared.payloadSHA256)\""
            + ",\"_sentinel_semantic_sha256\":\"\(prepared.semanticSHA256)\"}"
    }

    public static func sha256Hex(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    public static func sha256Hex(_ text: String) -> String { sha256Hex(Data(text.utf8)) }

    private static func canonicalPercent(_ fields: [String: String]) -> String {
        fields.keys.sorted().map { "\($0)=\(percent(fields[$0] ?? ""))\n" }.joined()
    }

    private static func percent(_ s: String) -> String {
        var out = ""
        for b in s.utf8 {
            if (b >= 65 && b <= 90) || (b >= 97 && b <= 122) || (b >= 48 && b <= 57) ||
                b == 45 || b == 46 || b == 95 || b == 126 {
                out.append(Character(UnicodeScalar(b)))
            } else {
                out += String(format: "%%%02X", b)
            }
        }
        return out
    }

    private static func first(_ o: [String: Any], _ keys: [String]) -> String {
        for k in keys {
            guard let v = o[k], !(v is NSNull) else { continue }
            let s = string(v).trimmingCharacters(in: .whitespacesAndNewlines)
            if !s.isEmpty { return s }
        }
        return ""
    }
    private static func firstDefault(_ o: [String: Any], _ keys: [String], _ d: String) -> String {
        let v = first(o, keys); return v.isEmpty ? d : v
    }
    private static func firstLong(_ o: [String: Any], _ keys: [String], _ d: Int64) -> Int64 {
        for k in keys {
            guard let v = o[k], !(v is NSNull) else { continue }
            if let n = v as? NSNumber { return n.int64Value }
            if let n = Int64(string(v)) { return n }
        }
        return d
    }
    private static func string(_ value: Any?) -> String {
        guard let value else { return "" }
        if let s = value as? String { return s }
        if let n = value as? NSNumber { return n.stringValue }
        return String(describing: value)
    }
    private static func appendCanonical(_ value: Any, _ out: inout String) {
        if value is NSNull { out += "null"; return }
        if let s = value as? String { out += "\"\(escape(s))\""; return }
        if let n = value as? NSNumber {
            out += CFGetTypeID(n) == CFBooleanGetTypeID() ? (n.boolValue ? "true" : "false") : n.stringValue
            return
        }
        if let a = value as? [Any] {
            out += "["
            for i in a.indices { if i > 0 { out += "," }; appendCanonical(a[i], &out) }
            out += "]"; return
        }
        if let d = value as? [String: Any] {
            out += "{"
            let keys = d.keys.sorted()
            for i in keys.indices {
                if i > 0 { out += "," }
                out += "\"\(escape(keys[i]))\":"
                appendCanonical(d[keys[i]] ?? NSNull(), &out)
            }
            out += "}"; return
        }
        out += "null"
    }
    private static func escape(_ input: String) -> String {
        let ns = input as NSString
        var out = ""
        for i in 0..<ns.length {
            let c = ns.character(at: i)
            switch c {
            case 34: out += "\\\""
            case 92: out += "\\\\"
            case 8:  out += "\\b"
            case 12: out += "\\f"
            case 10: out += "\\n"
            case 13: out += "\\r"
            case 9:  out += "\\t"
            default: out += c < 0x20 ? String(format: "\\u%04x", c) : String(format: "%C", c)
            }
        }
        return out
    }
    private static func error(_ message: String) -> NSError {
        NSError(domain: "io.nexilis.zta.sensitive", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
