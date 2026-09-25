//
//  ProtectedRuntimeVerifier.swift
//  Nexilis iOS ZTA — Barrier #2: the independent re-verification after protected decryption
//
//  Ported from Nexilis Sentinel v3.0.1 RC5 (SentinelProtectedRuntimeVerifier) onto this
//  codebase's app modes. RC5's second barrier: after institution authentication, server-authorized
//  key delivery and authenticated decryption of the protected asset, a second verifier repeats the
//  high-value local checks before protected readiness. It deliberately does not trust the result
//  of Barrier #1 - it re-runs the native set and adds probes of its own.
//
//  iOS does not let an App Store application execute freshly decrypted native code, so unlike the
//  Android verifier this one stays code-signed application code; what the encrypted asset gates
//  is its *activation*, cryptographically: no delivered key, no decrypted bytes, no proof.
//
//  The RC5 moving-target part: a per-device activation lineage is derived from the App Attest key
//  identity and the authenticated asset digest, the independent Swift probes run in a fresh random
//  order on every activation, and the lineage is bound into the proof and the audit record. The
//  probes' semantics never change - only the dynamic trace an analyst would record does, and it
//  differs per install and per activation.
//
//  Departures from RC5, deliberately, and the same two as Barrier #1: Debug builds are verified
//  rather than refused (this repository supports Debug runs of every mode), and VPN state is read
//  from NetworkPosture's scoped-proxy map with the host's trusted prefixes honoured, rather than
//  from getifaddrs, which on iOS flags every device.
//

import Foundation
import CryptoKit
import UIKit
import CFNetwork
import MachO
#if SWIFT_PACKAGE
import NexilisZTACore
#endif

public enum SentinelProtectedRuntimeVerifier {

    public static let errorDomain = "io.nexilis.zta.protected"

    private static let lock = NSLock()
    private static var verified = false
    private static var proofDigest = ""
    private static var lineageDigest = ""

    /// A proof exists for the current activation. Cleared at the start of every verification
    /// attempt and on revocation; `finish()` refuses without it where the mode requires it.
    public static var isVerified: Bool {
        lock.lock(); defer { lock.unlock() }
        return verified && !proofDigest.isEmpty
    }

    /// The proof of the current activation - what a later High Assurance posture will carry.
    public static var currentProof: String? {
        lock.lock(); defer { lock.unlock() }
        return verified ? proofDigest : nil
    }

    /// The activation lineage - non-secret, per device and per asset, for forensic attribution.
    public static var currentLineage: String? {
        lock.lock(); defer { lock.unlock() }
        return verified ? lineageDigest : nil
    }

    public static func invalidate() {
        lock.lock(); verified = false; proofDigest = ""; lineageDigest = ""; lock.unlock()
    }

    /// Whether this mode requires the barrier at all, given what the build ships.
    ///
    ///   - .hsa: required, and a build without a protected asset is a misconfigured build.
    ///   - .middle: required whenever the build ships an asset; a build without one is allowed.
    ///   - .regular: run when an asset is there, result recorded, never blocking.
    public static var isRequired: Bool {
        if NXSecurityPolicy.isHSA() { return true }
        return NXSecurityPolicy.requiresServerChain() && ProtectedAssetStore.isAvailable()
    }

    /// The chain's entry point, from `deliverKey` with the key the service just delivered.
    ///
    /// Opens the asset, runs the verification with the plaintext scoped to this call, and either
    /// records a proof or throws. A mode that does not require the barrier turns a failure into an
    /// audit entry and returns; at .hsa a missing asset is itself the failure.
    public static func activate(deliveredKey: Data, configuration: NexilisZTAConfiguration) throws {
        invalidate()
        let required = isRequired
        guard ProtectedAssetStore.isAvailable() else {
            if NXSecurityPolicy.isHSA() {
                throw failure(20, "Mode 1 requires a protected asset in the bundle and none was found.")
            }
            SecurityAuditChain.append(event: "protected_reverify_skipped", detail: ["reason": "no_asset"])
            return
        }
        do {
            try ProtectedAssetStore.withDecryptedAsset(deliveredKey: deliveredKey) { plaintext in
                try verify(decryptedProtectedAsset: plaintext, configuration: configuration)
            }
        } catch {
            guard required else {
                SecurityAuditChain.append(event: "protected_reverify_recorded",
                                          detail: ["error": (error as NSError).code,
                                                   "message": error.localizedDescription])
                NXLogger.appAttest.publicInfo("[Barrier2] Temuan dicatat, mode 3 tidak memblokir: \(error.localizedDescription)")
                return
            }
            throw error
        }
    }

    /// The verification itself, over the decrypted bytes. Public so a host that drives the steps
    /// by hand, or a test, can run it against a plaintext of its own.
    @discardableResult
    public static func verify(decryptedProtectedAsset: Data,
                              configuration: NexilisZTAConfiguration) throws -> String {
        invalidate()
        guard !decryptedProtectedAsset.isEmpty else {
            throw failure(1, "Protected asset decrypted to an empty payload.")
        }

        // Per-device activation lineage: the App Attest key this install registered with, and the
        // asset bytes that just authenticated. Non-secret; it is what lets a leaked protected
        // artifact be attributed, and what makes every activation's trace its own.
        guard let keyId = AppAttestService.shared.keyId, !keyId.isEmpty else {
            throw failure(2, "App Attest lineage unavailable: no registered key.")
        }
        let assetDigest = Data(SHA256.hash(data: decryptedProtectedAsset))
        var lineageMaterial = Data(keyId.utf8)
        lineageMaterial.append(Data("|".utf8))
        lineageMaterial.append(assetDigest)
        let lineage = hex(SHA256.hash(data: lineageMaterial))

        // The native detector set again, after protected decryption - not the launch verdict and
        // not Barrier #1's result, the device as it is at this instant.
        let threats = RASPGuard.shared().runChecksNow()
        guard threats == RASP_THREAT_NONE, RASPGuard.shared().deviceClean else {
            throw failure(Int(threats), "Protected-stage native RASP re-verification failed (mask 0x\(String(threats, radix: 16))).")
        }
        guard RASPGuard.shared().verifyCodeSignatureIntegrity() else {
            throw failure(3, "Protected-stage release identity verification failed.")
        }

        // Independent Swift probes, implemented here rather than delegated to the native engine,
        // in a fresh random order per activation. Same semantics every time; a different trace.
        var checks: [() throws -> Void] = [
            { if jailbreakFilesystemIndicatorsPresent() { throw failure(4, "Protected-stage jailbreak/root filesystem indicators detected.") } },
            { if suspiciousLoadedImagesPresent() { throw failure(5, "Protected-stage instrumentation/injection image detected.") } },
            { if UIScreen.main.isCaptured || UIScreen.screens.count > 1 { throw failure(6, "Protected-stage screen recording/mirroring/secondary display detected.") } },
            { if proxyIsConfigured() { throw failure(7, "Protected-stage proxy/PAC/SOCKS configuration detected.") } },
            { if untrustedVPNActive() { throw failure(8, "Protected-stage VPN/tunnel interface detected.") } },
            { if !AppAttestService.shared.isSupported { throw failure(9, "Protected-stage App Attest/Secure Enclave capability unavailable.") } },
            { if !SecurityAuditChain.verifyChain() { throw failure(10, "Protected-stage local audit chain invalid.") } },
        ]
        checks.shuffle()
        for check in checks { try check() }

        // The proof binds the decrypted bytes, the application identity, the OS, the native state
        // and the lineage. It is what protected readiness rests on.
        var material = Data()
        material.append(assetDigest)
        material.append(Data((Bundle.main.bundleIdentifier ?? "").utf8))
        material.append(Data(configuration.expectedApplicationID.utf8))
        material.append(Data(UIDevice.current.systemVersion.utf8))
        material.append(Data(String(threats).utf8))
        material.append(Data(lineage.utf8))
        let proof = hex(SHA256.hash(data: material))
        guard proof.count == 64 else { throw failure(11, "Protected-stage proof generation failed.") }

        lock.lock(); verified = true; proofDigest = proof; lineageDigest = lineage; lock.unlock()
        SecurityAuditChain.append(event: "protected_runtime_reverify_passed",
                                  detail: ["proof_sha256": proof,
                                           "activation_lineage_sha256": lineage,
                                           "threat_mask": Int(threats)])
        return proof
    }

    // MARK: - Independent probes

    private static func jailbreakFilesystemIndicatorsPresent() -> Bool {
        let paths = [
            "/Applications/Cydia.app", "/Applications/Sileo.app", "/Applications/Zebra.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib", "/usr/lib/libhooker.dylib",
            "/usr/lib/libsubstitute.dylib", "/usr/lib/ellekit", "/bin/bash", "/usr/sbin/sshd",
            "/etc/apt", "/private/var/lib/apt", "/var/jb", "/private/preboot/jb",
        ]
        return paths.contains { FileManager.default.fileExists(atPath: $0) }
    }

    private static func suspiciousLoadedImagesPresent() -> Bool {
        let needles = ["frida", "gadget", "substrate", "substitute", "libhooker", "ellekit", "cycript", "flexloader"]
        let count = _dyld_image_count()
        for index in 0 ..< count {
            guard let cName = _dyld_get_image_name(index) else { continue }
            let name = String(cString: cName).lowercased()
            if needles.contains(where: { name.contains($0) }) { return true }
        }
        return false
    }

    private static func proxyIsConfigured() -> Bool {
        guard let settings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] else {
            return true
        }
        let keys = ["HTTPEnable", "HTTPSEnable", "SOCKSEnable", "ProxyAutoConfigEnable"]
        return keys.contains { key in (settings[key] as? NSNumber)?.boolValue == true }
    }

    private static func untrustedVPNActive() -> Bool {
        let posture = NetworkPosture.currentPosture()
        return (posture["vpn_risky"] as? NSNumber)?.boolValue ?? false
    }

    private static func hex<D: Sequence>(_ digest: D) -> String where D.Element == UInt8 {
        digest.map { String(format: "%02x", $0) }.joined()
    }

    private static func failure(_ code: Int, _ message: String) -> NSError {
        NSError(domain: errorDomain, code: code, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
