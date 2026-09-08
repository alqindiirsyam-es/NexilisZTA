//
//  AppAttestService.swift
//  SampleAppShield
//
//  Created by Qindi on 02/04/26.
//

// AppAttestService.swift
import Foundation
import DeviceCheck
import UIKit
import OSLog

#if SWIFT_PACKAGE
// CocoaPods builds Swift and Objective-C as one mixed-language target, so these
// types are already in scope. SwiftPM has no mixed target, so the Objective-C and
// C half is its own module and has to be imported.
import NexilisZTACore
#endif
public class AppAttestService {

    public static let shared = AppAttestService()
    private init() {}

    // MARK: - Check support
    /// Whether this device can attest *and* be accepted by the service.
    ///
    /// Both halves matter. App Attest exists from iOS 14, but the ZTA service refuses anything
    /// below its own `minIosMajor` - so on an iOS 15 device the hardware answers yes, the
    /// registration goes out, and the server rejects it. That reads as a failed launch rather
    /// than an unsupported device, and at app mode 3 it stopped an app that used to run.
    public var isSupported: Bool {
        AppAttestManager.shared().isSupported
    }

    // MARK: - Errors

    /// A step that cannot run reports why rather than failing silently. A bare `false, nil` left
    /// the screen with nothing to say but "an unknown error occurred", and support with no code
    /// to work from - which is exactly what a reader saw after the app had been closed for days.
    private func flowStateError(_ stage: String) -> NSError {
        return NSError(
            domain: NXAppAttestErrorDomain,
            code: NXAppAttestError.flowStateInvalid.rawValue,
            userInfo: [
                NSLocalizedDescriptionKey: "Verifikasi keamanan belum siap untuk tahap \(stage).",
                NSLocalizedFailureReasonErrorKey: "Status alur \(stateGet()) tidak sesuai untuk \(stage)."
            ]
        )
    }

    private func unsupportedError() -> NSError {
        return NSError(
            domain: NXAppAttestErrorDomain,
            code: NXAppAttestError.notSupported.rawValue,
            userInfo: [
                NSLocalizedDescriptionKey: "Perangkat ini tidak mendukung App Attest.",
                NSLocalizedFailureReasonErrorKey: "Butuh iPhone dengan chip A12 atau lebih baru dan iOS \(AppAttestManager.shared().minimumOSMajor)+."
            ]
        )
    }

    // MARK: - Configure endpoints
    public func configure() {
        // The RASP chain (states 1-15) runs once per process and must have completed; the attest
        // sub-chain after it has to be restartable. It was pinned to `== PERIODIC_MONITORING`, so
        // a second attempt - the backoff, or the reader pressing "Coba Lagi" - found the state
        // already past 15, returned without arming anything, and then every step below rejected
        // its own guard. That is why a failed verification stayed failed until the app was killed,
        // however good the connection had become.
        guard stateGet() >= NX_STATE_PERIODIC_MONITORING else {
            return
        }
        let manager = AppAttestManager.shared()

        // The endpoints come from the configuration rather than straight from the compiled-in
        // constants, so a host can point the layer at a service of its own. With no configure()
        // call the configuration holds those same constants.
        let config = APISZTA.configuration
        manager.challengeEndpoint    = config.challengeEndpoint
        manager.attestEndpoint       = config.attestEndpoint
        manager.registerEndpoint     = config.registerEndpoint
        manager.keyDeliveryEndpoint  = config.keyDeliveryEndpoint
        manager.revokeEndpoint       = config.revokeEndpoint
        manager.statusVerifyEndpoint = config.statusVerifyEndpoint
        stateSet(NX_STATE_APPATTEST_ENDPOINT_CONFIG) // -> 16
    }

    // MARK: - Register device (first launch)
    public func registerDevice(completion: @escaping (Bool, Error?) -> Void) {
        guard isSupported else {
            print("[AppAttest] Device tidak support App Attest (butuh A12+)")
            completion(false, unsupportedError())
            return
        }
        guard stateGet() == NX_STATE_APPATTEST_ENDPOINT_CONFIG else {
            completion(false, flowStateError("registrasi perangkat"))
            return
        }
        let manager = AppAttestManager.shared()
//        manager.resetURLSession()
        manager.registerDevice { success, error in
            DispatchQueue.main.async {
                if success {
                    NXLogger.appAttest.publicInfo("[AppAttest] ✅ Registration berhasil")
                    stateSet(NX_STATE_APPATTEST_DEVICE_REGISTRATION) // -> 21
                } else if let nsError = error as? NSError {
                    NXLogger.appAttest.publicError("❌ domain  : \(nsError.domain)")
                    NXLogger.appAttest.publicError("❌ code    : \(nsError.code)")
                    NXLogger.appAttest.publicError("❌ message : \(nsError.localizedDescription)")
                    NXLogger.appAttest.publicError("❌ userInfo: \(nsError.userInfo)")

                    // Cek underlying error
                    if let underlying = nsError.userInfo[NSUnderlyingErrorKey] as? NSError {
                        NXLogger.appAttest.publicError("❌ underlying domain: \(underlying.domain)")
                        NXLogger.appAttest.publicError("❌ underlying code  : \(underlying.code)")
                        NXLogger.appAttest.publicError("❌ underlying msg   : \(underlying.localizedDescription)")
                    }
                }
                completion(success, error)
            }
        }
    }

    // The previous local-only `performAssertion()` API was removed: generating an assertion
    // without server adjudication is not a security state. The nonce-bound assertion inside
    // requestKeyDelivery() is the authoritative server-verified assertion.

    // MARK: - Request key delivery
    public func requestKeyDelivery(completion: @escaping (Data?, Error?) -> Void) {
        guard isSupported else {
            completion(nil, unsupportedError())
            return
        }
        let currentState = stateGet()
        guard currentState == NX_STATE_APPATTEST_DEVICE_REGISTRATION ||
              currentState == NX_STATE_APPATTEST_ENDPOINT_CONFIG else {
            completion(nil, flowStateError("pengiriman kunci/server assertion"))
            return
        }

        let manager = AppAttestManager.shared()

        // Device posture dari RASP
        let posture: [String: Any] = [
            "threat_mask":  Int(RASPGuard.shared().lastThreatMask),
            "rasp_clean":   RASPGuard.shared().deviceClean as Bool,
            "os_version":   UIDevice.current.systemVersion,
            "device_model": UIDevice.current.model,
            "audit_head": SecurityAuditChain.headHash(),
            "audit_chain_valid": SecurityAuditChain.verifyChain()
        ]

        manager.requestKeyDelivery(withPosture: posture) { decryptionKey, error in
            DispatchQueue.main.async {
                if let key = decryptionKey {
                    NXLogger.appAttest.publicInfo("[AppAttest] ✅ Server verified assertion and delivered key (\(key.count) bytes)")
                    stateSet(NX_STATE_APPATTEST_ASSERTION)
                    stateSet(NX_STATE_APPATTEST_KEY_DELIVERY)
                    completion(key, nil)
                } else {
                    NXLogger.appAttest.publicError("[AppAttest] ❌ Key delivery gagal: \(error?.localizedDescription ?? "unknown")")
                    completion(nil, error)
                }
            }
        }
    }

    // MARK: - Protected asset

    /// Opens the bundled sealed asset, if this build ships one.
    ///
    /// This is the whole point of key delivery: the key never lives in the app, so the asset is
    /// readable only by an install that has just proved through App Attest that it is genuine,
    /// unmodified, and running on real Apple hardware. Pulling the IPA gets an attacker the
    /// ciphertext and nothing else.
    ///
    /// The delivered key is zeroed as soon as the asset is open, so it exists for the length of
    /// one decryption rather than the length of the session.
    ///
    /// - Note: A build with no sealed asset fails with `ProtectedAssetStore.Failure.missing`.
    ///   Check `ProtectedAssetStore.isAvailable()` first where that is a legitimate configuration
    ///   rather than an error.
    public func requestProtectedAsset(completion: @escaping (Data?, Error?) -> Void) {
        requestKeyDelivery { key, error in
            guard var delivered = key else {
                completion(nil, error)
                return
            }
            defer { delivered.resetBytes(in: 0 ..< delivered.count) }
            do { completion(try ProtectedAssetStore.decrypt(deliveredKey: delivered), nil) }
            catch { completion(nil, error) }
        }
    }

    /// The scoped form, and the one production call sites should use: the plaintext is handed to
    /// `body` and zeroed on the way out, so no caller ends up deciding where to keep it.
    public func withProtectedAsset(_ body: @escaping (Data) throws -> Void,
                                   failure: @escaping (Error) -> Void) {
        requestKeyDelivery { key, error in
            guard var delivered = key else {
                failure(error ?? NSError(
                    domain: "io.nexilis.zta.protectedasset", code: 0,
                    userInfo: [NSLocalizedDescriptionKey: "key delivery returned no key"]))
                return
            }
            defer { delivered.resetBytes(in: 0 ..< delivered.count) }
            do { try ProtectedAssetStore.withDecryptedAsset(deliveredKey: delivered, body) }
            catch { failure(error) }
        }
    }

    // MARK: - Check registration status
    public var isRegistered: Bool {
        return AppAttestManager.shared().isRegistered
    }

    public var keyId: String? {
        return AppAttestManager.shared().keyId
    }
}
