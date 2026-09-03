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
    public var isSupported: Bool {
        if #available(iOS 16.0, *) {
            return DCAppAttestService.shared.isSupported
        }
        return false
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
                NSLocalizedFailureReasonErrorKey: "Butuh iPhone dengan chip A12 atau lebih baru dan iOS 16+."
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

    // MARK: - Assert (subsequent launches)
    public func performAssertion(completion: @escaping (Bool, Error?) -> Void) {
        guard isSupported else {
            completion(false, unsupportedError())
            return
        }
        let state = stateGet()
        guard state == NX_STATE_APPATTEST_DEVICE_REGISTRATION || state == NX_STATE_APPATTEST_ENDPOINT_CONFIG else {
            completion(false, flowStateError("assertion"))
            return
        }

        let manager = AppAttestManager.shared()

        // Generate clientData untuk assertion
        let clientData = "nexilis-assertion-\(Date().timeIntervalSince1970)"
            .data(using: .utf8) ?? Data()

        manager.generateAssertion(forClientData: clientData) { assertion, error in
            DispatchQueue.main.async {
                if assertion != nil {
                    NXLogger.appAttest.publicInfo("[AppAttest] ✅ Assertion berhasil")
                    stateSet(NX_STATE_APPATTEST_ASSERTION) // -> 22
                    completion(true, nil)
                } else {
                    NXLogger.appAttest.publicError("[AppAttest] ❌ Assertion gagal: \(error?.localizedDescription ?? "unknown")")
                    completion(false, error)
                }
            }
        }
    }

    // MARK: - Request key delivery
    public func requestKeyDelivery(completion: @escaping (Data?, Error?) -> Void) {
        guard isSupported else {
            completion(nil, unsupportedError())
            return
        }
        guard stateGet() == NX_STATE_APPATTEST_ASSERTION else {
            completion(nil, flowStateError("pengiriman kunci"))
            return
        }

        let manager = AppAttestManager.shared()

        // Device posture dari RASP
        let posture: [String: Any] = [
            "threat_mask":  Int(RASPGuard.shared().lastThreatMask),
            "rasp_clean":   RASPGuard.shared().deviceClean as Bool,
            "os_version":   UIDevice.current.systemVersion,
            "device_model": UIDevice.current.model
        ]

        manager.requestKeyDelivery(withPosture: posture) { decryptionKey, error in
            DispatchQueue.main.async {
                if let key = decryptionKey {
                    NXLogger.appAttest.publicInfo("[AppAttest] ✅ Key delivered (\(key.count) bytes)")
                    stateSet(NX_STATE_APPATTEST_KEY_DELIVERY)
                    completion(key, nil)
                } else {
                    NXLogger.appAttest.publicError("[AppAttest] ❌ Key delivery gagal: \(error?.localizedDescription ?? "unknown")")
                    completion(nil, error)
                }
            }
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
