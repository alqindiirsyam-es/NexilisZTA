//
//  ProtectedData.swift
//  Nexilis iOS ZTA — data the app cannot read by itself: APISZTA.withProtectedAsset
//
//  The iOS counterpart of the Android SDK's protected payload. Android can keep the app's own
//  code encrypted and load it once the chain has passed; iOS cannot execute decrypted code, so
//  what is protected here is data - configuration, endpoints, third-party keys or certificates,
//  fraud rules, models, licensed content - sealed at build time into `<name>.spa` files with the
//  per-app key the ZTA service holds (tools/build_ios_protected_asset.py).
//
//  Every access follows the Android disclosure pattern: a fresh nonce-bound App Attest assertion
//  and posture to /zta/key, the delivered key used for this one decryption and zeroed, the
//  plaintext handed to `body` and zeroed when it returns. Nothing is cached - not the key, not the
//  bytes - so the service decides on every read, and a revoked or tampered install stops getting
//  the key at once.
//
//      try await APISZTA.withProtectedAsset(named: "payment-config") { data in
//          try JSONDecoder().decode(PaymentConfig.self, from: data)
//      }
//
//  Modes 1 and 2 also require the session to be authorized (a live ZTA token); mode 3 requires a
//  registered install. The Barrier #2 activation asset (SentinelProtectedAssets.spa) is separate
//  and not readable through this API.
//

import Foundation
#if SWIFT_PACKAGE
import NexilisZTACore
#endif

public extension APISZTA {

    /// Opens the sealed data asset `<name>.spa` for the length of `body`.
    ///
    /// - Parameters:
    ///   - name: the asset's name in the bundle, without `.spa`.
    ///   - body: runs with the plaintext; whatever it returns is the result. Do not keep the
    ///     `Data` it is given - it is zeroed as soon as `body` returns.
    ///   - completion: on the main queue.
    static func withProtectedAsset<T>(named name: String,
                                      _ body: @escaping (Data) throws -> T,
                                      completion: @escaping (Result<T, Error>) -> Void) {
        let done: (Result<T, Error>) -> Void = { result in
            if Thread.isMainThread { completion(result) } else { DispatchQueue.main.async { completion(result) } }
        }
        if NXSecurityPolicy.requiresServerChain(), !hasValidAuthorization {
            done(.failure(protectedDataError(11, "Protected data needs an authorized session at app mode 1 and 2.")))
            return
        }
        // Fail on a missing or malformed asset before spending a key delivery on it.
        do { _ = try ProtectedAssetStore.protectedAssetURL(named: name) } catch { done(.failure(error)); return }

        AppAttestService.shared.requestKeyDelivery(forAccess: true) { key, error in
            guard var delivered = key else {
                NXLogger.appAttest.publicError("[ProtectedData] \(name): kunci tidak dikirim - \(error?.localizedDescription ?? "?")")
                done(.failure(error ?? protectedDataError(12, "The ZTA service delivered no key.")))
                return
            }
            defer { delivered.resetBytes(in: 0 ..< delivered.count) }
            do {
                var plaintext = try ProtectedAssetStore.decrypt(deliveredKey: delivered, named: name)
                defer { plaintext.resetBytes(in: 0 ..< plaintext.count) }
                let count = plaintext.count
                let value = try body(plaintext)
                NXLogger.appAttest.publicInfo("[ProtectedData] \(name) dibuka (\(count) byte), kunci dan plaintext dinolkan")
                SecurityAuditChain.append(event: "protected_data_opened", detail: ["name": name, "bytes": count])
                done(.success(value))
            } catch {
                NXLogger.appAttest.publicError("[ProtectedData] \(name): \(error.localizedDescription)")
                done(.failure(error))
            }
        }
    }

    /// The async form of `withProtectedAsset(named:_:completion:)`.
    static func withProtectedAsset<T>(named name: String,
                                      _ body: @escaping (Data) throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            withProtectedAsset(named: name, body) { continuation.resume(with: $0) }
        }
    }

    private static func protectedDataError(_ code: Int, _ message: String) -> NSError {
        NSError(domain: "io.nexilis.zta.protectedasset", code: code, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
