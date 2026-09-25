//
//  InstallToken.swift
//  Nexilis iOS ZTA — the attested install, shown to an institution backend before key delivery
//
//  Pre-decrypt sign-in (NexilisLite's bootstrap Login/TFA) talks to the institution backend over
//  HTTPS - CPaaS /idp/v1/authn/* - between App Attest registration and /zta/key. That backend has
//  to know the request comes from an attested install of this app; on Android it is shown the
//  install_token the ZTA server issues at /register. This is the iOS counterpart: a short-lived
//  RS256 token from POST /zta/install-token, obtained with a fresh App Attest assertion over a
//  one-time challenge, in Android's claim shape (type "install", zta_install_id = the App Attest
//  key id, zta_device_id, zta_reg_pub_sha256) and checkable against /zta/.well-known/jwks.json.
//
//  zta_install_id is also the binding_id the institution's assertion must carry for
//  /zta/bootstrap/auth - the value the backend reads from this token, not from the app.
//

import Foundation
#if SWIFT_PACKAGE
import NexilisZTACore
#endif

public extension APISZTA {

    /// A live install token for the institution backend, reused until a minute before it runs out.
    /// Needs a registered App Attest key (the chain has attested) and an open Barrier #1.
    static func requestInstallToken() async throws -> String {
        try await InstallTokenClient.shared.token()
    }

    /// Completion form of `requestInstallToken()`, delivered on the main queue.
    static func requestInstallToken(completion: @escaping (Result<String, Error>) -> Void) {
        Task {
            let result: Result<String, Error>
            do { result = .success(try await requestInstallToken()) } catch { result = .failure(error) }
            DispatchQueue.main.async { completion(result) }
        }
    }

    /// The App Attest key id of this install - `binding_id` in the institution's assertion.
    static var installBindingID: String? { AppAttestManager.shared().keyId }
}

public let NXInstallTokenErrorDomain = "io.nexilis.zta.installtoken"

private actor InstallTokenClient {
    static let shared = InstallTokenClient()
    private var cached: (token: String, expiresAt: Date, keyID: String)?

    nonisolated private func fail(_ code: Int, _ reason: String) -> NSError {
        NSError(domain: NXInstallTokenErrorDomain, code: code, userInfo: [NSLocalizedDescriptionKey: reason])
    }

    func token() async throws -> String {
        let manager = AppAttestManager.shared()
        guard manager.isRegistered, let keyID = manager.keyId, !keyID.isEmpty else {
            throw fail(1, "App Attest registration is required before an install token.")
        }
        if let cached, cached.keyID == keyID, cached.expiresAt.timeIntervalSinceNow > 60 { return cached.token }
        try SentinelOfflinePreflight.requireNetworkAllowed()
        var base = APISZTA.configuration.baseURL
        while base.hasSuffix("/") { base.removeLast() }
        guard let challengeURL = URL(string: base + "/zta/challenge?purpose=install_token"),
              let tokenURL = URL(string: base + "/zta/install-token") else {
            throw fail(2, "Invalid ZTA base URL.")
        }

        // One-time challenge for this purpose only.
        let (challengeData, challengeResponse) = try await Self.session.data(for: URLRequest(url: challengeURL, timeoutInterval: 15))
        guard (challengeResponse as? HTTPURLResponse)?.statusCode == 200,
              let challenge = try JSONSerialization.jsonObject(with: challengeData) as? [String: Any],
              let nonce = challenge["nonce"] as? String, let nonceID = challenge["nonce_id"] as? String else {
            throw fail(3, "Install token challenge refused.")
        }

        // The assertion covers the body the server canonicalizes: every field but `assertion`.
        let timestamp = Int64(Date().timeIntervalSince1970 * 1000)
        let fields = ["key_id": keyID, "nonce_id": nonceID, "challenge": nonce, "platform": "ios"]
        let clientData = RILCanonicalJSON.encode(fields, timestamp: timestamp)
        let assertion: Data = try await withCheckedThrowingContinuation { continuation in
            AppAttestManager.shared().generateAssertion(forClientData: clientData) { bytes, error in
                if let bytes { continuation.resume(returning: bytes) }
                else { continuation.resume(throwing: error ?? self.fail(4, "App Attest assertion unavailable.")) }
            }
        }
        var body: [String: Any] = fields
        body["timestamp_ms"] = timestamp
        body["assertion"] = assertion.base64EncodedString()
        var request = URLRequest(url: tokenURL, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 15)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await Self.session.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
        guard status == 200, let token = json["install_token"] as? String, !token.isEmpty,
              let expires = (json["expires_at_ms"] as? NSNumber)?.doubleValue else {
            throw fail(5, "Install token refused: HTTP \(status) \(json["error"] as? String ?? "")")
        }
        let expiresAt = Date(timeIntervalSince1970: expires / 1000)
        cached = (token, expiresAt, keyID)
        NXLogger.appAttest.publicInfo("[InstallToken] token instalasi diterbitkan (berlaku sampai \(Int(expiresAt.timeIntervalSinceNow)) s)")
        return token
    }

    /// Pinned, uncached, behind Barrier #1 - like every other ZTA session.
    private static let session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.protocolClasses = [SentinelOfflineGateURLProtocol.self]
        return URLSession(configuration: configuration, delegate: PinnedURLSessionDelegate(), delegateQueue: nil)
    }()
}
