import Foundation
#if SWIFT_PACKAGE
import NexilisZTACore
#endif

public extension RILClient {
    init(configuration: RILConfiguration) {
        self.init(configuration: configuration, storage: RILKeychainStorage(scope: configuration.scope),
                  cryptography: RILSecureEnclaveCryptography(),
                  transport: RILPinnedTransport(origin: configuration.origin), authentication: RILZTAAuthentication())
    }
}

private struct RILZTAAuthentication: RILAuthentication {
    func credentials() throws -> RILCredentials {
        guard let token = APISZTA.currentAuthorizationToken, !token.isEmpty,
              AppAttestManager.shared().isRegistered,
              let id = AppAttestManager.shared().keyId, !id.isEmpty else { throw RILError.sessionUnavailable }
        return RILCredentials(token: token, appAttestKeyID: id)
    }
    func assertion(for clientData: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            // AppAttestManager hashes clientData once; do not prehash here.
            AppAttestManager.shared().generateAssertion(forClientData: clientData) { bytes, error in
                if let error = error { continuation.resume(throwing: error) }
                else if let bytes = bytes { continuation.resume(returning: bytes) }
                else { continuation.resume(throwing: RILError.invalidResponse) }
            }
        }
    }
}

public extension RILPilotTransport {
    @MainActor convenience init(session: RILSession, routes: RILPilotRoutes) {
        let transport = RILPinnedTransport(origin: routes.origin)
        self.init(routes: routes, sign: { try await session.sign($0) },
                  transmit: { request in
            guard let token = APISZTA.currentAuthorizationToken,
                  token == request.value(forHTTPHeaderField: "X-Nexilis-ZTA-Session") else {
                throw RILError.sessionUnavailable
            }
            let result = try await transport.send(request)
            if APISZTA.currentAuthorizationToken == token,
               !(200...299).contains(result.1.statusCode),
               let body = try? JSONSerialization.jsonObject(with: result.0) as? [String: Any],
               let code = body["error"] as? String,
               ["RIL_REQUIRED", "RIL_KEY_UNAVAILABLE", "RIL_BINDING_MISMATCH", "RIL_PROFILE_UNSUPPORTED",
                "RIL_INVALID_SIGNATURE", "RIL_DIGEST_MISMATCH", "RIL_EXPIRED", "RIL_CLOCK_SKEW"].contains(code) {
                await session.rejectRequest(status: result.1.statusCode, code: code)
            }
            return result
        })
    }

    convenience init(client: RILClient, routes: RILPilotRoutes) {
        let transport = RILPinnedTransport(origin: routes.origin)
        self.init(routes: routes, sign: { try await client.sign($0).request },
                  transmit: { try await transport.send($0) })
    }
}

private final class RILPinnedTransport: RILEnrollmentTransport {
    let origin: String
    let session: URLSession
    init(origin: String) {
        self.origin = origin
        let config = URLSessionConfiguration.ephemeral
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.timeoutIntervalForRequest = 15
        config.timeoutIntervalForResource = 30
        config.waitsForConnectivity = false
        config.httpShouldSetCookies = false
        config.httpCookieStorage = nil
        config.urlCredentialStorage = nil
        config.urlCache = nil
        // Barrier #1: RIL runs after authorization, but it is an SDK session and stands behind
        // the same latch as the rest.
        config.protocolClasses = [SentinelOfflineGateURLProtocol.self] + (config.protocolClasses ?? [])
        session = URLSession(configuration: config, delegate: RILPinnedDelegate(), delegateQueue: nil)
    }
    deinit { session.invalidateAndCancel() }
    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        guard let url = request.url, try RILCore.target(url).origin == origin,
              let host = url.host, RASPGuard.shared().isPinnedHost(host) else { throw RILError.invalidConfiguration }
        let (stream, response) = try await session.bytes(for: request)
        guard let response = response as? HTTPURLResponse else { throw RILError.invalidResponse }
        guard !(300...399).contains(response.statusCode) else {
            stream.task.cancel(); throw RILError.redirectDenied
        }
        guard response.expectedContentLength <= 262144 else {
            stream.task.cancel(); throw RILError.responseTooLarge
        }
        var bytes = Data()
        do {
            for try await byte in stream {
                guard bytes.count < 262144 else { throw RILError.responseTooLarge }
                bytes.append(byte)
            }
        } catch { stream.task.cancel(); throw error }
        return (bytes, response)
    }
}

private final class RILPinnedDelegate: NSObject, URLSessionTaskDelegate {
    private let trust = PinnedURLSessionDelegate()
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        trust.urlSession(session, didReceive: challenge, completionHandler: completionHandler)
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}
