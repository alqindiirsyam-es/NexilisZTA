import Foundation

public struct RILConfiguration {
    public let origin: String
    public let appID: String
    public let bundleID: String
    public let tenantID: String
    public let environment: String
    public let challengeURL: URL
    public let enrollmentURL: URL
    public let policy: RILPolicy
    /// Limits for requests signed for a relying backend (RILProtection) - larger bodies than the
    /// ZTA pilot routes accept, still bounded: a body is hashed in memory before it is sent.
    public let relyingPolicy: RILPolicy
    var scope: String { [origin, appID, tenantID, environment].map(RILCanonicalJSON.quote).joined(separator: "|") }

    public init(origin: String, appID: String, bundleID: String, tenantID: String = "",
                environment: String, challengeURL: URL, enrollmentURL: URL,
                policy: RILPolicy? = nil, relyingPolicy: RILPolicy? = nil) throws {
        guard let url = URL(string: origin), try RILCore.target(url).origin == origin,
              try RILCore.target(challengeURL).origin == origin,
              try RILCore.target(enrollmentURL).origin == origin,
              !appID.isEmpty, !bundleID.isEmpty, ["production", "development"].contains(environment),
              appID.hasSuffix("." + bundleID),
              URLComponents(url: challengeURL, resolvingAgainstBaseURL: false)?.query == nil,
              URLComponents(url: enrollmentURL, resolvingAgainstBaseURL: false)?.query == nil else {
            throw RILError.invalidConfiguration
        }
        self.origin = origin; self.appID = appID; self.bundleID = bundleID; self.tenantID = tenantID
        self.environment = environment; self.challengeURL = challengeURL; self.enrollmentURL = enrollmentURL
        self.policy = try policy ?? RILPolicy()
        self.relyingPolicy = try relyingPolicy ?? RILPolicy()
    }
}

struct RILCredentials: Equatable { let token: String; let appAttestKeyID: String }
protocol RILAuthentication {
    func credentials() throws -> RILCredentials
    func assertion(for clientData: Data) async throws -> Data
}
protocol RILEnrollmentTransport {
    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

public struct RILReadiness {
    public let enrolledKeyID: String?
    public let hasPendingEnrollment: Bool
    public let hasPendingRotation: Bool
}

/// Explicit opt-in. Does not install interceptors or change the OneApp startup sequence.
/// Use one client per configuration; process-wide leases also reject overlapping clients.
public actor RILClient {
    let configuration: RILConfiguration
    private let storage: RILStateStorage
    private let cryptography: RILKeyCryptography
    private let transport: RILEnrollmentTransport
    private let authentication: RILAuthentication
    private let clock: () -> Date

    init(configuration: RILConfiguration, storage: RILStateStorage, cryptography: RILKeyCryptography,
         transport: RILEnrollmentTransport, authentication: RILAuthentication, clock: @escaping () -> Date = Date.init) {
        self.configuration = configuration; self.storage = storage; self.cryptography = cryptography
        self.transport = transport; self.authentication = authentication; self.clock = clock
    }

    private func state(for credentials: RILCredentials) throws -> RILLocalState {
        guard let state = try storage.load() else {
            return RILLocalState(scope: configuration.scope, appAttestKeyID: credentials.appAttestKeyID)
        }
        guard state.scope == configuration.scope, state.appAttestKeyID == credentials.appAttestKeyID else {
            // Named, because the two look identical from outside and are handled differently: a
            // scope change is a configuration change; a key change means App Attest was
            // re-registered (the service lost or refused the registration) and the RIL key bound
            // to the old one can never be used again - only a fresh enrollment recovers.
            let which = (state.scope != configuration.scope ? "scope " : "")
                + (state.appAttestKeyID != credentials.appAttestKeyID ? "app_attest_key_id" : "")
            NXLogger.general.publicError("[RIL] local state identity mismatch: \(which)")
            print("[RIL] local state identity mismatch: \(which) - kunci RIL lokal terikat ke registrasi App Attest lain; didaftarkan ulang otomatis")
            throw RILError.registrationChanged
        }
        guard state.version == 1,
              !state.confirmationPending || (state.active != nil && state.pending != nil),
              state.pending != nil || (!state.confirmationPending && state.replacesKeyID.isEmpty),
              state.replacesKeyID.isEmpty || state.replacesKeyID == state.active?.keyID else {
            throw RILError.corruptState
        }
        return state
    }
    public func readiness() throws -> RILReadiness {
        let s = try state(for: authentication.credentials())
        return RILReadiness(enrolledKeyID: s.active?.keyID,
                            hasPendingEnrollment: s.pending != nil, hasPendingRotation: !s.replacesKeyID.isEmpty)
    }

    /// Retries the persisted candidate after timeout/restart; never generates a new retry key.
    @discardableResult public func enroll() async throws -> String { try await perform(rotation: false) }
    @discardableResult public func rotate() async throws -> String { try await perform(rotation: true) }

    private func perform(rotation: Bool) async throws -> String {
        try RILOperationLease.acquire(configuration.scope)
        defer { RILOperationLease.release(configuration.scope) }
        let credentials = try authentication.credentials()
        var s = try state(for: credentials)
        if s.pending == nil {
            if !rotation, let active = s.active { return active.keyID }
            if rotation, s.active == nil { throw RILError.notEnrolled }
            s.pending = try cryptography.generate()
            s.replacesKeyID = s.active?.keyID ?? ""
            try storage.save(s) // Persist candidate before ANY network request.
        }
        guard let pending = s.pending else { throw RILError.corruptState }
        let key = try cryptography.signer(for: pending)
        if !s.confirmationPending {
            let reply = try await exchange(operation: "enroll", key: key, replaces: s.replacesKeyID, credentials: credentials)
            if !s.replacesKeyID.isEmpty {
                // Even if a previous confirm response was lost, repeat confirm idempotently.
                guard reply.requiresRotationConfirmation || reply.generation >= 2 else { throw RILError.invalidResponse }
                s.confirmationPending = true
                try storage.save(s)
            } else {
                guard !reply.requiresRotationConfirmation else { throw RILError.invalidResponse }
                s.active = pending; s.pending = nil
                try storage.save(s)
                return pending.keyID
            }
        }
        _ = try await exchange(operation: "confirm_rotation", key: key, replaces: s.replacesKeyID, credentials: credentials)
        // Drop the old wrapped key only after server confirmation and an atomic local save.
        s.active = pending; s.pending = nil; s.replacesKeyID = ""; s.confirmationPending = false
        try storage.save(s)
        return pending.keyID
    }

    /// Generate immediately before each attempt. No automatic retries, redirects or HTTP sends.
    public func sign(_ input: URLRequest) throws -> RILSignedRequest {
        try RILOperationLease.acquire(configuration.scope)
        defer { RILOperationLease.release(configuration.scope) }
        let credentials = try authentication.credentials()
        let s = try state(for: credentials)
        guard !s.confirmationPending else { throw RILError.busy }
        guard let key = s.active, let url = input.url,
              try RILCore.target(url).origin == configuration.origin else { throw RILError.notEnrolled }
        var request = input
        request.setValue(credentials.token, forHTTPHeaderField: "X-Nexilis-ZTA-Session")
        return try RILCore.sign(request, key: cryptography.signer(for: key), policy: configuration.policy,
                                created: Int64(clock().timeIntervalSince1970))
    }

    /// Signs a request for a relying backend - any HTTPS origin other than the pilot routes, the
    /// Lite/CPaaS backend or a host's own API - which checks it through /zta/ril/verify.
    ///
    /// The ZTA session token never leaves for such a backend: the request carries
    /// X-Nexilis-ZTA-Binding, the session's digest, which the ZTA server resolves to the install
    /// and cannot be used as a session. Which URLs may be signed is RILProtection's decision.
    public func signForRelyingParty(_ input: URLRequest) throws -> RILSignedRequest {
        try RILOperationLease.acquire(configuration.scope)
        defer { RILOperationLease.release(configuration.scope) }
        let credentials = try authentication.credentials()
        let s = try state(for: credentials)
        guard !s.confirmationPending else { throw RILError.busy }
        guard let key = s.active else { throw RILError.notEnrolled }
        guard let url = input.url else { throw RILError.invalidRequest("URL required") }
        _ = try RILCore.target(url)
        var request = input
        request.setValue(nil, forHTTPHeaderField: "X-Nexilis-ZTA-Session")
        request.setValue(RILCore.base64URL(RILCore.sha256(Data(credentials.token.utf8))),
                         forHTTPHeaderField: RILClient.bindingHeader)
        return try RILCore.sign(request, key: cryptography.signer(for: key), policy: configuration.relyingPolicy,
                                created: Int64(clock().timeIntervalSince1970))
    }

    /// The header a relying backend forwards to /zta/ril/verify as `binding`.
    public static let bindingHeader = "X-Nexilis-ZTA-Binding"

    /// Local key teardown only; call as part of explicit logout/hard-wipe integration in stage 6.
    /// Does not claim to revoke server keys. Never call as a generic response to a timeout/403.
    public func clearLocalKeys() throws {
        try RILOperationLease.acquire(configuration.scope)
        defer { RILOperationLease.release(configuration.scope) }
        try storage.delete()
    }

    private struct Challenge: Decodable {
        let key_id: String, app_id: String, bundle_id: String, tenant_id: String
        let environment: String, origin: String, session_token_sha256: String
        let profile: String, algorithm: String, purpose: String, nonce_id: String, nonce: String
        let ttl_ms: Int64, server_epoch_ms: Int64
    }
    private struct Reply: Decodable {
        let status: String, profile: String, ril_key_id: String
        let generation: Int
        let requires_rotation_confirmation: Bool
        var requiresRotationConfirmation: Bool { requires_rotation_confirmation }
    }
    private func request(_ url: URL, credentials: RILCredentials) -> URLRequest {
        var r = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 15)
        r.setValue(credentials.token, forHTTPHeaderField: "X-Nexilis-ZTA-Session")
        r.setValue("application/json", forHTTPHeaderField: "Accept")
        return r
    }
    private func checkedSend(_ request: URLRequest, credentials: RILCredentials) async throws -> Data {
        try Task.checkCancellation()
        guard try authentication.credentials() == credentials else { throw RILError.identityMismatch }
        let (bytes, response) = try await transport.send(request)
        guard bytes.count <= 262144 else { throw RILError.responseTooLarge }
        guard response.url == request.url else { throw RILError.redirectDenied }
        guard try authentication.credentials() == credentials else { throw RILError.identityMismatch }
        guard response.statusCode == 200 else {
            let body = (try? JSONSerialization.jsonObject(with: bytes)) as? [String: Any]
            let code = body?["error"] as? String ?? "RIL_SERVER_REJECTED"
            print("[RIL] server menolak \(request.url?.path ?? "?"): HTTP \(response.statusCode) \(String(code.prefix(128)))")
            throw RILError.server(status: response.statusCode, code: String(code.prefix(128)))
        }
        return bytes
    }
    private func exchange(operation: String, key: RILSigningKey, replaces: String,
                          credentials: RILCredentials) async throws -> Reply {
        var url = URLComponents(url: configuration.challengeURL, resolvingAgainstBaseURL: false)!
        url.queryItems = [URLQueryItem(name: "purpose", value: "ril_enroll")]
        let started = ProcessInfo.processInfo.systemUptime
        let bytes = try await checkedSend(request(url.url!, credentials: credentials), credentials: credentials)
        let c = try JSONDecoder().decode(Challenge.self, from: bytes)
        let tokenHash = RILCore.sha256(Data(credentials.token.utf8)).map { String(format: "%02x", $0) }.joined()
        guard c.key_id == credentials.appAttestKeyID, c.app_id == configuration.appID,
              c.bundle_id == configuration.bundleID, c.tenant_id == configuration.tenantID,
              c.environment == configuration.environment, c.origin == configuration.origin,
              c.session_token_sha256 == tokenHash, c.profile == RILCore.profile,
              c.algorithm == RILCore.algorithm, c.purpose == "ril_enroll", c.ttl_ms == 60000,
              UUID(uuidString: c.nonce_id) != nil,
              let nonce = Data(base64Encoded: c.nonce), nonce.count == 32, nonce.base64EncodedString() == c.nonce,
              c.server_epoch_ms >= 0, c.server_epoch_ms <= 9_007_199_254_740_991,
              abs(Double(c.server_epoch_ms) - clock().timeIntervalSince1970 * 1000) <= 60000 else {
            // Which field, not which value: the values are the identity, and the log is public.
            var off: [String] = []
            if c.key_id != credentials.appAttestKeyID { off.append("key_id") }
            if c.app_id != configuration.appID { off.append("app_id") }
            if c.bundle_id != configuration.bundleID { off.append("bundle_id") }
            if c.tenant_id != configuration.tenantID { off.append("tenant_id") }
            if c.environment != configuration.environment { off.append("environment") }
            if c.origin != configuration.origin { off.append("origin") }
            if c.session_token_sha256 != tokenHash { off.append("session_token") }
            if c.profile != RILCore.profile || c.algorithm != RILCore.algorithm { off.append("profile/algorithm") }
            if c.purpose != "ril_enroll" || c.ttl_ms != 60000 { off.append("purpose/ttl") }
            if abs(Double(c.server_epoch_ms) - clock().timeIntervalSince1970 * 1000) > 60000 { off.append("clock_skew") }
            if off.isEmpty { off.append("nonce/nonce_id") }
            NXLogger.general.publicError("[RIL] challenge identity mismatch: \(off.joined(separator: ","))")
            print("[RIL] challenge identity mismatch: \(off.joined(separator: ",")) - bandingkan Info.plist NexilisRIL dengan apps.json server (app_id/tenant_id/env) dan RIL_ENROLLMENT_ORIGIN")
            throw RILError.identityMismatch
        }
        var fields = ["operation": operation, "profile": c.profile, "algorithm": c.algorithm,
                      "key_id": c.key_id, "app_id": c.app_id, "bundle_id": c.bundle_id,
                      "tenant_id": c.tenant_id, "environment": c.environment, "origin": c.origin,
                      "nonce_id": c.nonce_id, "challenge": c.nonce, "session_token_sha256": tokenHash,
                      "public_key_spki_b64": key.publicKeySPKI.base64EncodedString(), "replaces_key_id": replaces]
        let timestamp = Int64(clock().timeIntervalSince1970 * 1000)
        let canonical = RILCanonicalJSON.encode(fields, timestamp: timestamp)
        let proof = try key.signP1363(Data("NEXILIS-RIL-ENROLL-V1\n".utf8) + canonical)
        guard proof.count == 64 else { throw RILError.invalidResponse }
        fields["proof_b64"] = proof.base64EncodedString()
        let assertion = try await authentication.assertion(for: RILCanonicalJSON.encode(fields, timestamp: timestamp))
        guard !assertion.isEmpty, ProcessInfo.processInfo.systemUptime - started < 55 else { throw RILError.invalidResponse }
        fields["assertion"] = assertion.base64EncodedString()
        var post = request(configuration.enrollmentURL, credentials: credentials)
        post.httpMethod = "POST"
        post.setValue("application/json", forHTTPHeaderField: "Content-Type")
        post.httpBody = RILCanonicalJSON.encode(fields, timestamp: timestamp)
        guard post.httpBody!.count <= 262144 else { throw RILError.invalidResponse }
        let result = try JSONDecoder().decode(Reply.self, from: await checkedSend(post, credentials: credentials))
        guard result.profile == RILCore.profile, result.ril_key_id == key.keyID, result.generation > 0,
              result.status == (operation == "enroll" ? "enrolled" : "rotation_confirmed"),
              operation != "confirm_rotation" || !result.requiresRotationConfirmation else { throw RILError.invalidResponse }
        return result
    }
}

private enum RILOperationLease {
    private static let lock = NSLock()
    private static var scopes: Set<String> = []
    static func acquire(_ scope: String) throws {
        lock.lock(); defer { lock.unlock() }
        guard scopes.insert(scope).inserted else { throw RILError.busy }
    }
    static func release(_ scope: String) {
        lock.lock(); defer { lock.unlock() }
        scopes.remove(scope)
    }
}
