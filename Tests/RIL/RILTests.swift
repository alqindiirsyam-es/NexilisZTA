// Standalone macOS test executable: compile with the three platform-independent RIL source files.
// Software private keys exist only in this test file, never in the production key provider.
import Foundation
import CryptoKit

final class MemoryStorage: RILStateStorage {
    var state: RILLocalState?
    var failSave = false
    func load() throws -> RILLocalState? { state }
    func save(_ value: RILLocalState) throws {
        if failSave { throw RILError.keychain(-1) }
        state = value
    }
    func delete() throws { state = nil }
}
struct TestSigner: RILSigningKey {
    let key: P256.Signing.PrivateKey
    var publicKeySPKI: Data { key.publicKey.derRepresentation }
    func signP1363(_ data: Data) throws -> Data { try key.signature(for: data).rawRepresentation }
}
final class TestCryptography: RILKeyCryptography {
    var generated = 0
    func generate() throws -> RILStoredKey {
        generated += 1
        let key = P256.Signing.PrivateKey()
        return RILStoredKey(wrappedKey: key.rawRepresentation, publicKeySPKI: key.publicKey.derRepresentation)
    }
    func signer(for value: RILStoredKey) throws -> RILSigningKey {
        let key = try P256.Signing.PrivateKey(rawRepresentation: value.wrappedKey)
        guard key.publicKey.derRepresentation == value.publicKeySPKI else { throw RILError.corruptState }
        return TestSigner(key: key)
    }
}
final class TestAuthentication: RILAuthentication {
    let key = P256.Signing.PrivateKey()
    var identity = RILCredentials(token: "test-session", appAttestKeyID: "test-attest")
    var counter: UInt32 = 0
    var disabled = false
    func credentials() throws -> RILCredentials {
        if disabled { throw RILError.sessionUnavailable }
        return identity
    }
    func assertion(for data: Data) async throws -> Data {
        counter += 1
        var auth = RILCore.sha256(Data("TEAM123456.io.example.oneapp".utf8)) + Data([0])
        auth.append(contentsOf: [UInt8(counter >> 24), UInt8((counter >> 16) & 255), UInt8((counter >> 8) & 255), UInt8(counter & 255)])
        // Apple's form: ECDSA-SHA256 over nonce = SHA256(authenticatorData || SHA256(clientData)),
        // the one ril-enrollment.js and /zta/key verify - signature(for:) hashes the nonce once more.
        let signature = try key.signature(for: RILCore.sha256(auth + RILCore.sha256(data))).derRepresentation
        // Minimal independent CBOR encoder for the two Apple assertion byte-string fields.
        func text(_ s: String) -> Data { Data([0x60 + UInt8(s.utf8.count)]) + Data(s.utf8) }
        func bytes(_ d: Data) -> Data { Data([0x58, UInt8(d.count)]) + d }
        return Data([0xa2]) + text("authenticatorData") + bytes(auth) + text("signature") + bytes(signature)
    }
}
final class TestTransport: RILEnrollmentTransport {
    let auth: TestAuthentication
    let now: Date
    var calls = 0
    var loseEnrollment = false
    var loseConfirmation = false
    var wrongIdentity = false
    var wrongResponse = false
    var suspend = false
    var waiting: CheckedContinuation<Void, Never>?
    var responses: [[String: Any]] = []
    var challenges: [[String: Any]] = []
    var posts: [[String: Any]] = []
    var generation = 0
    var known: Set<String> = []
    var confirmed: Set<String> = []
    init(auth: TestAuthentication, now: Date) { self.auth = auth; self.now = now }
    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        calls += 1
        if suspend { suspend = false; await withCheckedContinuation { waiting = $0 } }
        let url = request.url!
        var result: [String: Any]
        if request.httpMethod == "GET" {
            let c: [String: Any] = ["key_id": auth.identity.appAttestKeyID,
                "app_id": wrongIdentity ? "OTHER.app" : "TEAM123456.io.example.oneapp",
                "bundle_id": "io.example.oneapp", "tenant_id": "", "environment": "production",
                "origin": "https://zta.example", "profile": RILCore.profile, "algorithm": RILCore.algorithm,
                "session_token_sha256": RILCore.sha256(Data(auth.identity.token.utf8)).map { String(format: "%02x", $0) }.joined(),
                "purpose": "ril_enroll", "nonce_id": UUID().uuidString.lowercased(),
                "nonce": Data(repeating: UInt8(calls % 255), count: 32).base64EncodedString(),
                "ttl_ms": 60000, "server_epoch_ms": Int64(now.timeIntervalSince1970 * 1000)]
            challenges.append(c); result = c
        } else {
            let payload = try JSONSerialization.jsonObject(with: request.httpBody!) as! [String: Any]
            posts.append(payload)
            let spki = Data(base64Encoded: payload["public_key_spki_b64"] as! String)!
            let id = "device-" + RILCore.base64URL(RILCore.sha256(spki))
            if known.insert(id).inserted { generation += 1 }
            let confirm = payload["operation"] as! String == "confirm_rotation"
            if confirm { confirmed.insert(id) }
            if confirm && loseConfirmation { loseConfirmation = false; throw URLError(.timedOut) }
            if !confirm && loseEnrollment { loseEnrollment = false; throw URLError(.timedOut) }
            result = ["status": confirm ? "rotation_confirmed" : "enrolled", "profile": RILCore.profile,
                      "ril_key_id": wrongResponse ? "wrong" : id, "generation": generation,
                      "requires_rotation_confirmation": !(payload["replaces_key_id"] as! String).isEmpty && !confirmed.contains(id)]
            responses.append(result)
        }
        return (try JSONSerialization.data(withJSONObject: result),
                HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!)
    }
}

@main struct RILTests {
    static var count = 0
    static var fixtures: [String: Any] = [:]
    static let now = Date(timeIntervalSince1970: 1_800_000_000)
    static func check(_ value: Bool, _ label: String) throws {
        guard value else { throw NSError(domain: "RILTests", code: 1, userInfo: [NSLocalizedDescriptionKey: label]) }
        count += 1
    }
    static func rejects(_ label: String, _ action: () throws -> Void) throws {
        do { try action() } catch { count += 1; return }
        throw NSError(domain: "RILTests", code: 2, userInfo: [NSLocalizedDescriptionKey: label])
    }
    static func rejectsAsync(_ label: String, _ action: () async throws -> Void) async throws {
        do { try await action() } catch { count += 1; return }
        throw NSError(domain: "RILTests", code: 3, userInfo: [NSLocalizedDescriptionKey: label])
    }
    static func config() throws -> RILConfiguration {
        try RILConfiguration(origin: "https://zta.example", appID: "TEAM123456.io.example.oneapp",
                             bundleID: "io.example.oneapp", environment: "production",
                             challengeURL: URL(string: "https://zta.example/zta/challenge")!,
                             enrollmentURL: URL(string: "https://zta.example/zta/ril/enroll")!)
    }
    static func main() async throws {
        let key = TestSigner(key: P256.Signing.PrivateKey())
        let policy = try RILPolicy()
        let target = try RILCore.target(URL(string: "https://ZTA.EXAMPLE:443/a%2Fb?x=1&x=2&q=a+b")!)
        try check(target.authority == "zta.example" && target.path == "/a%2Fb" && target.query == "?x=1&x=2&q=a+b", "URL canonicalization")
        try check(try RILCore.target(URL(string: "https://zta.example")!).query == "?", "empty query")
        try check(try RILCore.target(URL(string: "https://[::1]:8443/")!).authority == "[::1]:8443", "IPv6")
        var request = URLRequest(url: URL(string: "https://zta.example/zta/security-pack")!)
        let signed = try RILCore.sign(request, key: key, policy: policy, created: 1_800_000_000, nonce: "abcdefghijklmnopqrstuv")
        try check(signed.request.value(forHTTPHeaderField: "Content-Digest") == "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:", "empty digest")
        let wire = signed.request.value(forHTTPHeaderField: "Signature")!
        let sig = try P256.Signing.ECDSASignature(rawRepresentation: Data(base64Encoded: String(wire.dropFirst(6).dropLast()))!)
        try check(key.key.publicKey.isValidSignature(sig, for: Data(signed.signatureBase.utf8)), "P1363 verifies")
        try check(!signed.signatureBase.hasSuffix("\n"), "no final LF")
        try rejects("cleartext forbidden") { _ = try RILCore.target(URL(string: "http://zta.example")!) }
        try rejects("fragment forbidden") { _ = try RILCore.target(URL(string: "https://zta.example/#")!) }
        try rejects("userinfo forbidden") { _ = try RILCore.target(URL(string: "https://user@zta.example/")!) }
        try rejects("nonce injection forbidden") { _ = try RILCore.sign(request, key: key, policy: policy, nonce: "abcdefghijklmnop\n") }
        request.httpBodyStream = InputStream(data: Data([1]))
        try rejects("streams forbidden") { _ = try RILCore.sign(request, key: key, policy: policy) }
        request.httpBodyStream = nil
        request.setValue("identity", forHTTPHeaderField: "Content-Encoding")
        try rejects("encoding forbidden") { _ = try RILCore.sign(request, key: key, policy: policy) }
        request.setValue(nil, forHTTPHeaderField: "Content-Encoding")
        request.httpBody = Data(repeating: 0, count: 2)
        try rejects("body limit") { _ = try RILCore.sign(request, key: key, policy: RILPolicy(maxBodyBytes: 1)) }
        try rejects("lifetime limit") { _ = try RILPolicy(lifetimeSeconds: 61) }
        let quoted = String(data: RILCanonicalJSON.encode(["path": "a/b\n\u{1}é\u{2028}", "quote": "\"\\"], timestamp: 1), encoding: .utf8)!
        fixtures["canonicalJSON"] = quoted
        fixtures["core"] = ["url": signed.request.url!.absoluteString, "method": "GET",
                            "headers": signed.request.allHTTPHeaderFields!, "signatureBase": signed.signatureBase,
                            "publicKeySPKI": key.publicKeySPKI.base64EncodedString()]

        let storage = MemoryStorage(), crypto = TestCryptography(), auth = TestAuthentication()
        let transport = TestTransport(auth: auth, now: now)
        func client() throws -> RILClient {
            RILClient(configuration: try config(), storage: storage, cryptography: crypto,
                      transport: transport, authentication: auth, clock: { now })
        }
        var c = try client()
        try await rejectsAsync("cannot sign before enrollment") { _ = try await c.sign(URLRequest(url: URL(string: "https://zta.example/")!)) }
        storage.failSave = true
        try await rejectsAsync("persist before networking") { _ = try await c.enroll() }
        try check(transport.calls == 0, "no network when storage failed")
        storage.failSave = false
        transport.loseEnrollment = true
        try await rejectsAsync("lost enrollment response") { _ = try await c.enroll() }
        let candidate = storage.state!.pending!.keyID, generated = crypto.generated
        c = try client() // process-equivalent recovery: no in-memory RIL state survives.
        let enrolled = try await c.enroll()
        try check(enrolled == candidate && generated == crypto.generated, "retry same candidate")
        try check(storage.state!.active?.keyID == enrolled && storage.state!.pending == nil, "atomic promotion")
        let outgoing = try await c.sign(URLRequest(url: URL(string: "https://zta.example/zta/security-pack")!))
        fixtures["clientRequest"] = ["url": outgoing.request.url!.absoluteString,
                                     "headers": outgoing.request.allHTTPHeaderFields!]
        try check(outgoing.request.value(forHTTPHeaderField: "X-Nexilis-ZTA-Session") == auth.identity.token, "attach live session")
        // A relying backend (Lite/CPaaS, a host API) gets the session digest, never the token.
        var relying = URLRequest(url: URL(string: "https://api.example/v1/login?x=1")!)
        relying.httpMethod = "POST"
        relying.setValue("application/json", forHTTPHeaderField: "Content-Type")
        relying.setValue("leak-me", forHTTPHeaderField: "X-Nexilis-ZTA-Session")
        relying.httpBody = Data("{\"user\":\"a\"}".utf8)
        let relayed = try await c.signForRelyingParty(relying)
        try check(relayed.request.value(forHTTPHeaderField: "X-Nexilis-ZTA-Session") == nil, "no session token to a relying backend")
        try check(relayed.request.value(forHTTPHeaderField: RILClient.bindingHeader)
                  == RILCore.base64URL(RILCore.sha256(Data(auth.identity.token.utf8))), "binding is the session digest")
        fixtures["relying"] = ["url": relayed.request.url!.absoluteString, "headers": relayed.request.allHTTPHeaderFields!,
                               "body": relayed.request.httpBody!.base64EncodedString()]
        let enrolledClient = c
        let pilot = RILPilotTransport(routes: try RILPilotRoutes(origin: "https://zta.example",
            securityPackURL: URL(string: "https://zta.example/zta/security-pack")!,
            telemetryURL: URL(string: "https://zta.example/zta/telemetry/events")!),
            sign: { try await enrolledClient.sign($0).request }, transmit: { request in
                fixtures["pilotPost"] = ["headers": request.allHTTPHeaderFields!,
                                         "body": request.httpBody!.base64EncodedString()]
                return (Data(), HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!)
            })
        var telemetry = URLRequest(url: URL(string: "https://zta.example/zta/telemetry/events")!)
        telemetry.httpMethod = "POST"; telemetry.httpBody = Data("{\"events\":[],\"note\":\"é\"}".utf8)
        telemetry.setValue("application/json", forHTTPHeaderField: "Content-Type")
        _ = try await pilot.send(telemetry)
        try await rejectsAsync("cross origin denied") { _ = try await c.sign(URLRequest(url: URL(string: "https://other.example/")!)) }
        transport.loseConfirmation = true
        try await rejectsAsync("lost rotation confirmation") { _ = try await c.rotate() }
        try check(storage.state!.active?.keyID == enrolled && storage.state!.confirmationPending, "keep old key and recovery state")
        try await rejectsAsync("do not send revoked old key while confirmation uncertain") { _ = try await c.sign(URLRequest(url: URL(string: "https://zta.example/")!)) }
        let rotated = storage.state!.pending!.keyID
        c = try client()
        let confirmed = try await c.enroll()
        try check(confirmed == rotated && !storage.state!.confirmationPending && storage.state!.pending == nil, "resume confirmation after restart")
        auth.disabled = true
        try await rejectsAsync("invalid session denied") { _ = try await c.sign(URLRequest(url: URL(string: "https://zta.example/")!)) }
        auth.disabled = false
        auth.identity = RILCredentials(token: "test-session", appAttestKeyID: "new-install")
        try await rejectsAsync("different App Attest install cannot reuse key") { _ = try await c.enroll() }
        auth.identity = RILCredentials(token: "test-session", appAttestKeyID: "test-attest")

        // Save real Swift-generated enrollment proof and CBOR for the Node backend test.
        fixtures["enrollment"] = ["challenge": transport.challenges[0], "body": transport.posts[0],
                                   "appAttestPublicKey": auth.key.publicKey.pemRepresentation]
        try await c.clearLocalKeys()
        transport.wrongIdentity = true
        let before = transport.posts.count
        try await rejectsAsync("reject untrusted challenge identity") { _ = try await c.enroll() }
        try check(transport.posts.count == before, "no proof sent to wrong identity")
        transport.wrongIdentity = false
        transport.wrongResponse = true
        try await rejectsAsync("reject wrong response key ID") { _ = try await c.enroll() }
        try check(storage.state!.active == nil, "bad response cannot grant readiness")
        transport.wrongResponse = false
        transport.suspend = true
        let firstClient = c
        let task = Task { try await firstClient.enroll() }
        while transport.waiting == nil { await Task.yield() }
        let second = try client()
        try await rejectsAsync("cross-instance serialization") { _ = try await second.enroll() }
        transport.waiting!.resume(); transport.waiting = nil
        _ = try await task.value
        try check(try await c.readiness().enrolledKeyID != nil, "ready after serialized enrollment")
        try await pilotTests(key: key)
        print("RIL Swift checks passed: \(count)")
        print("RIL_FIXTURES:" + String(data: try JSONSerialization.data(withJSONObject: fixtures), encoding: .utf8)!)
    }

    static func pilotTests(key: TestSigner) async throws {
        let packURL = URL(string: "https://zta.example/zta-ios/zta/security-pack")!
        let telemetryURL = URL(string: "https://zta.example/zta-ios/zta/telemetry/events")!
        let routes = try RILPilotRoutes(origin: "https://zta.example", securityPackURL: packURL, telemetryURL: telemetryURL)
        var sent: [URLRequest] = []
        var failSigning = false
        var failNetwork = false
        var status = 200
        var responseURL: URL?
        let pilot = RILPilotTransport(routes: routes, sign: { request in
            if failSigning { throw RILError.notEnrolled }
            return try RILCore.sign(request, key: key, policy: RILPolicy()).request
        }, transmit: { request in
            sent.append(request)
            if failNetwork { throw URLError(.timedOut) }
            return (Data(), HTTPURLResponse(url: responseURL ?? request.url!, statusCode: status,
                                           httpVersion: nil, headerFields: nil)!)
        })
        var pack = URLRequest(url: packURL)
        pack.httpMethod = "GET"
        _ = try await pilot.send(pack)
        _ = try await pilot.send(pack)
        try check(sent.count == 2 && sent[0].value(forHTTPHeaderField: "Signature-Input") != sent[1].value(forHTTPHeaderField: "Signature-Input"), "new nonce per attempt")
        failSigning = true
        try await rejectsAsync("no unsigned fallback") { _ = try await pilot.send(pack) }
        try check(sent.count == 2, "signing failure never transmits")
        failSigning = false
        for url in ["https://other.example/zta-ios/zta/security-pack", "https://zta.example/zta-ios/zta/security-pack/", "https://zta.example/zta/challenge", "https://zta.example/v2/business"] {
            var r = pack; r.url = URL(string: url)!
            try await rejectsAsync("route rejected") { _ = try await pilot.send(r) }
        }
        var wrong = pack; wrong.httpMethod = "POST"
        try await rejectsAsync("method rejected") { _ = try await pilot.send(wrong) }
        wrong = pack; wrong.httpBody = Data([1])
        try await rejectsAsync("GET body rejected") { _ = try await pilot.send(wrong) }
        wrong = pack; wrong.setValue("application/json", forHTTPHeaderField: "Content-Type")
        try await rejectsAsync("GET content type rejected") { _ = try await pilot.send(wrong) }
        var post = URLRequest(url: telemetryURL); post.httpMethod = "POST"
        post.setValue("application/json", forHTTPHeaderField: "Content-Type")
        post.httpBody = Data(repeating: 32, count: 262144)
        _ = try await pilot.send(post)
        try check(sent.last!.httpBody == post.httpBody, "final body bytes preserved at boundary")
        post.httpBody!.append(32)
        try await rejectsAsync("telemetry 262145 rejected") { _ = try await pilot.send(post) }
        post.httpBody = Data("{\"events\":[]}".utf8)
        post.setValue("identity", forHTTPHeaderField: "Content-Encoding")
        try await rejectsAsync("encoding rejected") { _ = try await pilot.send(post) }
        post.setValue(nil, forHTTPHeaderField: "Content-Encoding")
        post.setValue("text/plain", forHTTPHeaderField: "Content-Type")
        try await rejectsAsync("content type rejected") { _ = try await pilot.send(post) }
        post.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let beforeTimeout = sent.count
        failNetwork = true
        do { _ = try await pilot.send(post); try check(false, "timeout must fail") }
        catch RILPilotError.deliveryUncertain { try check(true, "ambiguous delivery classified") }
        try check(sent.count == beforeTimeout + 1, "no POST timeout retry")
        failNetwork = false
        for code in [401, 403, 409, 503] {
            status = code
            let before = sent.count
            let response = try await pilot.send(post)
            try check(response.1.statusCode == code && sent.count == before + 1, "HTTP error preserved without retry")
        }
        status = 302
        try await rejectsAsync("redirect denied") { _ = try await pilot.send(pack) }
        status = 200; responseURL = URL(string: "https://other.example/")!
        try await rejectsAsync("changed response URL denied") { _ = try await pilot.send(pack) }
    }
}
