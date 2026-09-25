import Foundation

@main struct RILSessionTests {
    @MainActor static func main() async throws {
        var count = 0
        func check(_ ok: Bool, _ label: String) throws {
            guard ok else { throw NSError(domain: label, code: 1) }
            count += 1
        }
        func rejects(_ operation: () async throws -> Void) async throws {
            do { try await operation() } catch { count += 1; return }
            throw NSError(domain: "Expected rejection", code: 1)
        }
        var enrolls = 0, rotations = 0, clears = 0, signs = 0
        var fail = false, failClear = false, hold = false, badRequest = false
        var continuation: CheckedContinuation<Void, Never>?
        let session = RILSession(enroll: {
            enrolls += 1
            if hold { await withCheckedContinuation { continuation = $0 } }
            if fail { throw RILError.server(status: 503, code: "test") }
            return "test-key"
        }, rotate: {
            rotations += 1
            if fail { throw URLError(.timedOut) }
            return "rotated-key"
        }, sign: { request in
            if badRequest { throw RILError.invalidRequest("body too large") }
            signs += 1; return request
        }, clear: {
            if failClear { throw RILError.keychain(-1) }
            clears += 1
        })
        let request = URLRequest(url: URL(string: "https://zta.example/zta/security-pack")!)
        try check(session.state == .waitingForSession, "initial")
        try await rejects { _ = try await session.sign(request) }
        hold = true
        let first = Task { try await session.prepare() }
        while continuation == nil { await Task.yield() }
        let second = Task { try await session.prepare() }
        await Task.yield()
        try check(enrolls == 1 && session.state == .enrolling, "coalesced enrollment")
        continuation?.resume(); continuation = nil; hold = false
        try await first.value; try await second.value
        try check(session.state == .ready, "ready after enrollment")
        _ = try await session.sign(request)
        try check(signs == 1, "sign after readiness")
        try await session.prepare()
        try check(enrolls == 1, "idempotent prepare")
        // One request that cannot be signed must not switch RIL off for every other request.
        badRequest = true
        try await rejects { _ = try await session.sign(request) }
        try await rejects { _ = try await session.signForRelyingParty(request) }
        badRequest = false
        try check(session.state == .ready, "unsignable request keeps the session ready")
        _ = try await session.signForRelyingParty(request)
        try check(signs == 2, "relying sign after an unsignable one")
        try check(await session.waitUntilReady(timeout: 1), "ready waits for nothing")
        fail = true
        try await rejects { try await session.rotateKey() }
        try check(rotations == 1 && clears == 0 && session.state == .failed, "rotation timeout preserves keys")
        try await rejects { try await session.prepare() }
        try check(enrolls == 1, "no automatic failed retry")
        fail = false
        try await session.retryEnrollment()
        try check(enrolls == 2 && session.state == .ready, "explicit recovery")
        session.rejectRequest(status: 403, code: "RIL_KEY_UNAVAILABLE")
        try check(session.state == .failed && clears == 0, "server error does not delete keys")
        try await rejects { _ = try await session.sign(request) }
        try await session.retryEnrollment()
        session.suspend()
        try check(session.state == .suspended, "suspend immediate")
        try await rejects { _ = try await session.sign(request) }
        try await session.sessionAuthorized()
        try check(session.state == .ready, "new session explicit resume")

        session.suspend(); hold = true
        let enrollment = Task { try await session.sessionAuthorized() }
        while continuation == nil { await Task.yield() }
        let deletion = Task { try await session.clearLocalKeys() }
        while session.state != .suspended { await Task.yield() }
        try check(clears == 0, "deletion waits for canceled network")
        try await rejects { try await session.retryEnrollment() }
        continuation?.resume(); continuation = nil; hold = false
        try await rejects { try await enrollment.value }
        try await deletion.value
        try check(clears == 1 && session.state == .suspended, "late success cannot revive deleted keys")
        try await rejects { _ = try await session.sign(request) }
        failClear = true
        try await rejects { try await session.clearLocalKeys() }
        try check(session.state == .suspended && session.lastError != nil, "keychain delete failure visible")
        failClear = false
        try await session.clearLocalKeys()
        try check(clears == 2, "explicit deletion retry")
        session.onStateChange = { state in
            if state == .enrolling { session.suspend() }
        }
        try await rejects { try await session.retryEnrollment() }
        try check(session.state == .suspended, "state observer cannot revive canceled enrollment")
        print("RIL lifecycle checks passed: \(count)")
    }
}
