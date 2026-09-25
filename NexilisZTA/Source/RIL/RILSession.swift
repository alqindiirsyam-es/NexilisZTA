import Foundation

public enum RILSessionState: String {
    case waitingForSession, enrolling, ready, failed, suspended
}

/// Host lifecycle for one installation/configuration. Failure never deletes an enrolled key.
/// All state transitions are on the main actor; concurrent preparations share one operation.
@MainActor public final class RILSession {
    public private(set) var state: RILSessionState = .waitingForSession
    public private(set) var lastError: Error?
    public var onStateChange: ((RILSessionState) -> Void)?
    private let enroll: () async throws -> String
    private let rotate: () async throws -> String
    private let signRequest: (URLRequest) async throws -> URLRequest
    private let signRelyingRequest: (URLRequest) async throws -> URLRequest
    private let clear: () async throws -> Void
    private var pending: Task<String, Error>?
    private var generation = 0
    private var clearing = false

    public convenience init(client: RILClient) {
        self.init(enroll: { try await client.enroll() }, rotate: { try await client.rotate() },
                  sign: { try await client.sign($0).request },
                  signRelying: { try await client.signForRelyingParty($0).request },
                  clear: { try await client.clearLocalKeys() })
    }

    init(enroll: @escaping () async throws -> String, rotate: @escaping () async throws -> String,
         sign: @escaping (URLRequest) async throws -> URLRequest,
         signRelying: ((URLRequest) async throws -> URLRequest)? = nil,
         clear: @escaping () async throws -> Void) {
        self.enroll = enroll; self.rotate = rotate; signRequest = sign; self.clear = clear
        signRelyingRequest = signRelying ?? sign
    }

    private func transition(_ value: RILSessionState, error: Error? = nil) {
        state = value; lastError = error
        // print(), not only os_log: Xcode's console filters os_log info-level lines by default,
        // and the reason a session failed is the one thing a developer wants to see there.
        if let error {
            print("[RIL] state -> \(value.rawValue): \(error)")
        } else {
            print("[RIL] state -> \(value.rawValue)")
        }
        onStateChange?(value)
    }

    /// Call only after a live ZTA session exists. A failure needs explicit retryEnrollment().
    public func prepare() async throws {
        guard !clearing else { throw RILError.busy }
        if state == .ready { return }
        if state == .suspended { throw RILError.sessionUnavailable }
        if state == .failed { throw lastError ?? RILError.notEnrolled }
        try await run(rotation: false)
    }

    public func retryEnrollment() async throws {
        guard !clearing else { throw RILError.busy }
        if state == .suspended, let old = pending {
            let epoch = generation
            _ = await old.result
            guard !clearing, generation == epoch else { throw RILError.busy }
            pending = nil
        }
        guard pending == nil else { throw RILError.busy }
        transition(.waitingForSession)
        try await prepare()
    }

    public func rotateKey() async throws {
        guard !clearing, pending == nil, state == .ready else { throw RILError.busy }
        try await run(rotation: true)
    }

    private func run(rotation: Bool) async throws {
        let epoch: Int
        let task: Task<String, Error>
        if let existing = pending { task = existing; epoch = generation }
        else {
            generation += 1
            epoch = generation
            let operation = rotation ? rotate : enroll
            task = Task { try Task.checkCancellation(); return try await operation() }
            pending = task
            transition(.enrolling)
        }
        do {
            _ = try await task.value
            guard generation == epoch else { throw CancellationError() }
            if pending != nil { pending = nil; transition(.ready) }
        } catch {
            if generation == epoch, pending != nil { pending = nil; transition(.failed, error: error) }
            throw error
        }
    }

    public func sign(_ request: URLRequest) async throws -> URLRequest {
        try await sign(request, with: signRequest)
    }

    /// Signs for a relying backend (see RILClient.signForRelyingParty). Same gate as `sign`.
    public func signForRelyingParty(_ request: URLRequest) async throws -> URLRequest {
        try await sign(request, with: signRelyingRequest)
    }

    private func sign(_ request: URLRequest, with operation: (URLRequest) async throws -> URLRequest) async throws -> URLRequest {
        guard !clearing, state == .ready else { throw RILError.notEnrolled }
        let epoch = generation
        do {
            let signed = try await operation(request)
            guard epoch == generation, state == .ready else { throw RILError.sessionUnavailable }
            return signed
        } catch {
            // A stale response from before suspend/clear must not revive or replace that state.
            // Only a failure of the key itself fails the session. A request that cannot be signed
            // (a body over the limit, a plain-HTTP URL), a rotation in progress or a ZTA session
            // being re-established says nothing about the key - with every HTTPS request of the
            // app going through here, treating those as fatal would switch RIL off for all of them.
            if epoch == generation, state == .ready, Self.isKeyFailure(error) { transition(.failed, error: error) }
            throw error
        }
    }

    static func isKeyFailure(_ error: Error) -> Bool {
        switch error as? RILError {
        case .notEnrolled?, .identityMismatch?, .registrationChanged?, .corruptState?, .keychain?, .secureEnclaveUnavailable?, .invalidConfiguration?:
            return true
        case .invalidRequest?, .busy?, .sessionUnavailable?:
            return false
        default:
            return !(error is CancellationError)
        }
    }

    /// Waits until the session can sign - enrollment still running just after the ZTA session
    /// became ready, typically - for at most `timeout`. Returns at once when it cannot get there
    /// on its own: failed and suspended need an explicit decision.
    public func waitUntilReady(timeout: TimeInterval) async -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while state != .ready {
            guard state == .waitingForSession || state == .enrolling, !clearing, Date() < deadline else { return false }
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
        return !clearing
    }

    /// Immediately closes the signing gate. Cancellation is not proof of server rollback.
    public func suspend() {
        generation += 1
        pending?.cancel()
        transition(.suspended)
    }

    func rejectRequest(status: Int, code: String) {
        guard state == .ready else { return }
        transition(.failed, error: RILError.server(status: status, code: code))
    }

    /// Explicit local teardown, not server revocation. Wait for an in-flight enrollment to settle
    /// before deleting its persisted candidate, so it cannot recreate state after deletion.
    public func clearLocalKeys() async throws {
        guard !clearing else { throw RILError.busy }
        clearing = true
        suspend()
        let old = pending
        if let old { _ = await old.result }
        pending = nil
        defer { clearing = false }
        do { try await clear() }
        catch { transition(.suspended, error: error); throw error }
    }

    /// Called after authorization is re-established, not for every foreground notification.
    public func sessionAuthorized() async throws {
        guard !clearing else { throw RILError.busy }
        if state == .suspended {
            let epoch = generation
            if let pending { _ = await pending.result }
            guard !clearing, generation == epoch else { throw RILError.busy }
            self.pending = nil
            transition(.waitingForSession)
        }
        try await prepare()
    }
}
