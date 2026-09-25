//
//  RILProtection.swift
//  NexilisZTA
//
//  RIL for HTTPS beyond the ZTA pilot routes: every request the app sends to a protected URL -
//  NexilisLite's backend, a host's own API - leaves signed with the install's Secure Enclave RIL
//  key (profile nexilis-ril-v2), and the backend checks it through the ZTA server
//  (POST /zta/ril/verify, see ServerZTAiOS/RIL-RELYING-PARTY.md).
//
//  How requests are reached: RILSigningURLProtocol. Once protection is configured it is put in
//  front of every URLSession created from URLSessionConfiguration.default / .ephemeral (Lite's
//  sessions, Alamofire, the host's own) and registered for URLSession.shared, so neither Lite nor
//  a no-code shielded host has to change a line. It claims only requests whose URL starts with a
//  protected prefix; everything else is left to the normal stack untouched.
//
//  What it does to a claimed request: reads the body (bounded), signs the final bytes, sends
//  them on its own session and hands the response back. The host session's delegate still sees
//  the server-trust challenge (its own pinning keeps working), after the SDK's check of any
//  RASPGuard-pinned host.
//
//  Modes:
//    enforce  no signature, no request: RIL not ready within the readiness timeout, a body over
//             the limit or one the protocol cannot see (an upload task) fails the request.
//    observe  signed when it can be, sent unsigned otherwise - for rolling out ahead of a
//             backend that enforces.
//
//  Never claimed: the ZTA service's own URLs (they have their own RIL path), a request that
//  already carries a Signature-Input, anything that is not HTTPS. Not reachable at all: WKWebView
//  and Dart's HttpClient (Flutter) do not use URLSession - a host signs those with APISZTA.rilSign.
//

import Foundation
import ObjectiveC
#if SWIFT_PACKAGE
import NexilisZTACore
#endif

public enum RILProtectionMode: String {
    case enforce, observe
}

/// Which HTTPS URLs leave RIL-signed.
public struct RILProtection {
    /// Absolute HTTPS prefixes, e.g. "https://api.example/v1/". A request is protected when its
    /// URL (scheme and host lowercased, default port dropped) starts with one of them.
    public var urlPrefixes: [String]
    /// Prefixes inside a protected one that are not signed - large uploads, public files.
    public var excludedURLPrefixes: [String]
    public var mode: RILProtectionMode
    /// How long an enforced request waits for RIL to become ready (enrollment runs right after the
    /// ZTA session is up) before it fails.
    public var readinessTimeout: TimeInterval
    /// Also protect NexilisLite's own backend (the URL base it connects to), minus its upload
    /// endpoints. NexilisLite registers that base itself; this only switches it on.
    public var protectsNexilisLite: Bool

    public init(urlPrefixes: [String] = [], excludedURLPrefixes: [String] = [], mode: RILProtectionMode = .enforce,
                readinessTimeout: TimeInterval = 15, protectsNexilisLite: Bool = false) throws {
        for prefix in urlPrefixes + excludedURLPrefixes {
            guard RILProtectionRegistry.normalizedPrefix(prefix) != nil else { throw RILError.invalidConfiguration }
        }
        guard urlPrefixes.isEmpty == false || protectsNexilisLite, (1...120).contains(readinessTimeout) else {
            throw RILError.invalidConfiguration
        }
        self.urlPrefixes = urlPrefixes
        self.excludedURLPrefixes = excludedURLPrefixes
        self.mode = mode
        self.readinessTimeout = readinessTimeout
        self.protectsNexilisLite = protectsNexilisLite
    }

    /// Reads the protection keys of a `NexilisRIL` dictionary (Info.plist or the shield plist):
    ///
    ///     <key>ProtectedURLs</key>      <array><string>https://api.example/v1/</string></array>
    ///     <key>ExcludedURLs</key>       <array><string>https://api.example/v1/upload</string></array>
    ///     <key>ProtectionMode</key>     <string>enforce</string>   <!-- or observe -->
    ///     <key>ProtectNexilisLite</key> <true/>
    ///     <key>ReadinessTimeout</key>   <integer>15</integer>
    ///
    /// None of them present: nil, RIL signs only the ZTA pilot routes. Present and wrong: throws.
    static func from(settings: [String: Any]) throws -> RILProtection? {
        let keys = ["ProtectedURLs", "ExcludedURLs", "ProtectionMode", "ProtectNexilisLite", "ReadinessTimeout"]
        guard keys.contains(where: { settings[$0] != nil }) else { return nil }
        func strings(_ key: String) throws -> [String] {
            guard let value = settings[key] else { return [] }
            guard let list = value as? [String] else { throw RILError.invalidConfiguration }
            return list
        }
        let mode: RILProtectionMode
        if let raw = settings["ProtectionMode"] {
            guard let text = raw as? String, let value = RILProtectionMode(rawValue: text) else { throw RILError.invalidConfiguration }
            mode = value
        } else { mode = .enforce }
        let lite: Bool
        if let raw = settings["ProtectNexilisLite"] {
            guard let value = raw as? Bool else { throw RILError.invalidConfiguration }
            lite = value
        } else { lite = false }
        let timeout: TimeInterval
        if let raw = settings["ReadinessTimeout"] {
            guard let value = raw as? NSNumber else { throw RILError.invalidConfiguration }
            timeout = value.doubleValue
        } else { timeout = 15 }
        return try RILProtection(urlPrefixes: strings("ProtectedURLs"), excludedURLPrefixes: strings("ExcludedURLs"),
                                 mode: mode, readinessTimeout: timeout, protectsNexilisLite: lite)
    }
}

public extension APISZTA {

    /// Signs `request` for a relying backend with the install's RIL key, waiting up to the
    /// configured readiness timeout (15 s without protection configured) for enrollment.
    ///
    /// For what RILSigningURLProtocol cannot reach - a request built for WKWebView, one a Flutter
    /// host sends from Dart, a background upload - or for a host that prefers to sign explicitly.
    /// The URL must be HTTPS; the body must be in `httpBody` (not a stream) and within the limit.
    /// Throws when RIL is not configured, not ready, or the request cannot be signed.
    static func rilSign(_ request: URLRequest) async throws -> URLRequest {
        let timeout = RILProtectionRegistry.shared.readinessTimeout
        return try await RILProtectionRegistry.sign(request, waitingUpTo: timeout)
    }

    /// Completion form of `rilSign(_:)`, delivered on the main queue.
    static func rilSign(_ request: URLRequest, completion: @escaping (Result<URLRequest, Error>) -> Void) {
        Task {
            let result: Result<URLRequest, Error>
            do { result = .success(try await rilSign(request)) } catch { result = .failure(error) }
            DispatchQueue.main.async { completion(result) }
        }
    }

    /// Adds protected URL prefixes at runtime, on top of the configuration's. Needs RIL configured
    /// (Info.plist `NexilisRIL`, `NexilisZTAConfiguration.ril`, or the shield plist `RIL`).
    static func addRILProtectedURLs(_ prefixes: [String], excluding excluded: [String] = []) throws {
        try RILProtectionRegistry.shared.add(prefixes, excluding: excluded)
    }

    /// Whether requests to protected URLs are being signed - RIL configured with protection.
    static var isRILProtectionActive: Bool { RILProtectionRegistry.shared.isActive }

    /// For NexilisLite: its backend base and the endpoints inside it that are not signed. Evaluated
    /// on each request (the base can change after connect); used only when the configuration says
    /// `ProtectNexilisLite`.
    static func registerNexilisLiteRILScope(_ provider: @escaping () -> (base: [String], excluded: [String])) {
        RILProtectionRegistry.shared.liteProvider = provider
    }
}

public let RILProtectionErrorDomain = "io.nexilis.ril.protection"

public enum RILProtectionErrorCode: Int {
    /// RIL is configured but the key is not ready (still enrolling, failed, suspended).
    case notReady = -7510
    /// The body is over the relying-request limit, or streamed where it has to be materialized.
    case bodyNotSignable = -7511
    /// An upload task whose body a URL protocol cannot see.
    case uploadNotSignable = -7512
    /// RIL is not configured in this app at all.
    case notConfigured = -7513
}

func rilProtectionError(_ code: RILProtectionErrorCode, _ reason: String, underlying: Error? = nil) -> NSError {
    var info: [String: Any] = [NSLocalizedDescriptionKey: "RIL: " + reason]
    if let underlying { info[NSUnderlyingErrorKey] = underlying }
    return NSError(domain: RILProtectionErrorDomain, code: code.rawValue, userInfo: info)
}

// MARK: - Registry

final class RILProtectionRegistry {

    static let shared = RILProtectionRegistry()
    private let lock = NSLock()
    private var included: [String] = []
    private var excluded: [String] = []
    private var ztaExcluded: [String] = []
    private var mode: RILProtectionMode = .enforce
    private var timeout: TimeInterval = 15
    private var protectsLite = false
    private var active = false
    private var liteCache: (at: Date, base: [String], excluded: [String])?
    var liteProvider: (() -> (base: [String], excluded: [String]))? {
        get { lock.lock(); defer { lock.unlock() }; return storedLiteProvider }
        set { lock.lock(); storedLiteProvider = newValue; liteCache = nil; lock.unlock() }
    }
    private var storedLiteProvider: (() -> (base: [String], excluded: [String]))?

    var isActive: Bool { lock.lock(); defer { lock.unlock() }; return active }
    private var signedHosts: Set<String> = []
    private var unsignedHosts: Set<String> = []

    /// Observe mode, once per host: the first request that went out unsigned, and why.
    func noteUnsigned(_ host: String?, label: String, reason: String) {
        let key = host ?? "?"
        lock.lock(); let first = unsignedHosts.insert(key).inserted; lock.unlock()
        if first { NXLogger.general.publicInfo("[RIL] observe: \(label) terkirim tanpa tanda tangan (\(reason)) - log sekali per host") }
    }

    /// Once per host, so a developer can see protection at work without a line per request.
    func noteSigned(_ host: String?) {
        guard let host else { return }
        lock.lock(); let first = signedHosts.insert(host).inserted; lock.unlock()
        if first { NXLogger.general.publicInfo("[RIL] request ke \(host) ditandatangani (log sekali per host)") }
    }
    var readinessTimeout: TimeInterval { lock.lock(); defer { lock.unlock() }; return timeout }

    /// "https://Host:443/path" -> "https://host/path". Nil for anything that is not an absolute
    /// HTTPS URL without userinfo, query or fragment.
    static func normalizedPrefix(_ text: String) -> String? {
        guard let c = URLComponents(string: text), c.scheme?.lowercased() == "https",
              let host = c.host?.lowercased(), !host.isEmpty, c.user == nil, c.password == nil,
              c.query == nil, c.fragment == nil else { return nil }
        let port = (c.port == nil || c.port == 443) ? "" : ":\(c.port!)"
        return "https://" + host + port + (c.percentEncodedPath.isEmpty ? "/" : c.percentEncodedPath)
    }

    static func normalized(_ url: URL) -> String? {
        guard let c = URLComponents(url: url, resolvingAgainstBaseURL: false), c.scheme?.lowercased() == "https",
              let host = c.host?.lowercased(), !host.isEmpty else { return nil }
        let port = (c.port == nil || c.port == 443) ? "" : ":\(c.port!)"
        return "https://" + host + port + (c.percentEncodedPath.isEmpty ? "/" : c.percentEncodedPath)
    }

    func configure(_ protection: RILProtection, ztaBaseURL: String) {
        lock.lock(); defer { lock.unlock() }
        included = protection.urlPrefixes.compactMap(Self.normalizedPrefix)
        excluded = protection.excludedURLPrefixes.compactMap(Self.normalizedPrefix)
        // The ZTA service's own paths are never claimed: the pilot routes are signed by
        // RILPilotTransport with the session token, and the chain itself must not wait on RIL.
        var base = ztaBaseURL
        if !base.hasSuffix("/") { base += "/" }
        ztaExcluded = Self.normalizedPrefix(base).map { [$0] } ?? []
        mode = protection.mode
        timeout = protection.readinessTimeout
        protectsLite = protection.protectsNexilisLite
        active = true
    }

    func add(_ prefixes: [String], excluding more: [String]) throws {
        let add = prefixes.map(Self.normalizedPrefix), skip = more.map(Self.normalizedPrefix)
        guard !add.contains(nil), !skip.contains(nil) else { throw RILError.invalidConfiguration }
        lock.lock(); defer { lock.unlock() }
        guard active else { throw rilProtectionError(.notConfigured, "RIL protection is not configured") }
        included += add.compactMap { $0 }
        excluded += skip.compactMap { $0 }
    }

    /// The mode a request is protected under, or nil when it is not protected.
    func mode(for request: URLRequest) -> RILProtectionMode? {
        guard let url = request.url, let target = Self.normalized(url),
              request.value(forHTTPHeaderField: "Signature-Input") == nil else { return nil }
        lock.lock()
        guard active else { lock.unlock(); return nil }
        var include = included, exclude = excluded + ztaExcluded
        let mode = self.mode
        let lite = protectsLite ? storedLiteProvider : nil
        var cached = liteCache
        lock.unlock()
        if let lite {
            // The base lives in Lite's encrypted defaults; a second's staleness is harmless.
            if cached == nil || Date().timeIntervalSince(cached!.at) > 2 {
                let scope = lite()
                cached = (Date(), scope.base.compactMap(Self.normalizedPrefix), scope.excluded.compactMap(Self.normalizedPrefix))
                lock.lock(); liteCache = cached; lock.unlock()
            }
            include += cached!.base
            exclude += cached!.excluded
        }
        guard include.contains(where: { target.hasPrefix($0) }),
              !exclude.contains(where: { target.hasPrefix($0) }) else { return nil }
        return mode
    }

    /// Signs for a relying backend, waiting for readiness up to `timeout` (0: not at all).
    static func sign(_ request: URLRequest, waitingUpTo timeout: TimeInterval) async throws -> URLRequest {
        var request = request
        // What URLSession would add on the way out must be there before signing: a body with no
        // Content-Type goes as form data, and the type is a covered component.
        if let body = request.httpBody, !body.isEmpty, request.value(forHTTPHeaderField: "Content-Type") == nil {
            request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        }
        return try await signOnMain(request, waitingUpTo: timeout)
    }

    @MainActor private static func signOnMain(_ request: URLRequest, waitingUpTo timeout: TimeInterval) async throws -> URLRequest {
        guard let session = APISZTA.rilSession else {
            throw rilProtectionError(.notConfigured, "RIL is not configured in this app")
        }
        // A key being replaced (APISZTA.recoverRILRegistration: failed -> suspended -> enrolling) is not a
        // failure yet: wait for it the same way as for a first enrollment.
        let deadline = Date().addingTimeInterval(timeout)
        while APISZTA.isRecoveringRILRegistration, Date() < deadline {
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
        if session.state != .ready,
           !(await session.waitUntilReady(timeout: max(0, deadline.timeIntervalSinceNow))) {
            throw rilProtectionError(.notReady, "the RIL key is not ready (\(session.state.rawValue))",
                                     underlying: session.lastError)
        }
        return try await session.signForRelyingParty(request)
    }
}

// MARK: - Installation

enum RILProtectionInstaller {

    private typealias Getter = @convention(c) (AnyClass, Selector) -> URLSessionConfiguration
    private static var originalDefault: Getter?
    private static var installed = false
    private static let lock = NSLock()

    /// Puts RILSigningURLProtocol in front of every default/ephemeral session created from now on,
    /// and of URLSession.shared. Sessions that already exist keep their configuration - which is
    /// why APISZTA.configure (or the shield) runs before the host's networking starts.
    static func install() {
        lock.lock(); defer { lock.unlock() }
        guard !installed else { return }
        installed = true
        URLProtocol.registerClass(RILSigningURLProtocol.self)
        guard let meta = object_getClass(URLSessionConfiguration.self) else { return }
        for name in ["defaultSessionConfiguration", "ephemeralSessionConfiguration"] {
            let selector = NSSelectorFromString(name)
            guard let method = class_getInstanceMethod(meta, selector) else { continue }
            let original = unsafeBitCast(method_getImplementation(method), to: Getter.self)
            if name == "defaultSessionConfiguration" { originalDefault = original }
            let block: @convention(block) (AnyClass) -> URLSessionConfiguration = { cls in
                let configuration = original(cls, selector)
                let others = (configuration.protocolClasses ?? []).filter { $0 != RILSigningURLProtocol.self }
                configuration.protocolClasses = [RILSigningURLProtocol.self] + others
                return configuration
            }
            method_setImplementation(method, imp_implementationWithBlock(block))
        }
        NXLogger.general.publicInfo("[RIL] perlindungan HTTPS aktif - URLSession default/ephemeral dan shared")
    }

    /// A default configuration without RILSigningURLProtocol, for the protocol's own session.
    static func plainDefaultConfiguration() -> URLSessionConfiguration {
        lock.lock(); let original = originalDefault; lock.unlock()
        let configuration = original.map { $0(URLSessionConfiguration.self, NSSelectorFromString("defaultSessionConfiguration")) }
            ?? URLSessionConfiguration.default
        configuration.protocolClasses = (configuration.protocolClasses ?? []).filter { $0 != RILSigningURLProtocol.self }
        return configuration
    }
}

// MARK: - URL protocol

/// Signs requests to protected URLs (see RILProtection). Installed automatically once protection
/// is configured; a host that builds a session from a configuration of its own adds it with
/// `configuration.protocolClasses = [RILSigningURLProtocol.self] + (configuration.protocolClasses ?? [])`.
public final class RILSigningURLProtocol: URLProtocol {

    static let handledKey = "io.nexilis.ril.protocol.handled"
    private var inner: URLSessionDataTask?
    private var signing: Task<Void, Never>?
    private var clientThread: Thread?
    private var clientModes: [String] = [RunLoop.Mode.default.rawValue]
    private let stateLock = NSLock()
    private var stopped = false
    /// Taken from the task the loader hands the initializer. Reading `self.task` inside
    /// startLoading aborts on iOS 15 (unrecognized selector in CFNetwork's loader), so it never is.
    private var isUpload = false

    public override init(request: URLRequest, cachedResponse: CachedURLResponse?, client: URLProtocolClient?) {
        super.init(request: request, cachedResponse: cachedResponse, client: client)
    }

    @objc public convenience init(task: URLSessionTask, cachedResponse: CachedURLResponse?, client: URLProtocolClient?) {
        let request = task.currentRequest ?? task.originalRequest ?? URLRequest(url: URL(string: "about:blank")!)
        self.init(request: request, cachedResponse: cachedResponse, client: client)
        isUpload = Self.isUploadTask(task)
    }

    public override class func canInit(with request: URLRequest) -> Bool {
        guard property(forKey: handledKey, in: request) == nil else { return false }
        return RILProtectionRegistry.shared.mode(for: request) != nil
    }

    public override class func canInit(with task: URLSessionTask) -> Bool {
        guard let request = task.currentRequest ?? task.originalRequest,
              property(forKey: handledKey, in: request) == nil,
              let mode = RILProtectionRegistry.shared.mode(for: request) else { return false }
        // An upload task's body is not given to a URL protocol. Enforce claims it to fail it -
        // letting it go unsigned would be the bypass; observe leaves it to the normal stack.
        if isUploadTask(task), request.httpBody == nil, request.httpBodyStream == nil {
            return mode == .enforce
        }
        return true
    }

    public override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    /// Upload task or not, without sending the object a message. On iOS 15 the protocol's `task`
    /// is not always an object that answers the selectors a Swift `is` cast sends (a SIGABRT on
    /// every claimed request), and the concrete classes (`__NSCFLocalUploadTask`) do not descend
    /// from URLSessionUploadTask anyway - so the class chain is walked by pointer and by name.
    static func isUploadTask(_ task: URLSessionTask?) -> Bool {
        guard let task else { return false }
        var cls: AnyClass? = object_getClass(task)
        while let current = cls {
            if current === URLSessionUploadTask.self || String(cString: class_getName(current)).contains("UploadTask") {
                return true
            }
            cls = class_getSuperclass(current)
        }
        return false
    }

    public override func startLoading() {
        clientThread = Thread.current
        if let mode = RunLoop.current.currentMode { clientModes = [mode.rawValue] }
        let mode = RILProtectionRegistry.shared.mode(for: request) ?? .observe
        let original = request
        let label = "\(original.httpMethod ?? "GET") \(original.url?.host ?? "?")\(original.url?.path ?? "")"

        if isUpload, original.httpBody == nil, original.httpBodyStream == nil {
            fail(rilProtectionError(.uploadNotSignable, "upload tasks cannot be signed by the URL protocol - send the body with a data task, or exclude the URL"))
            return
        }
        // The body as bytes: what is signed is exactly what is sent.
        let limit = 1_048_576
        var body = original.httpBody
        var oversized = false
        if body == nil, let stream = original.httpBodyStream {
            let (bytes, complete) = Self.read(stream, limit: limit)
            body = bytes
            oversized = !complete
        }
        oversized = oversized || (body?.count ?? 0) > limit
        var materialized = original
        materialized.httpBodyStream = nil
        materialized.httpBody = body

        if oversized {
            guard mode == .observe else {
                fail(rilProtectionError(.bodyNotSignable, "request body over \(limit) bytes cannot be signed - exclude the URL"))
                return
            }
            RILProtectionRegistry.shared.noteUnsigned(original.url?.host, label: label, reason: "body terlalu besar")
            send(original)
            return
        }

        signing = Task { [weak self] in
            do {
                let wait = mode == .enforce ? RILProtectionRegistry.shared.readinessTimeout : 0
                let signed = try await RILProtectionRegistry.sign(materialized, waitingUpTo: wait)
                RILProtectionRegistry.shared.noteSigned(original.url?.host)
                self?.send(signed)
            } catch {
                guard let self else { return }
                if mode == .observe {
                    RILProtectionRegistry.shared.noteUnsigned(original.url?.host, label: label, reason: error.localizedDescription)
                    self.send(materialized)
                } else {
                    NXLogger.general.publicError("[RIL] enforce: \(label) ditolak - \(error.localizedDescription)")
                    self.fail(error as NSError)
                }
            }
        }
    }

    public override func stopLoading() {
        stateLock.lock(); stopped = true; let task = inner; stateLock.unlock()
        signing?.cancel()
        task?.cancel()
        if let task { RILProtocolSession.shared.forget(task) }
    }

    // MARK: Plumbing

    /// Reads a body stream; `complete` false when it went past `limit` (the bytes read so far
    /// are the whole stream up to that point, and the rest is read too so it can still be sent).
    private static func read(_ stream: InputStream, limit: Int) -> (Data, Bool) {
        var data = Data()
        stream.open(); defer { stream.close() }
        var buffer = [UInt8](repeating: 0, count: 65_536)
        while true {
            let count = stream.read(&buffer, maxLength: buffer.count)
            if count <= 0 { break }
            data.append(buffer, count: count)
        }
        return (data, data.count <= limit)
    }

    private func send(_ prepared: URLRequest) {
        var outgoing = prepared
        let mutable = (outgoing as NSURLRequest).mutableCopy() as! NSMutableURLRequest
        URLProtocol.setProperty(true, forKey: Self.handledKey, in: mutable)
        outgoing = mutable as URLRequest
        stateLock.lock()
        guard !stopped else { stateLock.unlock(); return }
        let task = RILProtocolSession.shared.dataTask(with: outgoing, owner: self)
        inner = task
        stateLock.unlock()
        task.resume()
    }

    fileprivate func onClient(_ work: @escaping () -> Void) {
        stateLock.lock(); let done = stopped; stateLock.unlock()
        guard !done else { return }
        guard let thread = clientThread, thread != Thread.current else { work(); return }
        perform(#selector(runOnClient(_:)), on: thread, with: RILBlock(work), waitUntilDone: false, modes: clientModes)
    }

    @objc private func runOnClient(_ block: RILBlock) {
        stateLock.lock(); let done = stopped; stateLock.unlock()
        if !done { block.work() }
    }

    private func fail(_ error: Error) {
        onClient { self.client?.urlProtocol(self, didFailWithError: error) }
    }

    fileprivate func received(_ response: URLResponse) {
        onClient { self.client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed) }
    }
    fileprivate func received(_ data: Data) {
        onClient { self.client?.urlProtocol(self, didLoad: data) }
    }
    fileprivate func completed(_ error: Error?) {
        onClient {
            if let error { self.client?.urlProtocol(self, didFailWithError: error) }
            else { self.client?.urlProtocolDidFinishLoading(self) }
        }
    }
    fileprivate func redirected(to request: URLRequest, by response: HTTPURLResponse) {
        let mutable = (request as NSURLRequest).mutableCopy() as! NSMutableURLRequest
        URLProtocol.removeProperty(forKey: Self.handledKey, in: mutable)
        onClient {
            // The loading system restarts with the new request, which is claimed (and signed
            // afresh) only if it is protected too.
            self.client?.urlProtocol(self, wasRedirectedTo: mutable as URLRequest, redirectResponse: response)
            self.client?.urlProtocol(self, didFailWithError: NSError(domain: NSCocoaErrorDomain, code: NSUserCancelledError))
        }
    }
    /// The host session's delegate decides on trust too - its own pinning keeps working.
    fileprivate func challenge(_ challenge: URLAuthenticationChallenge,
                               completion: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        let sender = RILChallengeSender(completion)
        let forwarded = URLAuthenticationChallenge(authenticationChallenge: challenge, sender: sender)
        onClient { self.client?.urlProtocol(self, didReceive: forwarded) }
    }
}

private final class RILBlock: NSObject {
    let work: () -> Void
    init(_ work: @escaping () -> Void) { self.work = work }
}

private final class RILChallengeSender: NSObject, URLAuthenticationChallengeSender {
    private var completion: ((URLSession.AuthChallengeDisposition, URLCredential?) -> Void)?
    private let lock = NSLock()
    init(_ completion: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) { self.completion = completion }
    private func finish(_ disposition: URLSession.AuthChallengeDisposition, _ credential: URLCredential?) {
        lock.lock(); let done = completion; completion = nil; lock.unlock()
        done?(disposition, credential)
    }
    func use(_ credential: URLCredential, for challenge: URLAuthenticationChallenge) { finish(.useCredential, credential) }
    func continueWithoutCredential(for challenge: URLAuthenticationChallenge) { finish(.useCredential, nil) }
    func cancel(_ challenge: URLAuthenticationChallenge) { finish(.cancelAuthenticationChallenge, nil) }
    func performDefaultHandling(for challenge: URLAuthenticationChallenge) { finish(.performDefaultHandling, nil) }
    func rejectProtectionSpaceAndContinue(with challenge: URLAuthenticationChallenge) { finish(.rejectProtectionSpace, nil) }
}

/// The one session every claimed request is sent on. Not cached, not redirected on its own.
private final class RILProtocolSession: NSObject, URLSessionDataDelegate {

    static let shared = RILProtocolSession()
    private let lock = NSLock()
    private var owners: [Int: RILSigningURLProtocol] = [:]
    private lazy var session: URLSession = {
        let configuration = RILProtectionInstaller.plainDefaultConfiguration()
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        let queue = OperationQueue()
        queue.maxConcurrentOperationCount = 1
        queue.name = "io.nexilis.ril.protocol"
        return URLSession(configuration: configuration, delegate: self, delegateQueue: queue)
    }()
    private let trust = PinnedURLSessionDelegate()

    func dataTask(with request: URLRequest, owner: RILSigningURLProtocol) -> URLSessionDataTask {
        let task = session.dataTask(with: request)
        lock.lock(); owners[task.taskIdentifier] = owner; lock.unlock()
        return task
    }
    func forget(_ task: URLSessionTask) {
        lock.lock(); owners[task.taskIdentifier] = nil; lock.unlock()
    }
    private func owner(_ task: URLSessionTask) -> RILSigningURLProtocol? {
        lock.lock(); defer { lock.unlock() }; return owners[task.taskIdentifier]
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let owner = owner(task) else { completionHandler(.cancelAuthenticationChallenge, nil); return }
        let host = challenge.protectionSpace.host.lowercased()
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              RASPGuard.shared().isPinnedHost(host) else {
            owner.challenge(challenge, completion: completionHandler)
            return
        }
        // A host RASPGuard pins is held to those pins first, whatever the host session would say.
        trust.urlSession(session, didReceive: challenge) { disposition, credential in
            guard disposition == .useCredential else { completionHandler(disposition, credential); return }
            owner.challenge(challenge, completion: completionHandler)
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
        guard let owner = owner(task) else { return }
        forget(task)
        task.cancel()
        owner.redirected(to: request, by: response)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        owner(dataTask)?.received(response)
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        owner(dataTask)?.received(data)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        guard let owner = owner(task) else { return }
        forget(task)
        owner.completed(error)
    }
}
