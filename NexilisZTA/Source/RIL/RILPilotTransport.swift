import Foundation

/// Exact public endpoints, including any deployment prefix. No wildcard or business API coverage.
public struct RILPilotRoutes {
    let origin: String
    let securityPackPath: String
    let telemetryPath: String

    public init(origin: String, securityPackURL: URL, telemetryURL: URL) throws {
        let pack = try RILCore.target(securityPackURL)
        let telemetry = try RILCore.target(telemetryURL)
        guard pack.origin == origin, telemetry.origin == origin,
              pack.path.hasSuffix("/zta/security-pack"), telemetry.path.hasSuffix("/zta/telemetry/events"),
              URLComponents(url: securityPackURL, resolvingAgainstBaseURL: false)?.query == nil,
              URLComponents(url: telemetryURL, resolvingAgainstBaseURL: false)?.query == nil else {
            throw RILError.invalidConfiguration
        }
        self.origin = origin; securityPackPath = pack.path; telemetryPath = telemetry.path
    }

    func validate(_ request: URLRequest) throws {
        guard let url = request.url, try RILCore.target(url).origin == origin,
              request.httpBodyStream == nil,
              request.value(forHTTPHeaderField: "Content-Encoding") == nil else {
            throw RILError.invalidRequest("Unsupported pilot request")
        }
        let path = try RILCore.target(url).path
        let size = request.httpBody?.count ?? 0
        if request.httpMethod == "GET", path == securityPackPath {
            guard size == 0, request.value(forHTTPHeaderField: "Content-Type") == nil else {
                throw RILError.invalidRequest("Security pack requires empty body without Content-Type")
            }
        } else if request.httpMethod == "POST", path == telemetryPath {
            let type = request.value(forHTTPHeaderField: "Content-Type")?
                .trimmingCharacters(in: CharacterSet(charactersIn: " \t"))
            guard size <= 262144, ["application/json", "application/json;charset=UTF-8"].contains(type) else {
                throw RILError.invalidRequest("Telemetry body or Content-Type exceeds pilot policy")
            }
        } else { throw RILError.invalidRequest("Endpoint not allowed by RIL pilot") }
    }
}

public enum RILPilotError: Error {
    /// The transport started; a failed POST must not be automatically replayed.
    case deliveryUncertain
}

/// Signs final bytes immediately before sending. Never retries, enrolls, or falls back unsigned.
public final class RILPilotTransport {
    private let routes: RILPilotRoutes
    private let sign: (URLRequest) async throws -> URLRequest
    private let transmit: (URLRequest) async throws -> (Data, HTTPURLResponse)

    init(routes: RILPilotRoutes, sign: @escaping (URLRequest) async throws -> URLRequest,
         transmit: @escaping (URLRequest) async throws -> (Data, HTTPURLResponse)) {
        self.routes = routes; self.sign = sign; self.transmit = transmit
    }

    public func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        try Task.checkCancellation()
        try routes.validate(request)
        let signed = try await sign(request)
        try Task.checkCancellation()
        do {
            let result = try await transmit(signed)
            guard result.1.url == signed.url, !(300...399).contains(result.1.statusCode) else {
                throw RILError.redirectDenied
            }
            return result
        } catch {
            // Do not expose response bodies, credentials, or signed URLs in error diagnostics.
            throw RILPilotError.deliveryUncertain
        }
    }
}
