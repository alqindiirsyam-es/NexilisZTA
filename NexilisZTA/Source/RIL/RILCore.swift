import Foundation
import CryptoKit
import Security

public enum RILError: Error {
    case invalidRequest(String), invalidConfiguration, invalidResponse, identityMismatch
    /// The local RIL key belongs to another App Attest registration (or scope) of this install: App Attest was
    /// registered again, and a key bound to the old registration can never be used. Recovered by clearing
    /// the local key and enrolling afresh - which the layer does by itself (APISZTA.recoverRILRegistration).
    case registrationChanged
    case notEnrolled, busy, secureEnclaveUnavailable, keychain(OSStatus), corruptState
    case sessionUnavailable, redirectDenied, responseTooLarge
    case server(status: Int, code: String)
}

public protocol RILSigningKey {
    var publicKeySPKI: Data { get }
    func signP1363(_ message: Data) throws -> Data
}

public extension RILSigningKey {
    var keyID: String { "device-" + RILCore.base64URL(RILCore.sha256(publicKeySPKI)) }
}

public struct RILPolicy {
    public let maxBodyBytes: Int
    public let lifetimeSeconds: Int64
    public init(maxBodyBytes: Int = 1_048_576, lifetimeSeconds: Int64 = 60) throws {
        guard (1...1_048_576).contains(maxBodyBytes), (1...60).contains(lifetimeSeconds) else {
            throw RILError.invalidConfiguration
        }
        self.maxBodyBytes = maxBodyBytes
        self.lifetimeSeconds = lifetimeSeconds
    }
}

public struct RILCanonicalTarget: Equatable {
    public let origin: String
    public let authority: String
    public let path: String
    public let query: String
}

public struct RILSignedRequest {
    public let request: URLRequest
    /// Diagnostics/test evidence; do not log in production (may include sensitive query data).
    public let signatureBase: String
    public let created: Int64
    public let expires: Int64
    public let nonce: String
    public let keyID: String
}

public enum RILCore {
    public static let profile = "nexilis-ril-v2"
    public static let algorithm = "ecdsa-p256-sha256"

    public static func sha256(_ bytes: Data) -> Data { Data(SHA256.hash(data: bytes)) }
    public static func base64URL(_ bytes: Data) -> String {
        bytes.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
    public static func randomNonce() throws -> String {
        var bytes = [UInt8](repeating: 0, count: 16)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else { throw RILError.keychain(status) }
        return base64URL(Data(bytes))
    }
    static func matches(_ value: String, _ pattern: String) -> Bool {
        guard let range = value.range(of: pattern, options: .regularExpression) else { return false }
        return range.lowerBound == value.startIndex && range.upperBound == value.endIndex
    }
    public static func target(_ url: URL) throws -> RILCanonicalTarget {
        guard let c = URLComponents(url: url, resolvingAgainstBaseURL: false),
              c.scheme?.lowercased() == "https", c.user == nil, c.password == nil, c.fragment == nil,
              var host = c.host?.lowercased(), !host.isEmpty,
              host.unicodeScalars.allSatisfy({ $0.value > 32 && $0.value < 127 }),
              c.port == nil || (1...65535).contains(c.port!) else {
            throw RILError.invalidRequest("HTTPS absolute URL without userinfo/fragment required")
        }
        if host.contains(":"), !host.hasPrefix("[") { host = "[" + host + "]" }
        let authority = host + ((c.port == nil || c.port == 443) ? "" : ":\(c.port!)")
        let path = c.percentEncodedPath.isEmpty ? "/" : c.percentEncodedPath
        let query = "?" + (c.percentEncodedQuery ?? "")
        guard path.hasPrefix("/"), !url.absoluteString.contains("\\"),
              url.absoluteString.unicodeScalars.allSatisfy({ $0.value > 32 && $0.value < 127 }) else {
            throw RILError.invalidRequest("URL must already be encoded for transport")
        }
        return RILCanonicalTarget(origin: "https://" + authority, authority: authority, path: path, query: query)
    }

    public static func sign(_ input: URLRequest, key: RILSigningKey, policy: RILPolicy,
                            created: Int64 = Int64(Date().timeIntervalSince1970),
                            nonce: String? = nil) throws -> RILSignedRequest {
        guard let url = input.url, input.httpBodyStream == nil else {
            throw RILError.invalidRequest("Materialized request body required")
        }
        let target = try self.target(url)
        let method = input.httpMethod ?? "GET"
        guard matches(method, "^[A-Z0-9!#$%&'*+.^_`|~-]+$"), created >= 0,
              created <= 9_007_199_254_740_991 - policy.lifetimeSeconds else {
            throw RILError.invalidRequest("Invalid method or timestamp")
        }
        let body = input.httpBody ?? Data()
        guard body.count <= policy.maxBodyBytes, input.value(forHTTPHeaderField: "Content-Encoding") == nil else {
            throw RILError.invalidRequest("Body too large or Content-Encoding present")
        }
        let headers = input.allHTTPHeaderFields ?? [:]
        guard Set(headers.keys.map { $0.lowercased() }).count == headers.count else {
            throw RILError.invalidRequest("Duplicate header names")
        }
        let type = input.value(forHTTPHeaderField: "Content-Type")?.trimmingCharacters(in: CharacterSet(charactersIn: " \t"))
        if let type = type {
            guard !type.isEmpty, type.unicodeScalars.allSatisfy({ $0.value == 9 || ($0.value >= 32 && $0.value != 127) }) else {
                throw RILError.invalidRequest("Invalid Content-Type")
            }
        }
        let nonce = try nonce ?? randomNonce()
        guard matches(nonce, "^[A-Za-z0-9_-]{16,128}$"), matches(key.keyID, "^[A-Za-z0-9_-]{16,160}$") else {
            throw RILError.invalidRequest("Invalid nonce/key identity")
        }
        let digest = "sha-256=:" + sha256(body).base64EncodedString() + ":"
        var names = ["@method", "@authority", "@path", "@query"]
        var values = [method, target.authority, target.path, target.query]
        if let type = type { names.append("content-type"); values.append(type) }
        names.append("content-digest"); values.append(digest)
        let expires = created + policy.lifetimeSeconds
        let params = "(" + names.map { "\"\($0)\"" }.joined(separator: " ") + ")" +
            ";created=\(created);expires=\(expires);nonce=\"\(nonce)\";keyid=\"\(key.keyID)\";alg=\"\(algorithm)\""
        let base = zip(names, values).map { "\"\($0.0)\": \($0.1)" }.joined(separator: "\n") +
            "\n\"@signature-params\": " + params
        let signature = try key.signP1363(Data(base.utf8))
        guard signature.count == 64 else { throw RILError.invalidRequest("P1363 signature must be 64 bytes") }
        var request = input
        if let type = type { request.setValue(type, forHTTPHeaderField: "Content-Type") }
        request.setValue(digest, forHTTPHeaderField: "Content-Digest")
        request.setValue("sig1=" + params, forHTTPHeaderField: "Signature-Input")
        request.setValue("sig1=:" + signature.base64EncodedString() + ":", forHTTPHeaderField: "Signature")
        return RILSignedRequest(request: request, signatureBase: base, created: created,
                                expires: expires, nonce: nonce, keyID: key.keyID)
    }
}

/// Flat enrollment JSON matching JSON.stringify string escaping on the Node backend.
enum RILCanonicalJSON {
    static func quote(_ text: String) -> String {
        var result = "\""
        for scalar in text.unicodeScalars {
            switch scalar.value {
            case 34: result += "\\\""
            case 92: result += "\\\\"
            case 8: result += "\\b"
            case 9: result += "\\t"
            case 10: result += "\\n"
            case 12: result += "\\f"
            case 13: result += "\\r"
            case 0..<32: result += String(format: "\\u%04x", scalar.value)
            default: result.unicodeScalars.append(scalar)
            }
        }
        return result + "\""
    }
    static func encode(_ fields: [String: String], timestamp: Int64) -> Data {
        var values = fields.mapValues(quote)
        values["timestamp_ms"] = String(timestamp)
        return Data(("{" + values.keys.sorted().map { quote($0) + ":" + values[$0]! }.joined(separator: ",") + "}").utf8)
    }
}
