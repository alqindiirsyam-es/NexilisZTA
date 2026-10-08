//
//  SentinelPinnedHosts.swift
//  Nexilis iOS ZTA — certificate pinning for the host app's OWN backends
//
//  The iOS counterpart of the Android ZTA's `ztaProtector.pinnedHosts` (2026-10-05): one declaration,
//  both halves.
//
//    1. The platform half: Info.plist `NSAppTransportSecurity > NSPinnedDomains` (iOS 14+). The system
//       enforces it for every URLSession / WKWebView request of the app - Alamofire and other
//       URLSession-based stacks included - which is what Android's networkSecurityConfig does there.
//    2. The SDK half: the same entries, read from the same Info.plist, are enforced by
//       PinnedURLSessionDelegate and RASPGuard's own sessions, so a request that handles its server
//       trust itself is not left with system trust only.
//
//  Rules, as on Android: every host needs at least two DIFFERENT pins (a primary and a backup CA or
//  key), otherwise the next certificate rotation locks the app out of its own backend. An entry that
//  breaks this is not dropped - it refuses every connection to that host (fail closed), and says so
//  in the log. A pin is the base64 SHA-256 of a certificate's SubjectPublicKeyInfo; any certificate of
//  the chain may match (NSPinnedCAIdentities and NSPinnedLeafIdentities alike). The first-party ZTA
//  domains keep their compiled-in pins and are ignored here.
//
//  Computing a pin from a PEM certificate:
//      openssl x509 -in issuing_ca.pem -pubkey -noout | openssl pkey -pubin -outform der \
//        | openssl dgst -sha256 -binary | openssl base64
//
//  Dart code in a Flutter app does not go through URLSession and is not covered by either half.
//
import Foundation

public struct SentinelPinnedHost: Equatable {
    public let host: String
    public let includeSubdomains: Bool
    /// `sha256/<base64>` or bare base64 (the NSPinnedDomains form) - both are accepted.
    public let pins: [String]

    public init(host: String, includeSubdomains: Bool = false, pins: [String]) {
        self.host = host
        self.includeSubdomains = includeSubdomains
        self.pins = pins
    }

    /// The entries of Info.plist `NSAppTransportSecurity > NSPinnedDomains`.
    public static func fromInfoPlist(_ bundle: Bundle = .main) -> [SentinelPinnedHost] {
        guard let ats = bundle.object(forInfoDictionaryKey: "NSAppTransportSecurity") as? [String: Any],
              let domains = ats["NSPinnedDomains"] as? [String: Any] else { return [] }
        return domains.compactMap { domain, value in
            guard let entry = value as? [String: Any] else { return nil }
            let identities = ((entry["NSPinnedCAIdentities"] as? [[String: Any]]) ?? [])
                + ((entry["NSPinnedLeafIdentities"] as? [[String: Any]]) ?? [])
            let pins = identities.compactMap { $0["SPKI-SHA256-BASE64"] as? String }
            return SentinelPinnedHost(host: domain, includeSubdomains: (entry["NSIncludesSubdomains"] as? Bool) ?? false,
                                      pins: pins)
        }.sorted { $0.host < $1.host }
    }

    /// What RASPGuard is handed: host -> subdomains + normalized pins; an invalid entry keeps its host
    /// with no pins, which refuses every connection to it.
    static func guardConfiguration(_ hosts: [SentinelPinnedHost]) -> [String: [String: Any]] {
        var out: [String: [String: Any]] = [:]
        for entry in hosts {
            let host = entry.host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            guard !host.isEmpty else { continue }
            let pins = Array(Set(entry.pins.compactMap(normalize)))
            if pins.count < 2 {
                NXLogger.network.publicError("[Pinning] \(host): butuh minimal 2 pin berbeda (utama + cadangan), ada \(pins.count) - semua koneksi ke host ini ditolak sampai diperbaiki")
                out[host] = ["subdomains": entry.includeSubdomains, "pins": [String]()]
                continue
            }
            out[host] = ["subdomains": entry.includeSubdomains, "pins": pins.sorted()]
        }
        return out
    }

    /// `sha256/<base64 of 32 bytes>`, or nil for anything else.
    static func normalize(_ pin: String) -> String? {
        var value = pin.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.hasPrefix("sha256/") { value.removeFirst("sha256/".count) }
        guard let bytes = Data(base64Encoded: value), bytes.count == 32 else { return nil }
        return "sha256/" + bytes.base64EncodedString()
    }
}
