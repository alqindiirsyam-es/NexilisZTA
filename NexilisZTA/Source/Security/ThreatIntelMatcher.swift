//
//  ThreatIntelMatcher.swift
//  Nexilis iOS ZTA — Sentinel A2b: signed threat intelligence
//

import Foundation

// MARK: - A2b — indicators from the signed pack, matched against observed evidence
//
// The pack carries hashes and nothing else, and so does the event stream. An indicator of type
// `domain_sha256` is compared against `attributes["domain_sha256"]` on an observed event — never
// against a domain, a package name or an address in the clear. That is what makes the feed safe to
// ship to a device: a pack read off a jailbroken phone tells the reader which threats are being
// looked for only if they already know the answers.
//
// A match produces a new event rather than mutating the one it matched. The original stays exactly
// as the sensor reported it, and the derived event carries the indicator's own severity and
// confidence — which is what lets `localRiskScore` weigh a known-bad hash more heavily than the
// ordinary sensor reading that happened to contain it.
public enum SentinelThreatIntelMatcher {

    /// Identity map on purpose: an indicator's `type` is the attribute name it is compared
    /// against. Keeping the two spellings the same means a new indicator kind is one line here and
    /// one line in whichever sensor learns to report that attribute, with nothing to keep in sync
    /// in between.
    private static let attributeByType: [String: String] = [
        "apk_sha256":          "apk_sha256",
        "package_name_sha256": "package_name_sha256",
        "signer_sha256":       "signer_sha256",
        "domain_sha256":       "domain_sha256",
        "url_sha256":          "url_sha256",
        "certificate_sha256":  "certificate_sha256",
        "process_sha256":      "process_sha256",
        "ip_sha256":           "ip_sha256",
    ]

    /// Derives an intelligence event for every observed event whose hashed attributes match a live
    /// indicator. Returns only the new events; the caller appends them.
    public static func enrich(events: [[String: Any]], pack: [String: Any]?, now: Double) -> [[String: Any]] {
        guard !events.isEmpty,
              let pack,
              let indicators = pack["indicators"] as? [[String: Any]],
              !indicators.isEmpty else { return [] }

        // An indicator with no expiry of its own lives exactly as long as the pack that carries
        // it. A pack with no expiry at all does not make its indicators immortal by accident —
        // `SecurityPackPolicyValidator` caps every pack's lifetime, and the store re-checks it on
        // every read, so the pack itself is the outer bound.
        let packExpiry = (pack["not_after_ms"] as? NSNumber)?.doubleValue ?? .greatestFiniteMagnitude

        var derived: [[String: Any]] = []
        for indicator in indicators {
            let expiry = (indicator["expires_at_ms"] as? NSNumber)?.doubleValue ?? packExpiry
            guard expiry > now,
                  let type = (indicator["type"] as? String)?.lowercased(),
                  let attribute = attributeByType[type],
                  let expected = (indicator["sha256"] as? String)?.lowercased(),
                  expected.count == 64 else { continue }

            let source = (indicator["source"] as? String) ?? "security_pack"
            for observed in events {
                guard let attributes = observed["attributes"] as? [String: Any],
                      let actual = (attributes[attribute] as? String)?.lowercased(),
                      actual == expected else { continue }

                derived.append(SentinelThreatTelemetry.event(
                    sensor:     "intel:" + source,
                    category:   (indicator["category"] as? String) ?? "malware",
                    severity:   (indicator["severity"]   as? NSNumber)?.intValue ?? 90,
                    confidence: (indicator["confidence"] as? NSNumber)?.intValue ?? 95,
                    // Timestamped to the evidence, not to the match. The scorer's decay is meant
                    // to answer "how old is what we saw", and a stale observation does not become
                    // fresh because the pack matched it a moment ago.
                    now:        (observed["observed_at_ms"] as? NSNumber)?.doubleValue ?? now,
                    evidence:   expected,
                    attributes: ["rule_id":          (indicator["id"] as? String) ?? "indicator",
                                 "indicator_sha256": expected,
                                 "threat_code":      "indicator_match:" + type,
                                 "source":           source]))
            }
        }
        return derived
    }
}
