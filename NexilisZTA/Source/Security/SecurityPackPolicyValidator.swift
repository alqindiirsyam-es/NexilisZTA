//
//  SecurityPackPolicyValidator.swift
//  Nexilis iOS ZTA — Sentinel A1b: content validation for the signed Security Pack
//

import Foundation

// MARK: - A1b — what a valid signature still does not prove
//
// The signature says the pack came from the offline signer. It says nothing about whether the
// pack is sane: a signer with a bad build script, or a signing key that leaked, can produce a
// perfectly signed pack carrying a weight of 4000, an indicator list of a million entries, or a
// `revoke_at` that sits below its own `deny_at`. `SecurityPackStore` already refuses two things
// the signer is not trusted with — loosening a compiled floor, and going backwards in version.
// This type is the third: everything else the client can check for itself before it agrees to be
// governed by the pack.
//
// Every rule here is fail-closed and whole-pack. A pack with one malformed indicator is refused
// entirely rather than applied with that indicator dropped, because a pack that is silently only
// three-quarters applied leaves the device believing it enforces a policy it does not.
//
// Optional means optional. Today's server contract guarantees `version`, `min_protocol`,
// `not_after_ms` and `response`; the richer members are additive. So an absent member passes and
// a *present* member must be well-formed — which is the distinction that matters, because the
// hole being closed is a malformed value being silently clamped at read time, not a missing one.
//
// One deliberate departure from the reference model: an indicator whose `expires_at_ms` has
// already passed does **not** invalidate the pack. `SecurityPackStore.current()` re-validates on
// every read, so treating a lapsed indicator as fatal would make a pack self-destruct mid-session
// at its earliest indicator expiry and leave the device with no policy at all until the next
// refresh — strictly worse than the stale indicator it was trying to avoid. Time filtering is
// `SentinelThreatIntelMatcher`'s job, and it skips expired indicators at match time. Validation
// here only checks the field is well-formed and inside the pack's own lifetime.
public enum SecurityPackPolicyValidator {

    /// A pack issued further ahead than this is a clock problem or a forgery, not a policy.
    public static let maxFutureSkewMs: Double = 5 * 60 * 1000

    /// Longest lifetime a single pack may claim. A pack that never expires is a pack that can
    /// never be corrected by letting it lapse.
    public static let maxValidityMs: Double = 45 * 24 * 60 * 60 * 1000

    /// Enough to carry a real intelligence feed, small enough that parsing one cannot itself be
    /// the denial of service.
    public static let maxIndicators = 4096

    /// Every risk category this build knows how to score — the same set
    /// `SentinelThreatTelemetry.defaultWeight` switches over. A weight for a category the scorer
    /// has never heard of is dead weight at best, and at worst a typo standing in for a control
    /// somebody believes is enabled.
    public static let categories: Set<String> = [
        "device_integrity", "runtime_instrumentation", "app_integrity", "rat", "overlay",
        "accessibility", "screen_capture", "automation", "network", "attestation", "malware",
        "phishing", "transaction_manipulation", "external_mtd", "other",
    ]

    /// Indicator kinds the matcher can evaluate. All of them are hashes: a pack never carries a
    /// domain, a package name or an address in the clear, so an intercepted pack tells an attacker
    /// what is being looked for only if they already know the answer.
    public static let indicatorTypes: Set<String> = [
        "apk_sha256", "package_name_sha256", "signer_sha256", "domain_sha256",
        "url_sha256", "certificate_sha256", "process_sha256", "ip_sha256",
    ]

    /// The response ladder in the order it has to climb.
    private static let responseLadder = ["monitor_at", "step_up_at", "restrict_at", "deny_at", "revoke_at"]

    /// Validates a pack whose signature has already been verified.
    ///
    /// - Parameters:
    ///   - pack: the decoded payload.
    ///   - now: the reference clock — `SecurityPackStore.referenceTimeMs()`, which is the later of
    ///     the device clock and the last server timestamp seen, so a device clock moved backwards
    ///     cannot buy an expired pack more time.
    public static func validate(_ pack: [String: Any], now: Double) -> Bool {
        guard let version = (pack["version"] as? NSNumber)?.intValue, version > 0 else { return false }

        // A pack that needs a protocol this build does not speak is refused whole. Applying the
        // half it understands would leave the device believing it runs a policy it does not.
        if let required = pack["min_protocol"] {
            guard let n = required as? NSNumber, !isBool(n),
                  n.intValue >= 1, n.intValue <= SentinelProtocol.current else { return false }
        }

        return validateLifetime(pack, now: now)
            && validatePolicyVersion(pack)
            && validateWeights(pack)
            && validateHardBlocks(pack)
            && validateDecay(pack)
            && validateResponse(pack)
            && validateIndicators(pack)
            && validateStatisticalModel(pack)
            && validateCompatibility(pack)
    }

    // MARK: - Lifetime

    private static func validateLifetime(_ pack: [String: Any], now: Double) -> Bool {
        var issued: Double?
        if let raw = pack["issued_at_ms"] {
            guard let n = raw as? NSNumber, !isBool(n), n.doubleValue > 0,
                  n.doubleValue <= now + maxFutureSkewMs else { return false }
            issued = n.doubleValue
        }

        guard let raw = pack["not_after_ms"] else {
            // No expiry claimed at all. `SecurityPackStore` already reads that as "does not expire
            // on its own", and a pack that claims nothing cannot claim something wrong.
            return true
        }
        guard let n = raw as? NSNumber, !isBool(n) else { return false }
        let notAfter = n.doubleValue
        guard notAfter > 0, notAfter > now else { return false }

        if let issued {
            guard notAfter > issued, notAfter - issued <= maxValidityMs else { return false }
        } else {
            guard notAfter - now <= maxValidityMs else { return false }
        }
        return true
    }

    private static func validatePolicyVersion(_ pack: [String: Any]) -> Bool {
        guard let raw = pack["policy_version"] else { return true }
        guard let value = raw as? String else { return false }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return !trimmed.isEmpty && trimmed.count <= 64
    }

    // MARK: - Scoring parameters

    private static func validateWeights(_ pack: [String: Any]) -> Bool {
        guard let raw = pack["risk_weights"] else { return true }
        guard let weights = raw as? [String: Any] else { return false }
        for (category, value) in weights {
            guard categories.contains(category), inRange(value, 0, 100) else { return false }
        }
        return true
    }

    private static func validateHardBlocks(_ pack: [String: Any]) -> Bool {
        guard let raw = pack["hard_block_categories"] else { return true }
        guard let list = raw as? [String], list.count <= categories.count,
              list.allSatisfy({ categories.contains($0) }) else { return false }
        return true
    }

    /// The reader clamps these into range, which is exactly the behaviour being removed here: a
    /// half-life of 9,000,000 minutes silently became 1440 and nobody found out the pack was
    /// wrong. Refusing it surfaces the mistake while the previous pack stays in force.
    private static func validateDecay(_ pack: [String: Any]) -> Bool {
        guard let raw = pack["risk_decay"] else { return true }
        guard let decay = raw as? [String: Any] else { return false }
        return optionalInRange(decay["half_life_minutes"], 5, 1440)
            && optionalInRange(decay["floor_percent"], 10, 80)
            && optionalInRange(decay["max_event_age_minutes"], 5, 1440)
    }

    /// Only the rungs the pack actually carries are checked — today's server sends `deny_at` and
    /// `revoke_at` and nothing else — but the ones present may not be out of order. A `revoke_at`
    /// below `deny_at` is a policy that revokes before it denies, and there is no reading of that
    /// which was intended.
    private static func validateResponse(_ pack: [String: Any]) -> Bool {
        guard let raw = pack["response"] else { return true }
        guard let response = raw as? [String: Any] else { return false }
        var previous = 0
        for name in responseLadder {
            guard let value = response[name] else { continue }
            guard let n = value as? NSNumber, !isBool(n) else { return false }
            let threshold = n.intValue
            guard threshold >= 1, threshold <= 100, threshold >= previous else { return false }
            previous = threshold
        }
        return true
    }

    // MARK: - Threat intelligence

    private static func validateIndicators(_ pack: [String: Any]) -> Bool {
        guard let raw = pack["indicators"] else { return true }
        guard let indicators = raw as? [[String: Any]], indicators.count <= maxIndicators else { return false }
        let packExpiry = (pack["not_after_ms"] as? NSNumber)?.doubleValue

        for indicator in indicators {
            guard let id = indicator["id"] as? String, !id.isEmpty, id.count <= 96,
                  let type = (indicator["type"] as? String)?.lowercased(), indicatorTypes.contains(type),
                  let sha = (indicator["sha256"] as? String)?.lowercased(), isSHA256Hex(sha),
                  let category = (indicator["category"] as? String)?.lowercased(), categories.contains(category),
                  let source = indicator["source"] as? String, !source.isEmpty, source.count <= 96,
                  optionalInRange(indicator["severity"], 0, 100),
                  optionalInRange(indicator["confidence"], 0, 100) else { return false }

            // Well-formed, and never outliving the pack that carries it. Whether it has already
            // lapsed is the matcher's business — see the type comment.
            if let expiry = indicator["expires_at_ms"] {
                guard let n = expiry as? NSNumber, !isBool(n), n.doubleValue > 0 else { return false }
                if let packExpiry, n.doubleValue > packExpiry { return false }
            }
        }
        return true
    }

    // MARK: - Statistical model

    private static func validateStatisticalModel(_ pack: [String: Any]) -> Bool {
        guard let raw = pack["statistical_model"] else { return true }
        guard let model = raw as? [String: Any] else { return false }

        // A model the pack has switched off needs no parameters to be correct.
        guard (model["enabled"] as? NSNumber)?.boolValue == true else { return true }

        guard let version = model["version"] as? String, !version.isEmpty, version.count <= 64,
              (model["feature_schema_version"] as? NSNumber)?.intValue
                  == SentinelOnDeviceStatisticalModel.featureSchemaVersion,
              inRange(model["max_additive_risk"], 0, 30),
              inRange(model["min_confidence"], 50, 100),
              inRange(model["bias"], -12, 12),
              let training = (model["training_manifest_sha256"] as? String)?.lowercased(),
              isSHA256Hex(training),
              let validation = (model["validation_report_sha256"] as? String)?.lowercased(),
              isSHA256Hex(validation),
              let weights = model["feature_weights"] as? [String: Any] else { return false }

        // The two hashes above are not verified here — nothing on the device holds the training
        // manifest to compare them against. They are carried so a released decision can be traced
        // back to the artefacts it was trained and validated on, which is an audit property, not a
        // runtime one. What is enforced is that they exist and are the right shape.
        for (feature, value) in weights {
            guard SentinelOnDeviceStatisticalModel.featureNames.contains(feature),
                  inRange(value, 0, 8) else { return false }
        }
        return true
    }

    // MARK: - Forward compatibility

    /// v2.4's fail-closed rule. A pack that asks for a trust protocol or a feature identifier this
    /// build does not have is refused, rather than accepted by a client that will quietly not do
    /// the thing the pack was written to require.
    private static func validateCompatibility(_ pack: [String: Any]) -> Bool {
        guard let raw = pack["compatibility"] else { return true }
        guard let compatibility = raw as? [String: Any] else { return false }

        if let minimum = compatibility["minimum_trust_protocol"] {
            guard let n = minimum as? NSNumber, !isBool(n),
                  n.intValue >= 1, n.intValue <= SentinelProtocol.current else { return false }
        }
        if let required = compatibility["required_features"] {
            guard let features = required as? [String],
                  features.allSatisfy({ SentinelProtocol.supportedFeatures.contains($0) }) else { return false }
        }
        return true
    }

    // MARK: - Primitives

    /// `true` when the value is absent; otherwise it must be a non-boolean number in range.
    private static func optionalInRange(_ value: Any?, _ low: Double, _ high: Double) -> Bool {
        value == nil ? true : inRange(value, low, high)
    }

    private static func inRange(_ value: Any?, _ low: Double, _ high: Double) -> Bool {
        guard let n = value as? NSNumber, !isBool(n) else { return false }
        let d = n.doubleValue
        return d.isFinite && d >= low && d <= high
    }

    /// JSON `true` bridges to `NSNumber`, so without this a `"deny_at": true` would read as 1 and
    /// pass every bound it is checked against.
    private static func isBool(_ n: NSNumber) -> Bool { CFGetTypeID(n) == CFBooleanGetTypeID() }

    private static func isSHA256Hex(_ s: String) -> Bool {
        s.count == 64 && s.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
    }
}
