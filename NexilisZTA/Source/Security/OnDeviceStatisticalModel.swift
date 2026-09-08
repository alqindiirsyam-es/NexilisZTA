//
//  OnDeviceStatisticalModel.swift
//  Nexilis iOS ZTA — Sentinel A5: bounded offline statistical risk
//

import Foundation

// MARK: - A5 — a model that can only add risk, and only as much as it was signed to add
//
// Everything that makes this safe is a bound, and every bound comes from the signed pack:
//
// - It can only **add**. There is no path by which the model lowers a score the weighted evidence
//   already earned, so a model that is simply wrong costs false positives, never a missed threat.
// - It adds at most `max_additive_risk`, which `SecurityPackPolicyValidator` caps at 30 whatever
//   the pack asks for. A leaked signing key cannot turn the model into a remote deny switch.
// - It stays silent below `min_confidence`. Under the threshold it contributes exactly zero rather
//   than a small nudge nobody can account for.
// - It is **explainable**. Every assessment names the features that moved it, so a device that was
//   stepped up can be told why in terms a support ticket can carry.
//
// The parameters are weights on a logistic function, not a shipped binary blob: the whole model is
// a few dozen numbers inside a policy document that was already being signed, verified and
// bounded. Nothing here trains, learns or persists — the same events produce the same answer on
// every device running the same pack.
//
// It also cannot manufacture trust. The score it feeds only ever restricts the client further; the
// server scores the same evidence independently and its number is the one that can revoke.
public enum SentinelOnDeviceStatisticalModel {

    public struct Assessment {
        /// Points to add to the weighted score. Never negative.
        public let addedRisk: Int
        /// 0–100. Below the pack's `min_confidence` the model adds nothing and says so.
        public let confidence: Int
        /// The pack's model version, or a reason string when no model ran.
        public let version: String
        /// Which features were both weighted and present. The explanation, in order.
        public let reasons: [String]
    }

    /// Bumped only when `featureVector` changes what a name means. A pack built against a
    /// different schema is refused outright rather than scored against features whose meaning has
    /// moved underneath it — the same weights over redefined inputs is a different model wearing
    /// the old model's version string.
    public static let featureSchemaVersion = 1

    /// The feature space. The first thirteen are "a live event of this category exists"; the last
    /// three are shape — how varied, how certain, and how much of it came from a behaviour rule
    /// rather than a raw sensor.
    public static let featureNames: Set<String> = [
        "runtime_instrumentation", "app_integrity", "rat", "malware", "device_integrity", "overlay",
        "accessibility", "screen_capture", "automation", "network", "phishing",
        "transaction_manipulation", "external_mtd",
        "distinct_categories", "high_confidence_signals", "behavior_rules",
    ]

    /// Events older than this contribute nothing to the feature vector. The scorer's own decay
    /// handles gradual ageing; this is the hard edge past which evidence stops describing the
    /// device at all.
    private static let maxEventAgeMs: Double = 24 * 60 * 60 * 1000

    /// Tolerance for an event stamped slightly ahead of the reference clock. Beyond it the event
    /// is ignored rather than trusted — a future timestamp is the cheapest way to make a signal
    /// look permanently fresh.
    private static let maxFutureSkewMs: Double = 5 * 60 * 1000

    public static func evaluate(events: [[String: Any]], pack: [String: Any]?, now: Double) -> Assessment {
        guard let model = pack?["statistical_model"] as? [String: Any],
              (model["enabled"] as? NSNumber)?.boolValue == true else {
            return Assessment(addedRisk: 0, confidence: 0, version: "disabled", reasons: [])
        }
        // Belt and braces. The validator refuses a mismatched schema at apply time; this repeats
        // the check at evaluate time so a pack that reached the store by any other route still
        // cannot be scored against a feature space it was not built for.
        guard (model["feature_schema_version"] as? NSNumber)?.intValue == featureSchemaVersion else {
            return Assessment(addedRisk: 0, confidence: 0, version: "unsupported-schema",
                              reasons: ["feature_schema_mismatch"])
        }
        guard let weights = model["feature_weights"] as? [String: Any] else {
            return Assessment(addedRisk: 0, confidence: 0, version: modelVersion(of: model),
                              reasons: ["model_weights_missing"])
        }

        let version       = modelVersion(of: model)
        let maxAdd        = clamp((model["max_additive_risk"] as? NSNumber)?.intValue ?? 20, 0, 30)
        let minConfidence = clamp((model["min_confidence"]    as? NSNumber)?.intValue ?? 75, 50, 100)
        let bias          = clamp((model["bias"]              as? NSNumber)?.doubleValue ?? -4, -12, 12)

        let vector = featureVector(events: events, now: now)
        var z = bias
        var reasons: [String] = []
        for feature in featureNames {
            // Weights are clamped non-negative on top of the validator's own bound, so no single
            // feature can pull the score down and none can dominate the sum.
            let weight = clamp((weights[feature] as? NSNumber)?.doubleValue ?? 0, 0, 8)
            let value  = vector[feature] ?? 0
            z += weight * value
            if weight > 0 && value > 0 { reasons.append(feature) }
        }

        // Bounded before the exponential, so the logistic cannot be pushed into a value that
        // saturates to a certainty the evidence never supported.
        z = clamp(z, -20, 20)
        let probability = 1 / (1 + Foundation.exp(-z))
        let confidence  = Int((probability * 100).rounded())

        guard confidence >= minConfidence else {
            return Assessment(addedRisk: 0, confidence: confidence, version: version, reasons: [])
        }
        let added = clamp(Int((Double(maxAdd) * probability).rounded()), 0, maxAdd)
        return Assessment(addedRisk: added, confidence: confidence, version: version,
                          reasons: reasons.sorted())
    }

    // MARK: - Features

    private static func featureVector(events: [[String: Any]], now: Double) -> [String: Double] {
        var vector: [String: Double] = [:]
        var seenCategories = Set<String>()
        var highConfidence = 0
        var behaviorRules  = 0

        for event in events {
            let observed = (event["observed_at_ms"] as? NSNumber)?.doubleValue ?? now
            guard observed <= now + maxFutureSkewMs, now - observed <= maxEventAgeMs else { continue }

            let category = event["category"] as? String ?? "other"
            seenCategories.insert(category)
            if featureNames.contains(category) { vector[category] = 1 }

            let severity   = (event["severity"]   as? NSNumber)?.intValue ?? 0
            let confidence = (event["confidence"] as? NSNumber)?.intValue ?? 0
            if severity >= 70 && confidence >= 85 { highConfidence += 1 }

            if let attributes = event["attributes"] as? [String: Any],
               let rule = attributes["rule_id"] as? String, !rule.isEmpty { behaviorRules += 1 }
        }

        // Saturating ratios rather than raw counts. Five categories, three strong signals and two
        // fired rules already say "this device is in trouble"; a tenth of any of them says the
        // same thing, and letting the count keep climbing would let volume alone carry the score.
        vector["distinct_categories"]      = min(1, Double(seenCategories.count) / 5)
        vector["high_confidence_signals"]  = min(1, Double(highConfidence) / 3)
        vector["behavior_rules"]           = min(1, Double(behaviorRules) / 2)
        return vector
    }

    // MARK: - Primitives

    private static func modelVersion(of model: [String: Any]) -> String {
        let value = (model["version"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty || value.count > 64 ? "stat-v1" : value
    }

    private static func clamp(_ n: Int, _ low: Int, _ high: Int) -> Int { max(low, min(high, n)) }
    private static func clamp(_ n: Double, _ low: Double, _ high: Double) -> Double {
        n.isFinite ? max(low, min(high, n)) : low
    }
}
