//
//  DetectionFeatureSchema.swift
//  Nexilis iOS ZTA — the cross-platform 16-feature detection schema (Sentinel v3.0)
//
//  Ported from Nexilis Sentinel RC5 (SentinelDetectionFeatureSchema + SentinelStatisticalRiskModel).
//  Android, iOS and the Sentinel server score the same 16-slot vector from the same event
//  categories, so one model trained on the server applies to every platform - GATS case 3,
//  "cross-platform semantic drift", is about exactly this. It sits beside this repository's own
//  named-feature model (OnDeviceStatisticalModel): a pack picks one by `feature_schema`, and the
//  evaluator dispatches. Either form can only add risk.
//

import Foundation

public enum SentinelDetectionFeatureSchema {
    public static let version = "sentinel-detection-features-v1"

    /// Slot order is the contract; a model's `weights` array is read in this order.
    public static let names = [
        "root_or_jailbreak", "runtime_instrumentation", "app_integrity", "debugger",
        "hooking", "remote_access", "overlay_or_accessibility", "screen_capture",
        "network_mitm", "malware_or_rat", "external_mtd", "transaction_manipulation",
        "sideload_or_clone", "os_patch_risk", "reputation_hit", "behavior_correlation",
    ]

    /// 1.0 in every slot for which a live event of a mapped category exists, 0.0 otherwise.
    public static func vector(events: [[String: Any]]) -> [Double] {
        var v = Array(repeating: 0.0, count: names.count)
        let categories = Set(events.compactMap { $0["category"] as? String })
        func any(_ set: Set<String>) -> Double { categories.isDisjoint(with: set) ? 0.0 : 1.0 }
        v[0]  = any(["device_integrity", "root", "jailbreak"])
        v[1]  = any(["runtime_instrumentation"])
        v[2]  = any(["app_integrity"])
        v[3]  = any(["debugger"])
        v[4]  = any(["hooking"])
        v[5]  = any(["rat", "remote_access"])
        v[6]  = any(["overlay", "accessibility"])
        v[7]  = any(["screen_capture"])
        v[8]  = any(["network_mitm", "network"])
        v[9]  = any(["malware", "rat"])
        v[10] = any(["external_mtd"])
        v[11] = any(["transaction_manipulation"])
        v[12] = any(["sideload", "clone"])
        v[13] = any(["os_patch_risk"])
        v[14] = any(["reputation"])
        v[15] = any(["behavior_correlation"])
        return v
    }
}

/// Bounded additive logistic scoring over the 16-feature vector. Adds risk only; cannot grant
/// trust. Every departure from a well-formed model - wrong schema, wrong arity, a negative
/// weight, disabled - scores zero rather than something.
public struct SentinelStatisticalRiskModel {
    public let enabled: Bool
    public let bias: Double
    public let weights: [Double]
    public let maxAdditiveRisk: Int

    public init?(pack model: [String: Any]) {
        guard (model["feature_schema"] as? String) == SentinelDetectionFeatureSchema.version,
              let weights = (model["weights"] as? [Any])?.map({ ($0 as? NSNumber)?.doubleValue ?? -1 }),
              weights.count == SentinelDetectionFeatureSchema.names.count,
              weights.allSatisfy({ $0 >= 0 && $0 <= 8 }) else { return nil }
        self.enabled = (model["enabled"] as? NSNumber)?.boolValue ?? false
        self.bias = min(12, max(-12, (model["bias"] as? NSNumber)?.doubleValue ?? 0))
        self.weights = weights
        self.maxAdditiveRisk = min(30, max(0, (model["max_additive_risk"] as? NSNumber)?.intValue ?? 0))
    }

    public func additiveRisk(features: [Double]) -> Int {
        guard enabled, features.count == weights.count else { return 0 }
        var z = max(0, bias)
        for i in 0 ..< weights.count { z += max(0, features[i]) * weights[i] }
        z = min(20, z)
        let p = 1.0 / (1.0 + Foundation.exp(-z))
        return max(0, min(maxAdditiveRisk, Int((p * Double(maxAdditiveRisk)).rounded())))
    }
}
