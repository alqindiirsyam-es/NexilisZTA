//
//  SentinelVaultClient.swift
//  Nexilis iOS ZTA — Sentinel Vault: a server/HSM operation the device asks for and never holds
//
//  Ported from Nexilis Sentinel v3.0 (SentinelVaultClient + APISZTA.performVaultOperation). The
//  device never receives Vault key material: it sends the payload, the one-time decision token a
//  sensitive-transaction authorization produced, and the two digests that decision was bound to,
//  and gets back the operation's result - a signature or a MAC - and nothing else. The service
//  consumes the decision on the way, so a decision authorizes exactly one operation.
//
//  Purposes and algorithms are a closed set on both sides: transaction_sign → ECDSA_SHA256,
//  transaction_mac → HMAC_SHA256. Anything else is refused before a key is touched.
//

import Foundation
import CryptoKit

public enum SentinelVaultClient {

    public static let errorDomain = "io.nexilis.zta.vault"

    /// The request body /zta/vault/operate expects. `payload_sha256` lets the service refuse a
    /// payload that does not match what the decision authorized before it does anything with it.
    public static func makeRequest(purpose: String, algorithm: String, payload: Data,
                                   semanticSHA256: String, decisionToken: String) -> [String: Any] {
        let payloadSHA = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
        return ["purpose": purpose, "algorithm": algorithm, "payload_sha256": payloadSHA,
                "semantic_sha256": semanticSHA256.lowercased(), "decision_token": decisionToken,
                "payload_b64": payload.base64EncodedString(), "sentinel_protocol": 2]
    }
}
