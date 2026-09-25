//
//  OfflinePreflight.swift
//  Nexilis iOS ZTA — Barrier #1: everything observable without a network, before the network
//
//  Ported from Nexilis Sentinel v3.0.1 RC5 (SentinelOfflinePreflight) onto this codebase's app
//  modes. The RC5 invariant: no Sentinel backend connection is authorized until every locally
//  available security check has completed successfully. Here that is enforced through the latch
//  on RASPGuard - SentinelOfflineGateURLProtocol fails every SDK request while it is closed - and
//  this file is the only thing that opens it.
//
//  What differs from RC5, deliberately:
//    - RC5 refuses DEBUG builds outright. This repository supports Debug runs of every mode (see
//      NX_XCODE_DEBUG_RUN in rasp_native.c), so the preflight runs the real probes in Debug too
//      and enforces them the same way; it just does not refuse the build for being Debug.
//    - RC5 treats any utun/ipsec/ppp interface from getifaddrs as a finding, which on iOS is
//      every device. VPN state comes from NetworkPosture's scoped-proxy read instead, and hosts
//      can declare trusted VPN interface prefixes in Info.plist
//      (NexilisTrustedVPNInterfacePrefixes) - a VPN that matches one is not a finding.
//    - The verdict follows the app mode. At .hsa and .middle a finding fails the chain closed and
//      the latch stays shut. At .regular the probes still run and the evidence is still recorded
//      and reported, but the latch opens regardless - that mode tolerates offline and degraded
//      conditions by design, and the service decides what to make of the evidence.
//
//  It performs no DNS, HTTP, App Attest challenge or telemetry - anything that would itself be a
//  network operation is by definition not an offline check.
//

import Foundation
import UIKit
import CFNetwork
#if SWIFT_PACKAGE
import NexilisZTACore
#endif

public enum SentinelOfflinePreflight {

    public struct Evidence {
        public let threatMask: UInt32
        public let screenCaptured: Bool
        public let secondaryDisplay: Bool
        public let proxyConfigured: Bool
        public let vpnInterfaceActive: Bool
        public let vpnTrusted: Bool
        public let appAttestSupported: Bool
        public let auditChainValid: Bool
        public let releaseIdentityValid: Bool
        /// True when nothing above is a finding. At .regular the latch opens even when false.
        public let clean: Bool

        var auditDetail: [String: Any] {
            ["threat_mask": Int(threatMask), "screen_captured": screenCaptured,
             "secondary_display": secondaryDisplay, "proxy": proxyConfigured,
             "vpn": vpnInterfaceActive, "vpn_trusted": vpnTrusted,
             "app_attest_supported": appAttestSupported, "audit_chain_valid": auditChainValid,
             "release_identity_valid": releaseIdentityValid, "clean": clean]
        }
    }

    public static let errorDomain = "io.nexilis.zta.preflight"

    private static let lock = NSLock()
    private static var last: Evidence?

    /// The evidence of the most recent run, for anything that reports it after the fact.
    public static var lastEvidence: Evidence? {
        lock.lock(); defer { lock.unlock() }
        return last
    }

    /// Runs every offline probe and, when the mode allows, opens the network latch.
    ///
    /// Throws at .hsa and .middle on the first finding, in a fixed order that puts the cheapest
    /// and most decisive checks first. Must be called on the main thread: the display probes read
    /// UIKit state.
    @discardableResult
    public static func run(configuration: NexilisZTAConfiguration) throws -> Evidence {
        let guarder = RASPGuard.shared()
        guarder.invalidateOfflinePreflight()
        let enforce = NXSecurityPolicy.requiresServerChain()

        // Local audit chain first: a broken chain means the record of every earlier verdict on
        // this install cannot be trusted, and a preflight is one more entry in that record.
        let auditValid = SecurityAuditChain.verifyChain()
        try refuse(!auditValid, enforce, -7410, "Local security-audit chain is invalid.")

        // The native RASP set, run now rather than read from the launch verdict: an attempt that
        // starts minutes after launch has to earn the network with the device as it is now.
        let threats = guarder.runChecksNow()
        try refuse(threats != RASP_THREAT_NONE || !guarder.deviceClean, enforce,
                   Int(threats), "Offline RASP/device integrity preflight failed (mask 0x\(String(threats, radix: 16))).")

        // Release identity, where the host declared one. At .hsa the chain already requires the
        // declaration; here the comparison is repeated as part of the offline set.
        let identityValid = guarder.verifyCodeSignatureIntegrity()
        try refuse(!identityValid, enforce, -7411, "Application signing/release identity failed offline verification.")

        let captured = UIScreen.main.isCaptured
        let secondary = UIScreen.screens.count > 1
        try refuse(captured || secondary, enforce, -7412,
                   "Screen capture, recording, mirroring or a secondary display is active.")

        let proxy = proxyIsConfigured()
        try refuse(proxy, enforce, -7413, "A local proxy/PAC/SOCKS configuration is active.")

        let (vpn, trusted) = vpnInterfaceState()
        try refuse(vpn && !trusted, enforce, -7414, "A VPN/tunnel interface is active.")

        let appAttest = AppAttestService.shared.isSupported
        try refuse(!appAttest, enforce, -7415, "App Attest/Secure Enclave capability is unavailable.")

        let clean = auditValid && threats == RASP_THREAT_NONE && guarder.deviceClean && identityValid
            && !captured && !secondary && !proxy && !(vpn && !trusted) && appAttest
        let evidence = Evidence(threatMask: threats, screenCaptured: captured, secondaryDisplay: secondary,
                                proxyConfigured: proxy, vpnInterfaceActive: vpn, vpnTrusted: trusted,
                                appAttestSupported: appAttest, auditChainValid: auditValid,
                                releaseIdentityValid: identityValid, clean: clean)
        lock.lock(); last = evidence; lock.unlock()

        // Everything observable without backend access has been looked at. Only now may SDK
        // networking open - and at .regular it opens on a finding too, with the finding recorded.
        guarder.markOfflinePreflightPassed()
        SecurityAuditChain.append(event: clean ? "offline_preflight_passed" : "offline_preflight_recorded",
                                  detail: evidence.auditDetail)
        if !clean {
            NXLogger.appAttest.publicInfo("[Preflight] Temuan dicatat, mode 3 tidak memblokir: \(evidence.auditDetail)")
        }
        // print(), so it is visible in Xcode without an os_log filter: this is the line that says
        // the latch opened and what the service will be told (rc4_offline_preflight / mask).
        print("[Preflight] Barrier #1 \(clean ? "LULUS" : "dicatat (mode 3)") - latch dibuka; evidence ke server: rc4_offline_preflight=true rc4_local_threat_mask=\(threats) capture=\(captured) proxy=\(proxy) vpn=\(vpn)\(vpn ? (trusted ? " (tepercaya)" : " (tidak tepercaya)") : "") appAttest=\(appAttest)")
        NXLogger.appAttest.publicInfo("[Preflight] Barrier #1 \(clean ? "LULUS" : "dicatat (mode 3)") - latch dibuka; evidence ke server: rc4_offline_preflight=true rc4_local_threat_mask=\(threats) capture=\(captured) proxy=\(proxy) vpn=\(vpn)\(vpn ? (trusted ? " (tepercaya)" : " (tidak tepercaya)") : "") appAttest=\(appAttest)")
        return evidence
    }

    /// For a caller about to touch the network by hand: the same refusal the URL protocol gives,
    /// as an error it can show.
    public static func requireNetworkAllowed() throws {
        guard RASPGuard.shared().offlinePreflightPassed else {
            throw failure(Int(NXOfflineGateErrorCode),
                          "Sentinel networking is locked until the offline security preflight passes.")
        }
    }

    // MARK: - Probes

    /// HTTP, HTTPS, SOCKS or a PAC script. Unreadable settings count as a finding - a device whose
    /// proxy state cannot be inspected is not a device whose proxy state is known to be clean.
    private static func proxyIsConfigured() -> Bool {
        guard let settings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] else {
            return true
        }
        // String keys, the way NetworkPosture.m reads them: Swift on iOS marks the kCFNetworkProxies*
        // constants for HTTPS/SOCKS unavailable, but the dictionary carries them all the same.
        let keys = ["HTTPEnable", "HTTPSEnable", "SOCKSEnable", "ProxyAutoConfigEnable"]
        return keys.contains { key in (settings[key] as? NSNumber)?.boolValue == true }
    }

    /// The `__SCOPED__` proxy map, the way NetworkPosture reads it, and not getifaddrs: iOS keeps
    /// several utun interfaces up on every device for its own services, so walking the interface
    /// list would flag every phone. The scoped map lists only interfaces a VPN configuration
    /// actually routes through. A prefix the host declared trusted is not a finding.
    private static func vpnInterfaceState() -> (active: Bool, trusted: Bool) {
        let posture = NetworkPosture.currentPosture()
        let active = (posture["vpn_active"] as? NSNumber)?.boolValue ?? false
        let trusted = (posture["vpn_trusted"] as? NSNumber)?.boolValue ?? false
        return (active, active && trusted)
    }

    private static func refuse(_ finding: Bool, _ enforce: Bool, _ code: Int, _ message: String) throws {
        guard finding, enforce else { return }
        throw failure(code, message)
    }

    private static func failure(_ code: Int, _ message: String) -> NSError {
        NSError(domain: errorDomain, code: code, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
