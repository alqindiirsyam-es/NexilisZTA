//
//  MidSessionNetworkGuard.swift
//  Nexilis iOS ZTA — a proxy / VPN switched on mid-session is refused like the boot gate
//
//  The boot gate (OfflinePreflight, Barrier #1) refuses to start behind a local proxy or an untrusted
//  VPN at app modes 1 and 2 (-7413 / -7414). After that the same signals were only carried in the /key
//  posture and in telemetry, so an intercepting proxy or VPN turned on once the app was open was never
//  stopped. The Android ZTA closed the same gap (midsession_network_block, 2026-10-06); this is its
//  iOS counterpart.
//
//  It watches from the moment the session is authorized until it is revoked:
//    - NWPathMonitor: a VPN coming up changes the path;
//    - the app becoming active: a proxy is set in Settings, i.e. with the app in the background;
//    - a 30-second timer, for anything that changes neither.
//  On a finding it reports the network evidence to the collector, revokes the local authorization
//  and shows the failure screen with the boot gate's code and message (the screen closes the app).
//  Nothing is persisted: the next launch goes through the boot gate again.
//
import Foundation
import Network
import UIKit
#if SWIFT_PACKAGE
import NexilisZTACore
#endif

public enum SentinelMidSessionNetworkGuard {
    private static let queue = DispatchQueue(label: "io.nexilis.sentinel.midsession-network", qos: .utility)
    private static let lock = NSLock()
    private static var monitor: NWPathMonitor?
    private static var timer: DispatchSourceTimer?
    private static var activeObserver: NSObjectProtocol?
    private static var triggered = false
    private static let interval: DispatchTimeInterval = .seconds(30)

    /// Idempotent. Started when the session is authorized; does nothing where the boot gate does not
    /// enforce (mode 3) or when the host turned it off.
    static func start() {
        guard APISZTA.configuration.midSessionNetworkBlock, NXSecurityPolicy.requiresServerChain() else { return }
        lock.lock(); defer { lock.unlock() }
        guard monitor == nil else { return }
        triggered = false

        let pathMonitor = NWPathMonitor()
        pathMonitor.pathUpdateHandler = { _ in check(trigger: "path") }
        pathMonitor.start(queue: queue)
        monitor = pathMonitor

        let source = DispatchSource.makeTimerSource(queue: queue)
        source.schedule(deadline: .now() + interval, repeating: interval, leeway: .seconds(5))
        source.setEventHandler { check(trigger: "timer") }
        source.resume()
        timer = source

        activeObserver = NotificationCenter.default.addObserver(forName: UIApplication.didBecomeActiveNotification,
                                                                object: nil, queue: nil) { _ in
            queue.async { check(trigger: "active") }
        }
    }

    /// Called with the authorization's revocation: there is nothing left to protect.
    static func stop() {
        lock.lock(); defer { lock.unlock() }
        monitor?.cancel(); monitor = nil
        timer?.cancel(); timer = nil
        if let activeObserver { NotificationCenter.default.removeObserver(activeObserver) }
        activeObserver = nil
    }

    /// Runs on `queue`. The probes are the boot gate's own (SentinelOfflinePreflight.networkFinding).
    private static func check(trigger: String) {
        guard APISZTA.currentAuthorizationToken != nil else { return }
        guard let finding = SentinelOfflinePreflight.networkFinding() else { return }
        lock.lock()
        let first = !triggered
        triggered = true
        lock.unlock()
        guard first else { return }

        let now = Date().timeIntervalSince1970 * 1000
        let proxy = finding.code == SentinelOfflinePreflight.proxyFindingCode
        let event = SentinelThreatTelemetry.event(sensor: proxy ? "network:proxy" : "network:vpn", category: "network",
                                                  severity: proxy ? 45 : 35, confidence: 90, now: now,
                                                  attributes: ["network_type": proxy ? "proxy" : "risky_vpn",
                                                               "phase": "mid_session"])
        APISZTA.reportEvidenceBeforeRevocation(events: [event], auditEvent: "midsession_network_block",
                                               detail: ["code": finding.code, "trigger": trigger])
        APISZTA.failDuringSession(finding)
    }
}
