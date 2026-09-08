//
//  TelemetryLoop.swift
//  Nexilis iOS ZTA — Sentinel A4b: process-lifetime telemetry cadence
//

import Foundation

// MARK: - A4b — evidence reaches the collector on its own schedule
//
// Telemetry used to ride along with the 15-minute status poll, which meant a device that went bad
// two minutes after a poll sat on the evidence for thirteen more. Policy refresh and evidence
// delivery want different cadences: a policy that is a quarter of an hour stale is fine, and a
// compromise that is a quarter of an hour unreported is not. So they get separate timers, and the
// pack fetch stays where it was.
//
// What this deliberately is *not*: it is a plain timer on a utility queue, alive only while the
// host process is scheduled. There is no `BGTaskScheduler` registration, no `beginBackgroundTask`
// held open to buy time the app was not granted, and no entitlement the host does not already
// have. iOS suspends the app, the timer stops, and that is the correct behaviour — Sentinel does
// not get to run when the platform says the app is not running.
//
// It also stops itself. A tick that finds no live authorization tears the loop down rather than
// waking every five minutes to discover the same thing.
public enum SentinelTelemetryLoop {

    /// Frequent enough that evidence is minutes old rather than a quarter-hour old, sparse enough
    /// that it is not a battery or backend cost. `submitThreatTelemetry` has its own failure
    /// backoff on top of this, so a device that cannot reach the collector backs away from it
    /// rather than knocking every five minutes.
    private static let interval: DispatchTimeInterval = .seconds(300)

    /// Long enough after authorization that the first pack fetch has had a chance to land, so the
    /// first batch is scored against the policy in force rather than the compiled defaults.
    private static let firstTick: DispatchTimeInterval = .seconds(10)

    /// Generous on purpose: nothing here needs to happen at a precise moment, and letting the
    /// system coalesce this wake-up with others it was already making is most of the reason a
    /// five-minute timer costs so little.
    private static let leeway: DispatchTimeInterval = .seconds(15)

    private static let queue = DispatchQueue(label: "io.nexilis.sentinel.telemetry", qos: .utility)
    private static let lock = NSLock()
    private static var timer: DispatchSourceTimer?

    /// Idempotent. `finish()` can be reached more than once across a retried chain, and a second
    /// call must not leave two timers running.
    public static func start() {
        // The same gate every Sentinel control shares: a live server-issued token. Without one
        // there is nothing to authenticate a submission with, so the loop would wake up forever
        // to call something that returns immediately. A `.regular` session that opened offline is
        // exactly that case, and it starts no timer.
        guard APISZTA.currentAuthorizationToken != nil else { return }

        lock.lock()
        defer { lock.unlock() }
        guard timer == nil else { return }

        let source = DispatchSource.makeTimerSource(queue: queue)
        source.schedule(deadline: .now() + firstTick, repeating: interval, leeway: leeway)
        source.setEventHandler {
            guard APISZTA.hasValidAuthorization else {
                // The authorization is gone — revoked, expired, or torn down. There is nothing
                // left to authenticate a submission with, so the loop ends here rather than
                // spinning until the process does.
                stop()
                return
            }
            APISZTA.submitThreatTelemetry()
        }
        timer = source
        source.resume()
    }

    public static func stop() {
        lock.lock()
        let source = timer
        timer = nil
        lock.unlock()
        // Cancelled outside the lock: the handler runs on `queue` and calls back into `stop()`,
        // and cancelling while holding a non-recursive lock it may already be waiting on is how
        // that becomes a deadlock instead of a teardown.
        source?.cancel()
    }

    /// Whether the loop is currently scheduled. Test and diagnostic use.
    public static var isRunning: Bool {
        lock.lock(); defer { lock.unlock() }
        return timer != nil
    }
}
