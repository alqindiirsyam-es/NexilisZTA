//
//  NXLogger.swift
//  SampleAppShield
//
//  Created by Qindi on 06/04/26.
//
import Foundation
import OSLog

public struct NXLogger {
    private static let subsystem = "io.nexilis.SampleAppShield"

    public static let rasp      = Logger(subsystem: subsystem, category: "RASP")
    public static let appAttest = Logger(subsystem: subsystem, category: "AppAttest")
    public static let network   = Logger(subsystem: subsystem, category: "Network")
    public static let crypto    = Logger(subsystem: subsystem, category: "Crypto")
    public static let general   = Logger(subsystem: subsystem, category: "General")

    /// Diagnostic logging of NexilisZTA, SecurityShield and NexilisLite.
    ///
    /// These lines describe the security flow step by step - sign-in stages and the server's answers,
    /// biometric prompts, preflight findings, key ids - and with `privacy: .public` anyone with the
    /// phone on a Mac (Console, sysdiagnose) could read them from a shipped build. The Android ZTA strips
    /// its logging from release builds; this is the same rule:
    ///
    ///   - Debug builds of the library: on.
    ///   - Release builds: off, unless the host opts in with Info.plist `NexilisDiagnosticLogging = YES`
    ///     (a QA / pilot build). The Info.plist is covered by the code signature, so a shipped app cannot
    ///     be switched on without breaking its signature - and App Attest with it.
    ///
    /// Off means: `publicInfo` / `publicDebug` write nothing, `publicError` still records that an error
    /// happened but with its text redacted (`<private>` in Console).
    public static let diagnosticsEnabled: Bool = {
        #if DEBUG
        return true
        #else
        return (Bundle.main.object(forInfoDictionaryKey: "NexilisDiagnosticLogging") as? Bool) == true
        #endif
    }()
}

// Helper extension agar mudah log dengan privacy .public - hanya saat diagnostik aktif (lihat
// NXLogger.diagnosticsEnabled). Pesan dievaluasi hanya bila benar-benar ditulis.
public extension Logger {
    func publicError(_ message: @autoclosure () -> String) {
        if NXLogger.diagnosticsEnabled {
            let text = message()
            self.error("\(text, privacy: .public)")
        } else {
            let text = message()
            self.error("\(text, privacy: .private)")
        }
    }

    func publicInfo(_ message: @autoclosure () -> String) {
        guard NXLogger.diagnosticsEnabled else { return }
        let text = message()
        self.info("\(text, privacy: .public)")
    }

    func publicDebug(_ message: @autoclosure () -> String) {
        guard NXLogger.diagnosticsEnabled else { return }
        let text = message()
        self.debug("\(text, privacy: .public)")
    }
}
