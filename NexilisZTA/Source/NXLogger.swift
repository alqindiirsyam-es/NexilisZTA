//
//  NXLogger.swift
//  SampleAppShield
//
//  Created by Qindi on 06/04/26.
//
import OSLog

public struct NXLogger {
    private static let subsystem = "io.nexilis.SampleAppShield"

    public static let rasp      = Logger(subsystem: subsystem, category: "RASP")
    public static let appAttest = Logger(subsystem: subsystem, category: "AppAttest")
    public static let network   = Logger(subsystem: subsystem, category: "Network")
    public static let crypto    = Logger(subsystem: subsystem, category: "Crypto")
    public static let general   = Logger(subsystem: subsystem, category: "General")
}

// Helper extension agar mudah log error dengan privacy .public
public extension Logger {
    func publicError(_ message: String) {
        self.error("\(message, privacy: .public)")
    }

    func publicInfo(_ message: String) {
        self.info("\(message, privacy: .public)")
    }

    func publicDebug(_ message: String) {
        self.debug("\(message, privacy: .public)")
    }
}
