//
//  ZTAReachability.swift
//  NexilisZTA
//
//  Is there a network at all, asked without depending on NexilisLite.
//

import Foundation
import SystemConfiguration

/// Whether the device has a route to the internet right now.
///
/// The boot chain asks this in two places, and both answers change what happens rather than what
/// is logged: with no network the verification is not attempted at all, and a failure that turns
/// out to have no network behind it parks instead of spending the retry budget. NexilisLite has a
/// `CheckConnection` that answers the same question, but this layer is meant to stand on its own -
/// a host may adopt the ZTA pod without the chat SDK - so the check lives here too.
public enum ZTAReachability {

    /// True when a default route exists and needs no connection to be brought up first.
    ///
    /// This is reachability, not connectivity: a captive portal answers yes. It is enough for what
    /// the chain does with it, which is telling "the radio is off" apart from "the server said no".
    public static var isConnected: Bool {
        var address = sockaddr_in(sin_len: 0,
                                  sin_family: 0,
                                  sin_port: 0,
                                  sin_addr: in_addr(s_addr: 0),
                                  sin_zero: (0, 0, 0, 0, 0, 0, 0, 0))
        address.sin_len = UInt8(MemoryLayout.size(ofValue: address))
        address.sin_family = sa_family_t(AF_INET)

        guard let route = withUnsafePointer(to: &address, {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                SCNetworkReachabilityCreateWithAddress(nil, $0)
            }
        }) else {
            return false
        }

        var flags = SCNetworkReachabilityFlags(rawValue: 0)
        guard SCNetworkReachabilityGetFlags(route, &flags) else {
            return false
        }

        let reachable = flags.contains(.reachable)
        let needsConnection = flags.contains(.connectionRequired)
        return reachable && !needsConnection
    }
}
