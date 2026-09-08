//
//  PinnedURLSessionDelegate.swift
//  Nexilis iOS ZTA — replaces SelfSignedURLSessionDelegate (E3/E4)
//
//  THE PROBLEM THIS REPLACES:
//  The bundle's `SelfSignedURLSessionDelegate` (defined in Nexilis.swift and
//  SecurityShield.swift) does this on a server-trust challenge:
//
//      let credential = URLCredential(trust: serverTrust)
//      completionHandler(.useCredential, credential)
//
//  i.e. it accepts ANY certificate with no SecTrustEvaluateWithError and no
//  pinning. Combined with NSAllowsArbitraryLoads = true, the app's own traffic
//  (getAddressNew bootstrap, chat, media, StreamShield) is fully MITM-able.
//
//  THIS REPLACEMENT:
//   1. Performs real default trust evaluation — never blind .useCredential.
//   2. Pins the ZTA / banking hosts via the SPKI logic already implemented in
//      RASPGuard (exposed as a reusable method — see the patch guide).
//   3. Falls back to validated (not blind) trust for non-pinned hosts.
//
//  MIGRATION: delete both `SelfSignedURLSessionDelegate` definitions and replace
//  every `SelfSignedURLSessionDelegate()` instantiation with
//  `PinnedURLSessionDelegate()`.
//

import Foundation
import CommonCrypto

#if SWIFT_PACKAGE
// CocoaPods builds Swift and Objective-C as one mixed-language target, so these
// types are already in scope. SwiftPM has no mixed target, so the Objective-C and
// C half is its own module and has to be imported.
import NexilisZTACore
#endif

public final class PinnedURLSessionDelegate: NSObject, URLSessionTaskDelegate, URLSessionDataDelegate {

    public func urlSession(_ session: URLSession,
                           didReceive challenge: URLAuthenticationChallenge,
                           completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {

        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        // (1) Real trust evaluation — replaces the blind accept.
        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        let host = challenge.protectionSpace.host

        // (2) Pin the ZTA / banking hosts. RASPGuard already holds the pin set and
        //     the SPKI-hash logic; reuse it (see guide: expose -isPinnedHost: and
        //     -serverTrust:matchesPinnedSPKIForHost:). PinSetStore adds rotated pins.
        if RASPGuard.shared().isPinnedHost(host) {
            if RASPGuard.shared().serverTrust(trust, matchesPinnedSPKIForHost: host)
                || PinSetStore.matches(trust: trust, host: host) {
                completionHandler(.useCredential, URLCredential(trust: trust))
            } else {
                RASPGuard.shared().reportPinningFailure(forHost: host)
                completionHandler(.cancelAuthenticationChallenge, nil)
            }
            return
        }

        // (3) Non-pinned host: trust was validated above; proceed (no blind accept).
        completionHandler(.useCredential, URLCredential(trust: trust))
    }
}
