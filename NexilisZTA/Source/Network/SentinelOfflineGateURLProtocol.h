//
//  SentinelOfflineGateURLProtocol.h
//  Nexilis iOS ZTA — Barrier #1: the network stays shut until the offline preflight passes
//
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Installed at the front of every SDK URLSession configuration (RASPGuard's pinned session, the
/// feature-access session, the RIL transport). While RASPGuard's offline-preflight latch is closed
/// it claims every request and fails it with NXOfflineGateErrorCode; once the latch is open it
/// declines, and the normal HTTPS stack serves the request. A code path that reaches the network
/// before the preflight - a future one, or a host driving the steps by hand - is stopped here
/// rather than trusted to have checked.
@interface SentinelOfflineGateURLProtocol : NSURLProtocol
@end

FOUNDATION_EXPORT NSString *const NXOfflineGateErrorDomain;
FOUNDATION_EXPORT NSInteger const NXOfflineGateErrorCode;

NS_ASSUME_NONNULL_END
