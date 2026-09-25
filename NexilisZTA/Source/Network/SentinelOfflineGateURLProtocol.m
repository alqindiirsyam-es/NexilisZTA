//
//  SentinelOfflineGateURLProtocol.m
//  Nexilis iOS ZTA — Barrier #1 network gate
//
#import "SentinelOfflineGateURLProtocol.h"
#import "RASPGuard.h"

NSString *const NXOfflineGateErrorDomain = @"io.nexilis.zta.preflight";
NSInteger const NXOfflineGateErrorCode = -7401;

@implementation SentinelOfflineGateURLProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    // Claim the request only while the latch is closed. Open latch: decline, and the session's
    // other protocols - the real ones - take it.
    return ![RASPGuard sharedGuard].offlinePreflightPassed;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

- (void)startLoading {
    NSError *error = [NSError errorWithDomain:NXOfflineGateErrorDomain
                                         code:NXOfflineGateErrorCode
                                     userInfo:@{NSLocalizedDescriptionKey:
                                                    @"Sentinel networking is locked until the offline security preflight passes."}];
    [self.client URLProtocol:self didFailWithError:error];
}

- (void)stopLoading {}

@end
