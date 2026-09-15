/*
 * RASPGuard.h
 * Nexilis iOS ZTA Bundle V4 — RASP Coordinator
 */

#ifndef NEXILIS_RASP_GUARD_H
#define NEXILIS_RASP_GUARD_H

#import <Foundation/Foundation.h>
#import "rasp_native.h"

NS_ASSUME_NONNULL_BEGIN

@class RASPGuard;

@protocol RASPGuardDelegate <NSObject>
@optional
- (void)raspGuard:(RASPGuard *)guard didDetectThreats:(uint32_t)threats;
- (void)raspGuard:(RASPGuard *)guard didDetectPinningFailureForHost:(NSString *)host;
@end

@interface RASPGuard : NSObject <NSURLSessionDelegate>

+ (instancetype)sharedGuard;
+ (void)install;

- (void)configurePinningWithPrimaryPin:(nullable NSString *)primaryPin
                             backupPin:(nullable NSString *)backupPin;
- (void)configureAdditionalPins:(NSArray<NSString *> *)pins forHost:(NSString *)host;
/// Compiled-in pins for first-party hosts that are not the ZTA host. Kept apart from the rotation
/// pins above, which a signed payload replaces wholesale.
- (void)configureHostPinFloor:(NSDictionary<NSString *, NSArray<NSString *> *> *)pinsByHost;
- (void)configureExpectedBundleID:(NSString *)bundleID
                     applicationID:(NSString *)applicationID
                            teamID:(NSString *)teamID
              appAttestEnvironment:(NSString *)environment;
- (void)startMonitoring;
/// Re-evaluates a launch-time finding until it clears, without running the response path.
- (void)startRecoveryReevaluation;
- (void)stopMonitoring;
- (BOOL)verifyCodeSignatureIntegrity;
- (uint32_t)runChecksNow;
- (NSURLSession *)pinnedURLSession;

/* A.2 — reusable pinning API for PinnedURLSessionDelegate */
- (BOOL)isPinnedHost:(NSString *)host;
- (BOOL)serverTrust:(SecTrustRef)trust matchesPinnedSPKIForHost:(NSString *)host;
- (void)reportPinningFailureForHost:(NSString *)host;

/*
 * A.3 — channel binding: the pinned leaf this process actually reached a given host over.
 *
 * Ask for the host the request is about to go to. The answer is what that host's certificate
 * hashed to on the most recent connection that passed pinning, so it describes the channel the
 * request will travel, and it stays the same for that host across the life of the certificate.
 *
 * `lastPinnedLeafSPKIHex` is the same value for whichever host connected last, whatever host that
 * was. This library pins several — the ZTA service and the operator domain among them — so the
 * moment anything else makes a pinned request, that property stops describing the ZTA channel.
 * It is kept for diagnostics and for hosts already reading it; nothing that binds a request to a
 * channel should use it. Use `-pinnedLeafSPKIForHost:` instead.
 */
- (nullable NSString *)pinnedLeafSPKIForHost:(NSString *)host;
- (nullable NSString *)pinnedLeafSPKIForEndpoint:(nullable NSString *)endpoint;
@property (nonatomic, copy, nullable) NSString *lastPinnedLeafSPKIHex;

@property (nonatomic, assign) NSTimeInterval monitoringInterval;
@property (nonatomic, weak, nullable) id<RASPGuardDelegate> delegate;
@property (nonatomic, readonly) uint32_t lastThreatMask;
@property (nonatomic, readonly) BOOL deviceClean;
@property (nonatomic, readonly) BOOL pinningConfigured;
@property (nonatomic, readonly) BOOL releaseIdentityConfigured;

@end

NS_ASSUME_NONNULL_END

#endif /* NEXILIS_RASP_GUARD_H */
