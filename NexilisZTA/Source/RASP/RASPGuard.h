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

/* A.3 — last leaf SPKI hex for channel-binding in AppAttestManager */
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
