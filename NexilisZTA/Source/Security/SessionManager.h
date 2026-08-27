/*
 * SessionManager.h
 * Nexilis iOS ZTA Bundle V4 — Keychain-backed Session Token Management
 */

#ifndef NEXILIS_SESSION_MANAGER_H
#define NEXILIS_SESSION_MANAGER_H

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SessionManager : NSObject

+ (instancetype)sharedManager;

- (void)storeSessionToken:(NSString *)token expiresAt:(NSDate *)expiry;
- (nullable NSString *)validSessionToken;
@property (nonatomic, readonly) BOOL hasValidSession;

- (void)storeUserAuthToken:(NSString *)jwt;
- (nullable NSString *)userAuthToken;

- (void)clearAll;
@property (nonatomic, readonly, nullable) NSDate *sessionExpiry;

@end

NS_ASSUME_NONNULL_END

#endif
