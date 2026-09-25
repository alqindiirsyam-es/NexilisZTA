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

/* Bootstrap user authentication (Sentinel v3.0.1): the short-lived credential the service
 * issued after the institution's IdP assertion was consumed. Required for /key when the host
 * configured a bootstrapAuthentication provider; cleared with everything else on clearAll. */
- (void)storeUserAuthToken:(NSString *)jwt expiresAt:(NSDate *)expiry;
- (nullable NSString *)validUserAuthToken;
@property (nonatomic, readonly) BOOL hasValidUserAuth;
- (void)clearUserAuth;
/* Legacy, expiry-less form. Kept for callers that stored one; nothing in the chain reads it. */
- (void)storeUserAuthToken:(NSString *)jwt;
- (nullable NSString *)userAuthToken;

- (void)clearAll;
@property (nonatomic, readonly, nullable) NSDate *sessionExpiry;

@end

NS_ASSUME_NONNULL_END

#endif
