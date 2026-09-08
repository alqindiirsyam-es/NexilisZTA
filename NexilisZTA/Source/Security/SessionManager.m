/*
 * SessionManager.m
 * Nexilis iOS ZTA Bundle V4 — Keychain-backed Session Token Management
 */

#import "SessionManager.h"
#import <Security/Security.h>

static NSString * const kSessionTokenKey = @"io.nexilis.zta.session";
static NSString * const kSessionExpiryKey = @"io.nexilis.zta.session.expiry";
static NSString * const kUserAuthTokenKey = @"io.nexilis.zta.userauth";

/*
 * The token and its expiry are read on every protected operation - every send, every upload,
 * every TMessage.pack() - and each read used to be two round trips to securityd plus an
 * NSKeyedUnarchiver. One chat message cost roughly six of them. Keychain access is IPC, so that
 * is not free, and it lands on the outgoing thread while a person waits for a message to leave.
 *
 * The values are cached in memory instead. Nothing else writes these items: `keychainSet` is only
 * reached from the two store methods below, and the pod is linked into the app target alone - no
 * extension shares this keychain group - so the cache cannot go stale behind our back. Expiry is
 * still compared against the clock on every call; caching the value never caches the verdict.
 *
 * A cleared session caches the absence too. Without that, the state where there is no token -
 * exactly the state modes 1 and 2 sit in while they are being refused - would go back to the
 * keychain on every single call.
 */
@interface SessionManager () {
    NSString *_cachedToken;
    NSDate *_cachedExpiry;
    BOOL _cacheLoaded;
}
@end

@implementation SessionManager

+ (instancetype)sharedManager {
    static SessionManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ instance = [[SessionManager alloc] init]; });
    return instance;
}

- (void)keychainSet:(NSString *)key value:(NSData *)value {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: key,
        (__bridge id)kSecAttrAccount: @"nexilis",
    };
    SecItemDelete((__bridge CFDictionaryRef)query);

    NSMutableDictionary *add = [query mutableCopy];
    add[(__bridge id)kSecValueData] = value;
    add[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)add, NULL);
    if (status != errSecSuccess) {
        NSLog(@"[Nexilis/Session] Failed to persist key %@ (status=%d)", key, (int)status);
    }
}

- (NSData *)keychainGet:(NSString *)key {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: key,
        (__bridge id)kSecAttrAccount: @"nexilis",
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne,
    };
    CFTypeRef result = NULL;
    if (SecItemCopyMatching((__bridge CFDictionaryRef)query, &result) == errSecSuccess) {
        return (__bridge_transfer NSData *)result;
    }
    return nil;
}

- (void)keychainDelete:(NSString *)key {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: key,
        (__bridge id)kSecAttrAccount: @"nexilis",
    };
    SecItemDelete((__bridge CFDictionaryRef)query);
}

- (void)storeSessionToken:(NSString *)token expiresAt:(NSDate *)expiry {
    NSData *tokenData = [token dataUsingEncoding:NSUTF8StringEncoding];
    [self keychainSet:kSessionTokenKey value:tokenData];

    NSError *archiveError = nil;
    NSData *expiryData = [NSKeyedArchiver archivedDataWithRootObject:expiry
                                              requiringSecureCoding:YES
                                                              error:&archiveError];
    if (expiryData != nil && archiveError == nil) {
        [self keychainSet:kSessionExpiryKey value:expiryData];
    }

    @synchronized (self) {
        _cachedToken = [token copy];
        _cachedExpiry = expiryData != nil && archiveError == nil ? [expiry copy] : nil;
        _cacheLoaded = YES;
    }
}

/// Fills the cache from the keychain once. Caller holds @synchronized(self).
- (void)loadSessionCacheLocked {
    if (_cacheLoaded) return;

    NSData *expiryData = [self keychainGet:kSessionExpiryKey];
    _cachedExpiry = expiryData != nil
        ? [NSKeyedUnarchiver unarchivedObjectOfClass:[NSDate class] fromData:expiryData error:nil]
        : nil;

    NSData *tokenData = [self keychainGet:kSessionTokenKey];
    _cachedToken = tokenData != nil
        ? [[NSString alloc] initWithData:tokenData encoding:NSUTF8StringEncoding]
        : nil;

    _cacheLoaded = YES;
}

- (NSString *)validSessionToken {
    @synchronized (self) {
        [self loadSessionCacheLocked];
        if (_cachedExpiry == nil || [_cachedExpiry timeIntervalSinceNow] <= 0) {
            return nil;
        }
        return _cachedToken;
    }
}

- (BOOL)hasValidSession {
    return [self validSessionToken] != nil;
}

- (NSDate *)sessionExpiry {
    @synchronized (self) {
        [self loadSessionCacheLocked];
        return _cachedExpiry;
    }
}

- (void)storeUserAuthToken:(NSString *)jwt {
    [self keychainSet:kUserAuthTokenKey value:[jwt dataUsingEncoding:NSUTF8StringEncoding]];
}

- (NSString *)userAuthToken {
    NSData *data = [self keychainGet:kUserAuthTokenKey];
    return data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : nil;
}

- (void)clearAll {
    [self keychainDelete:kSessionTokenKey];
    [self keychainDelete:kSessionExpiryKey];
    [self keychainDelete:kUserAuthTokenKey];

    @synchronized (self) {
        _cachedToken = nil;
        _cachedExpiry = nil;
        _cacheLoaded = YES; // the absence is cached too - see the note above the interface
    }
}

@end
