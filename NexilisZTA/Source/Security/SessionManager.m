/*
 * SessionManager.m
 * Nexilis iOS ZTA Bundle V4 — Keychain-backed Session Token Management
 */

#import "SessionManager.h"
#import <Security/Security.h>

static NSString * const kSessionTokenKey = @"io.nexilis.zta.session";
static NSString * const kSessionExpiryKey = @"io.nexilis.zta.session.expiry";
static NSString * const kUserAuthTokenKey = @"io.nexilis.zta.userauth";

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
}

- (NSString *)validSessionToken {
    NSDate *expiry = self.sessionExpiry;
    if (expiry == nil || [expiry timeIntervalSinceNow] <= 0) {
        return nil;
    }
    NSData *data = [self keychainGet:kSessionTokenKey];
    return data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : nil;
}

- (BOOL)hasValidSession {
    return [self validSessionToken] != nil;
}

- (NSDate *)sessionExpiry {
    NSData *data = [self keychainGet:kSessionExpiryKey];
    if (data == nil) return nil;
    return [NSKeyedUnarchiver unarchivedObjectOfClass:[NSDate class] fromData:data error:nil];
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
}

@end
