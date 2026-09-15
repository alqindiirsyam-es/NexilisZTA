/*
 * EncryptedStrings.h
 * Nexilis iOS ZTA — Deklarasi semua obfuscated string constants
 */

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// The definitions live in EncryptedStrings.mm, compiled as Objective-C++ so ENCRYPTED_NSSTRING
// takes its constexpr path. Without this the compiler would give them C++ linkage and mangle the
// names, while every caller - Swift and Objective-C alike - goes looking for the plain C symbol.
#ifdef __cplusplus
extern "C" {
#endif

// P0 — API Endpoints ZTA
extern NSString *NXEncryptedAPIBaseURL(void);
extern NSString *NXEncryptedChallengeEndpoint(void);
extern NSString *NXEncryptedAttestEndpoint(void);
extern NSString *NXEncryptedRegisterEndpoint(void);
extern NSString *NXEncryptedKeyEndpoint(void);
extern NSString *NXEncryptedRevokeEndpoint(void);

// P1 — Certificate pinning
extern NSString *NXEncryptedPrimaryPin(void);
extern NSString *NXEncryptedBackupPin(void);
extern NSString *NXEncryptedNewUniversePin(void);
extern NSString *NXEncryptedPinRotationSignerSPKI(void);

// P2 — App API key  [baru: F1 fix]
extern NSString *NXEncryptedAPIKey(void);

// P3 — Feature access URL  [baru: F6 fix]
extern NSString *NXEncryptedFeatureAccessURL(void);

// P4 — App App Name [baru: F1 fix]
extern NSString *NXEncryptedAppName(void);

#ifdef __cplusplus
}
#endif

NS_ASSUME_NONNULL_END
