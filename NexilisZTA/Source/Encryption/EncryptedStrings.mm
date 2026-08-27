/*
 * EncryptedStrings.mm   ← PENTING: ekstensi .mm agar ENCRYPTED_NSSTRING() berjalan constexpr
 *
 * CATATAN UNTUK TIM:
 *   File ini harus dikompilasi sebagai Objective-C++ (.mm).
 *   Di Xcode: pilih file → Identity Inspector → Type = "Objective-C++ Source"
 *   atau rename file ini dari .m ke .mm di project navigator.
 *
 * Perubahan dari versi .m:
 *   - Tambah NXEncryptedAPIKey()          ← F1 fix: pindahkan apikey dari AppDelegate
 *   - Tambah NXEncryptedFeatureAccessURL() ← F6 fix: URL get_feature_access_zta
 */

#import "StringEncryptor.h"
#import "EncryptedStrings.h"

// P0 — API Endpoints ZTA
NSString *NXEncryptedAPIBaseURL(void) {
    return ENCRYPTED_NSSTRING("https://nexilis.io/zta-ios/");
}

NSString *NXEncryptedChallengeEndpoint(void) {
    return ENCRYPTED_NSSTRING("https://nexilis.io/zta-ios/zta/challenge");
}

NSString *NXEncryptedAttestEndpoint(void) {
    return ENCRYPTED_NSSTRING("https://nexilis.io/zta-ios/zta/attest");
}

NSString *NXEncryptedAssertEndpoint(void) {
    return ENCRYPTED_NSSTRING("https://nexilis.io/zta-ios/zta/assert");
}

NSString *NXEncryptedStatusVerifyEndpoint(void) {
    return ENCRYPTED_NSSTRING("https://nexilis.io/zta-ios/zta/status/verify");
}

NSString *NXEncryptedRegisterEndpoint(void) {
    return ENCRYPTED_NSSTRING("https://nexilis.io/zta-ios/zta/register");
}

NSString *NXEncryptedKeyEndpoint(void) {
    return ENCRYPTED_NSSTRING("https://nexilis.io/zta-ios/zta/key");
}

NSString *NXEncryptedRevokeEndpoint(void) {
    return ENCRYPTED_NSSTRING("https://nexilis.io/zta-ios/zta/revoke");
}

// P1 — Certificate pinning
NSString *NXEncryptedPrimaryPin(void) {
    return ENCRYPTED_NSSTRING("sha256/tIAA8SPvbLBRxOAeQYkymqN3MhVpPuJFAbfLxihiMAU="); //XFRSd92XlkDObEZQZnAC8eULRrmHCTW4prdwSBYr/N4=
}

NSString *NXEncryptedBackupPin(void) {
    return ENCRYPTED_NSSTRING("sha256/tIAA8SPvbLBRxOAeQYkymqN3MhVpPuJFAbfLxihiMAU=");
}

NSString *NXEncryptedAppName(void) {
    return ENCRYPTED_NSSTRING("OneApp");
}

// P2 — App API key  [F1: dipindahkan dari AppDelegate.swift]
// PRODUKSI: nilai ini seharusnya di-inject via CI/CD environment variable
// dan tidak di-commit ke repository dalam bentuk plaintext.
// Cara inject: -DNEXILIS_API_KEY_VALUE=\"$(API_KEY_ENV)\" di Build Settings → Other C Flags
#ifdef NEXILIS_API_KEY_VALUE
NSString *NXEncryptedAPIKey(void) {
    return ENCRYPTED_NSSTRING(NEXILIS_API_KEY_VALUE);
}
#else
NSString *NXEncryptedAPIKey(void) {
    // Fallback untuk debug build — nilai placeholder
    return ENCRYPTED_NSSTRING("38747683290F62E9667A018F490396EAE47BC16ADECD85B7E865C733E6DBD6A2");
}
#endif

// P3 — Feature access URL  [F6: dipindahkan dari AppDelegate.swift]
NSString *NXEncryptedFeatureAccessURL(void) {
    return ENCRYPTED_NSSTRING("https://nexilis.io/get_feature_access_zta");
}
