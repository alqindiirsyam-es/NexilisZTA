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

// The rotation successor for the ZTA host, and the reason the pin set is survivable.
//
// It is NOT a second pin for the certificate that is live today. It is the SPKI of an independent
// RSA-2048 key that has never been used for a certificate and is held offline, so that when the
// live key has to be replaced - a renewal with a fresh key, a compromise, a CA change - a
// certificate is issued for THIS key and every installed client already trusts it. A pin set whose
// only entry is the key currently in use is a pin set that cannot be rotated: the day that key
// changes, every install refuses the connection with no click-through, and the only recovery is an
// App Store release.
//
// Two properties it must keep, both load-bearing:
//
//   - Independent of the primary, and enforced: the hardened path refuses to verify at all unless
//     both pins are non-empty AND different - APISZTA.swift:842, error -7002 "Sentinel requires
//     distinct primary and backup SPKI pins." That guard sits after the `.regular` path has
//     already returned, so an empty value here hard-blocked app modes 1 and 2 outright; it is not
//     a warning anybody could ship past. (`-pinningConfigured`, RASPGuard.m:386, applies the same
//     test but only reports it through EnvironmentReport - it gates nothing.) Copying the primary
//     here passes neither, and rotates nothing.
//   - Unused until needed. Its value is that an attacker who takes the live key has not taken
//     this one. That holds only while the private key stays offline and off the server.
//
// The private key lives in SentinelOfflineKeys/nexilis-io-backup.key - gitignored, and it must be
// archived somewhere that survives this checkout. Losing it does not break anything today and
// makes this pin worthless on the day it is needed, which is the worst possible time to find out.
NSString *NXEncryptedBackupPin(void) {
    return ENCRYPTED_NSSTRING("sha256/2yiz66qtHnwP51ZYQwkOuua9dQTCxVcoqN/KR+z+ySI=");
}

// P1b — public half of the offline pin-rotation signer
//
// Pins can also arrive at runtime, signed: `/zta/status/verify` carries `pin_rotation_payload` and
// `pin_rotation_sig`, and PinSetStore verifies the signature against this key before it accepts a
// single SPKI (SecuritySupport.swift:134). The server is a courier, not an authority - it holds no
// signing key and cannot mint a pin, only withhold or replay one.
//
// While this was nil the whole mechanism was dead code: `verify()` returns false on an absent
// signer, so every rotation payload was rejected and the compiled-in primary/backup pair was the
// entire pin set for good. That is what made the certificate renewal a hard deadline rather than a
// routine operation. At app mode 1 a release build did not even launch past it - APISZTA.swift:849
// refuses with -7006 unless a signer of at least 65 bytes is configured.
//
// Full 91-byte P-256 SubjectPublicKeyInfo DER, base64. `verify()` takes the last 65 bytes and
// requires the uncompressed-point marker 0x04, so the SPKI DER and a bare point both parse; the
// DER is used because that is what `openssl ec -pubout -outform der` emits and there is no reason
// to hand-trim it.
//
// Private key: SentinelOfflineKeys/pin-rotation-signer.key. It must NEVER be deployed to the
// server - the design's whole claim is that a compromised server cannot mint pins, and a signing
// key sitting next to PIN_ROTATION_PATH gives that claim away.
NSString *NXEncryptedPinRotationSignerSPKI(void) {
    return ENCRYPTED_NSSTRING("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8rY3cC/tO+gamiXgagrFQROT6lhCK+klEMtECQpaPtT05DM64Ywv90EuelD7Wq365/SiR34bDeH4gLx1v+F/mg==");
}

// The second first-party domain. It is not the ZTA host, so it is not covered by the
// primary/backup floor above - that pair is one host's key and its rotation successor, not a
// list of every domain the app talks to. Installed hosts have always pinned this separately;
// dropping it would refuse every connection they make to it.
NSString *NXEncryptedNewUniversePin(void) {
    return ENCRYPTED_NSSTRING("sha256/XFRSd92XlkDObEZQZnAC8eULRrmHCTW4prdwSBYr/N4=");
}

NSString *NXEncryptedAppName(void) {
    return ENCRYPTED_NSSTRING("OneApp");
}

// P2 — App API key  [F1: dipindahkan dari AppDelegate.swift]
//
// The value is injected at build time and never committed: see SentinelAppSecrets.xcconfig.example.
// It has to reach the **NexilisZTA pod target**, because that is where this file is compiled -
// injecting it into the host app's target alone defines it for code that never asks for it.
//
// NX-20 removed a hardcoded 64-hex fallback from here, which was right, and replaced it with an
// empty string, which was only half the job. An empty API key is not a safe default: the app
// builds, App Attest passes, and the first thing the backend is asked reads as an unknown client -
// UCPaaS answers SUA01 with ERRCOD 2b, the client reports "please check your connection", and
// nothing in that chain names the actual cause. A quiet fallback again, exactly the failure mode
// StringEncryptor.h refuses to allow for the XOR keys.
//
// So a hardened build now fails to compile rather than ship without one, and a development build
// says so at runtime instead of leaving the reader to work backwards from a backend error code.
#if defined(NEXILIS_RELEASE_HARDENING) && !defined(NEXILIS_API_KEY_VALUE)
# error "Release hardening requires NEXILIS_API_KEY_VALUE injected at build time (see SentinelAppSecrets.xcconfig.example). Without it NXEncryptedAPIKey() is empty and every backend sign-in is refused."
#endif

#ifdef NEXILIS_API_KEY_VALUE
NSString *NXEncryptedAPIKey(void) {
    return ENCRYPTED_NSSTRING(NEXILIS_API_KEY_VALUE);
}
#else
NSString *NXEncryptedAPIKey(void) {
    // Unreachable in a hardened build - the #error above stops it. Reachable in development, and
    // loud there on purpose: this is the difference between ten minutes and an afternoon.
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSLog(@"[Nexilis] WARNING: NEXILIS_API_KEY_VALUE was not injected, so the app API key is "
              @"empty. Backend sign-in (SUA01) will be refused and preferences will never arrive. "
              @"Copy SentinelAppSecrets.xcconfig.example, fill in the key, and rebuild.");
    });
    // A client-embedded fallback must never become an authentication credential.
    return @"";
}
#endif

// P3 — Feature access URL  [F6: dipindahkan dari AppDelegate.swift]
NSString *NXEncryptedFeatureAccessURL(void) {
    return ENCRYPTED_NSSTRING("https://nexilis.io/get_feature_access_zta");
}
