/*
 * RASPGuard.m
 * Nexilis iOS ZTA Bundle V6 — RASP Coordinator Implementation
 *
 * PATCH LOG:
 *   - NSLog threat details → os_log dengan privacy .private (tidak bocor ke Console.app)
 *   - Periodic monitor: tidak lagi terminate lokal — delegate dulu, server yang memutuskan
 *   - [MERGE] Tambah property lastPinnedLeafSPKIHex untuk A.3 channel-binding
 *   - [MERGE] Tambah isPinnedHost:, serverTrust:matchesPinnedSPKIForHost:,
 *             dan reportPinningFailureForHost: sebagai reusable pinning API (A.2)
 */

#import "RASPGuard.h"
#import <CommonCrypto/CommonDigest.h>
#import <Security/Security.h>
#import <UIKit/UIKit.h>
#import <signal.h>
#import <os/log.h>
#import "GlobalState.h"

// Log channel khusus RASP — private agar tidak terbaca di Console.app tanpa entitlement
static os_log_t _rasp_log(void) {
    static os_log_t log = NULL;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        log = os_log_create("io.nexilis.rasp", "guard");
    });
    return log;
}

#ifndef NEXILIS_RASP_TERMINATE_ON_THREAT
#define NEXILIS_RASP_TERMINATE_ON_THREAT 1
#endif

#if NEXILIS_APPSTORE_BUILD && !defined(NEXILIS_ALLOW_INSECURE_RELEASE)
  #if !defined(NEXILIS_EXPECTED_BUNDLE_ID)
    #error "Release build requires NEXILIS_EXPECTED_BUNDLE_ID"
  #endif
  #if !defined(NEXILIS_EXPECTED_APP_ID)
    #error "Release build requires NEXILIS_EXPECTED_APP_ID"
  #endif
  #if !defined(NEXILIS_EXPECTED_TEAM_ID)
    #error "Release build requires NEXILIS_EXPECTED_TEAM_ID"
  #endif
  #if !defined(NEXILIS_EXPECTED_APPATTEST_ENV)
    #error "Release build requires NEXILIS_EXPECTED_APPATTEST_ENV"
  #endif
  #if !defined(NEXILIS_EXPECTED_EXECUTABLE_SHA256)
    #error "Release build requires NEXILIS_EXPECTED_EXECUTABLE_SHA256"
  #endif
#endif

@interface RASPGuard ()
@property (nonatomic, strong, nullable) dispatch_source_t monitorTimer;
@property (nonatomic, copy, nullable) NSString *primaryPin;
@property (nonatomic, copy, nullable) NSString *backupPin;
@property (nonatomic, readwrite) uint32_t lastThreatMask;
@property (nonatomic, readwrite) BOOL deviceClean;
@end

@implementation RASPGuard

+ (instancetype)sharedGuard {
    static RASPGuard *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[RASPGuard alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _monitoringInterval = 30.0;
        _lastThreatMask = RASP_THREAT_NONE;
        _deviceClean = YES;
    }
    return self;
}

static NSString *nx_sha256_hex_for_data(NSData *data) {
    if (data.length == 0) return nil;
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSUInteger i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hex appendFormat:@"%02x", digest[i]];
    }
    return hex;
}

+ (void)install {
    stateSet(NX_STATE_RASP_PREMAIN);
    rasp_deny_debugger_attach();

    RASPGuard *guard = [RASPGuard sharedGuard];
    uint32_t threats = rasp_run_boot_sequence();
    guard.lastThreatMask = threats;
    guard.deviceClean = (threats == RASP_THREAT_NONE);

    if (threats != RASP_THREAT_NONE) {
        // Gunakan os_log private: nilai tidak terbaca di Console.app tanpa entitlement khusus
        os_log_with_type(_rasp_log(), OS_LOG_TYPE_ERROR,
                         "Threats detected at launch: %{private}u", threats);
        return;
    }

    // Status FE 11 — Code Signature & Tamper Verification. Only reachable if
    // the full native chain above completed (GlobalState == 10).
    if (stateGet() != NX_STATE_NATIVE_GOT_HOOK_CHECK || ![guard verifyCodeSignatureIntegrity]) {
        guard.lastThreatMask |= RASP_THREAT_TAMPERED;
        guard.deviceClean = NO;
        os_log_with_type(_rasp_log(), OS_LOG_TYPE_ERROR,
                         "Entitlement/signature mismatch at launch");
        return;
    }
    stateSet(NX_STATE_CODE_SIGNATURE_VERIFY); // -> 11

    // Status FE 12 — fail-closed path is now armed for the remainder of launch.
    stateSet(NX_STATE_FAIL_CLOSED_READY); // -> 12

    // Status FE 15 — Periodic RASP Monitoring. (13/14 — string-obfuscation
    // self-test and certificate-pinning setup — belong to StringEncryptor/
    // EncryptedStrings and AppDelegate respectively; each should call
    // stateSet(NX_STATE_STRING_OBFUSCATION_SELFTEST) / stateSet(NX_STATE_CERT_PINNING_SETUP)
    // the same way once wired in.)
    [guard startMonitoring];
    stateSet(NX_STATE_PERIODIC_MONITORING); // -> 15
}

- (void)startMonitoring {
    if (self.monitorTimer != nil) return;

    dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_UTILITY, 0);
    self.monitorTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);

    uint64_t interval = (uint64_t)(MAX(self.monitoringInterval, 5.0) * NSEC_PER_SEC);
    dispatch_source_set_timer(self.monitorTimer,
                              dispatch_time(DISPATCH_TIME_NOW, interval),
                              interval,
                              NSEC_PER_SEC);

    __weak typeof(self) weakSelf = self;
    dispatch_source_set_event_handler(self.monitorTimer, ^{
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) return;

        uint32_t threats = rasp_run_all_checks();
        strongSelf.lastThreatMask = threats;
        strongSelf.deviceClean = (threats == RASP_THREAT_NONE);

        if (threats != RASP_THREAT_NONE) {
            // CONTROL 4 — Decouple detection dari response:
            // 1. Catat signal secara silent (tanpa nama ancaman spesifik)
            os_log_with_type(_rasp_log(), OS_LOG_TYPE_INFO,
                             "Periodic check: anomaly detected");

            // 2. Notifikasi delegate — delegate WAJIB kirim signal ke server
            //    Server yang memutuskan: step-up auth, limit transaksi, atau degraded session
            //    dengan delay agar tidak bisa ditelusuri ke branch ini
            if ([strongSelf.delegate respondsToSelector:@selector(raspGuard:didDetectThreats:)]) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    [strongSelf.delegate raspGuard:strongSelf didDetectThreats:threats];
                });
            }

            // 3. Terminate lokal HANYA jika tidak ada delegate yang menangani.
            //    Jika delegate sudah diset (AppDelegate melaporkan ke server),
            //    jangan terminate lokal — biarkan server yang memutuskan.
            //
            //    Untuk app yang belum punya server-side adjudication,
            //    aktifkan NEXILIS_RASP_TERMINATE_ON_THREAT sementara.
#if NEXILIS_RASP_TERMINATE_ON_THREAT
            if (![strongSelf.delegate respondsToSelector:@selector(raspGuard:didDetectThreats:)]) {
                // Same generic alert format as the boot-sequence failures,
                // using the Periodic RASP Monitoring row's errcode (Status FE 15).
            }
#endif
        }
    });

    dispatch_resume(self.monitorTimer);
}

- (void)stopMonitoring {
    if (self.monitorTimer != nil) {
        dispatch_source_cancel(self.monitorTimer);
        self.monitorTimer = nil;
    }
}

- (uint32_t)runChecksNow {
    uint32_t threats = rasp_run_all_checks();
    self.lastThreatMask = threats;
    self.deviceClean = (threats == RASP_THREAT_NONE);
    return threats;
}

- (BOOL)verifyCodeSignatureIntegrity {
    BOOL ok = YES;

#ifdef NEXILIS_EXPECTED_BUNDLE_ID
    NSString *bundleId = [[NSBundle mainBundle] bundleIdentifier] ?: @"";
    ok = ok && [bundleId isEqualToString:@NEXILIS_EXPECTED_BUNDLE_ID];
#endif

#ifdef NEXILIS_EXPECTED_APP_ID
    CFErrorRef appIdError = NULL;
    CFTypeRef appIdValue = SecTaskCopyValueForEntitlement(task,
                                                          CFSTR("application-identifier"),
                                                          &appIdError);
    if (appIdValue == NULL || CFGetTypeID(appIdValue) != CFStringGetTypeID()) {
        ok = NO;
    } else {
        NSString *actual = (__bridge NSString *)appIdValue;
        ok = ok && [actual isEqualToString:@NEXILIS_EXPECTED_APP_ID];
    }
    if (appIdValue) CFRelease(appIdValue);
    if (appIdError) CFRelease(appIdError);
#endif

#ifdef NEXILIS_EXPECTED_TEAM_ID
    CFErrorRef teamError = NULL;
    CFTypeRef teamValue = SecTaskCopyValueForEntitlement(task,
                                                         CFSTR("com.apple.developer.team-identifier"),
                                                         &teamError);
    if (teamValue == NULL || CFGetTypeID(teamValue) != CFStringGetTypeID()) {
        ok = NO;
    } else {
        NSString *actual = (__bridge NSString *)teamValue;
        ok = ok && [actual isEqualToString:@NEXILIS_EXPECTED_TEAM_ID];
    }
    if (teamValue) CFRelease(teamValue);
    if (teamError) CFRelease(teamError);
#endif

#ifdef NEXILIS_EXPECTED_APPATTEST_ENV
    CFErrorRef envError = NULL;
    CFTypeRef envValue = SecTaskCopyValueForEntitlement(task,
                                                        CFSTR("com.apple.developer.devicecheck.appattest-environment"),
                                                        &envError);
    if (envValue == NULL || CFGetTypeID(envValue) != CFStringGetTypeID()) {
        ok = NO;
    } else {
        NSString *actual = (__bridge NSString *)envValue;
        ok = ok && [actual isEqualToString:@NEXILIS_EXPECTED_APPATTEST_ENV];
    }
    if (envValue) CFRelease(envValue);
    if (envError) CFRelease(envError);
#endif

#ifdef NEXILIS_EXPECTED_EXECUTABLE_SHA256
    NSString *executablePath = [[NSBundle mainBundle] executablePath];
    NSData *executableData = executablePath.length > 0 ? [NSData dataWithContentsOfFile:executablePath options:NSDataReadingMappedIfSafe error:nil] : nil;
    NSString *actualExecutableHash = nx_sha256_hex_for_data(executableData);
    if (actualExecutableHash.length == 0) {
        ok = NO;
    } else {
        ok = ok && [actualExecutableHash caseInsensitiveCompare:@NEXILIS_EXPECTED_EXECUTABLE_SHA256] == NSOrderedSame;
    }
#endif

    return ok;
}

- (void)configurePinningWithPrimaryPin:(NSString *)primaryPin backupPin:(NSString *)backupPin {
    self.primaryPin = [primaryPin copy];
    self.backupPin = [backupPin copy];
}

// A.2 — reusable pinning API (used by PinnedURLSessionDelegate)
- (BOOL)isPinnedHost:(NSString *)host {
    if (!host.length) return NO;
    // Pin semua host ZTA dan banking domain
    NSArray *pinnedSuffixes = @[@"newuniverse.io", @"nexilis.io"];
    for (NSString *suffix in pinnedSuffixes) {
        if ([host isEqualToString:suffix] || [host hasSuffix:[@"." stringByAppendingString:suffix]]) {
            return YES;
        }
    }
    return NO;
}

- (BOOL)serverTrust:(SecTrustRef)trust matchesPinnedSPKIForHost:(NSString *)host {
    if (trust == NULL) return NO;
    SecKeyRef serverKey = SecTrustCopyKey(trust);
    if (serverKey == NULL) return NO;
    NSData *spki = nx_spki_for_key(serverKey);
    CFRelease(serverKey);
    if (spki == nil) return NO;

    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(spki.bytes, (CC_LONG)spki.length, hash);
    NSData *hashData = [NSData dataWithBytes:hash length:CC_SHA256_DIGEST_LENGTH];
    NSString *serverPin = [NSString stringWithFormat:@"sha256/%@",
                           [hashData base64EncodedStringWithOptions:0]];

    // A.3 — store for channel-binding in AppAttestManager
    self.lastPinnedLeafSPKIHex = serverPin;

    return (self.primaryPin.length > 0 && [serverPin isEqualToString:self.primaryPin])
        || (self.backupPin.length  > 0 && [serverPin isEqualToString:self.backupPin]);
}

- (void)reportPinningFailureForHost:(NSString *)host {
    os_log_with_type(_rasp_log(), OS_LOG_TYPE_ERROR,
                     "Certificate pinning failure for host: %{private}@", host);
    // Signal ke delegate → server adjudication
    self.lastThreatMask |= RASP_THREAT_TAMPERED;
    if ([self.delegate respondsToSelector:@selector(raspGuard:didDetectThreats:)]) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.delegate raspGuard:self didDetectThreats:RASP_THREAT_TAMPERED];
        });
    }
}

static NSData *nx_spki_for_key(SecKeyRef key) {
    if (key == NULL) return nil;
    NSDictionary *attrs = CFBridgingRelease(SecKeyCopyAttributes(key));
    NSData *rawData = CFBridgingRelease(SecKeyCopyExternalRepresentation(key, NULL));
    if (attrs == nil || rawData == nil) return nil;

    NSString *keyType = attrs[(__bridge id)kSecAttrKeyType];
    NSNumber *bitsNumber = attrs[(__bridge id)kSecAttrKeySizeInBits];
    size_t bits = (size_t)[bitsNumber unsignedIntegerValue];

    NSMutableData *spki = [NSMutableData data];
    if ([keyType isEqualToString:(__bridge NSString *)kSecAttrKeyTypeECSECPrimeRandom]) {
        const uint8_t *algoPrefix = NULL;
        size_t algoPrefixLen = 0;
        if (bits == 256) {
            static const uint8_t kPrefix[] = {
                0x30,0x59,0x30,0x13,0x06,0x07,0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,
                0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07,0x03,0x42,0x00
            };
            algoPrefix = kPrefix;
            algoPrefixLen = sizeof(kPrefix);
        } else if (bits == 384) {
            static const uint8_t kPrefix[] = {
                0x30,0x76,0x30,0x10,0x06,0x07,0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,
                0x06,0x05,0x2B,0x81,0x04,0x00,0x22,0x03,0x62,0x00
            };
            algoPrefix = kPrefix;
            algoPrefixLen = sizeof(kPrefix);
        } else {
            return nil;
        }
        [spki appendBytes:algoPrefix length:algoPrefixLen];
        [spki appendData:rawData];
        return spki;
    }

    if ([keyType isEqualToString:(__bridge NSString *)kSecAttrKeyTypeRSA]) {
        NSUInteger rsaLen = rawData.length;
        if (rsaLen > 0xFFFF) return nil;

        NSMutableData *bitString = [NSMutableData data];
        uint8_t zero = 0x00;
        [bitString appendBytes:&zero length:1];
        [bitString appendData:rawData];

        NSMutableData *algo = [NSMutableData dataWithBytes:(const uint8_t[]){
            0x30,0x0D,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01,0x05,0x00
        } length:15];

        uint8_t lenBytes[3] = {0};
        NSUInteger bitStringLen = bitString.length;
        NSMutableData *bitStringDer = [NSMutableData dataWithBytes:(const uint8_t[]){0x03} length:1];
        if (bitStringLen < 128) {
            uint8_t l = (uint8_t)bitStringLen;
            [bitStringDer appendBytes:&l length:1];
        } else {
            lenBytes[0] = 0x82;
            lenBytes[1] = (uint8_t)((bitStringLen >> 8) & 0xFF);
            lenBytes[2] = (uint8_t)(bitStringLen & 0xFF);
            [bitStringDer appendBytes:lenBytes length:3];
        }
        [bitStringDer appendData:bitString];

        NSUInteger seqLen = algo.length + bitStringDer.length;
        [spki appendBytes:(const uint8_t[]){0x30} length:1];
        if (seqLen < 128) {
            uint8_t l = (uint8_t)seqLen;
            [spki appendBytes:&l length:1];
        } else {
            lenBytes[0] = 0x82;
            lenBytes[1] = (uint8_t)((seqLen >> 8) & 0xFF);
            lenBytes[2] = (uint8_t)(seqLen & 0xFF);
            [spki appendBytes:lenBytes length:3];
        }
        [spki appendData:algo];
        [spki appendData:bitStringDer];
        return spki;
    }

    return nil;
}

- (NSURLSession *)pinnedURLSession {
    NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    config.timeoutIntervalForRequest = 15.0;
    config.timeoutIntervalForResource = 30.0;
    if (@available(iOS 13.0, *)) {
        config.TLSMinimumSupportedProtocolVersion = tls_protocol_version_TLSv12;
    }
    return [NSURLSession sessionWithConfiguration:config delegate:self delegateQueue:nil];
}

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler {

    if (![challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
        return;
    }

    SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
    if (serverTrust == NULL) {
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        return;
    }

    if (@available(iOS 13.0, *)) {
        if (!SecTrustEvaluateWithError(serverTrust, NULL)) {
            completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
            return;
        }
    } else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        SecTrustResultType result = kSecTrustResultInvalid;
        if (SecTrustEvaluate(serverTrust, &result) != errSecSuccess ||
            (result != kSecTrustResultProceed && result != kSecTrustResultUnspecified)) {
            completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
            return;
        }
#pragma clang diagnostic pop
    }

#if NEXILIS_APPSTORE_BUILD && !defined(NEXILIS_ALLOW_INSECURE_RELEASE)
    if (self.primaryPin.length == 0 && self.backupPin.length == 0) {
        if ([self.delegate respondsToSelector:@selector(raspGuard:didDetectPinningFailureForHost:)]) {
            NSString *host = challenge.protectionSpace.host ?: @"<unknown>";
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.delegate raspGuard:self didDetectPinningFailureForHost:host];
            });
        }
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        return;
    }
#else
    if (self.primaryPin.length == 0 && self.backupPin.length == 0) {
        completionHandler(NSURLSessionAuthChallengeUseCredential,
                          [NSURLCredential credentialForTrust:serverTrust]);
        return;
    }
#endif

    SecKeyRef serverKey = SecTrustCopyKey(serverTrust);
    NSData *spki = nx_spki_for_key(serverKey);
    if (serverKey != NULL) CFRelease(serverKey);
    if (spki == nil) {
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        return;
    }

    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(spki.bytes, (CC_LONG)spki.length, hash);
    NSData *hashData = [NSData dataWithBytes:hash length:CC_SHA256_DIGEST_LENGTH];
    NSString *serverPin = [NSString stringWithFormat:@"sha256/%@", [hashData base64EncodedStringWithOptions:0]];

    BOOL pinMatch = (self.primaryPin.length > 0 && [serverPin isEqualToString:self.primaryPin]) ||
                    (self.backupPin.length > 0 && [serverPin isEqualToString:self.backupPin]);
    if (pinMatch) {
        completionHandler(NSURLSessionAuthChallengeUseCredential,
                          [NSURLCredential credentialForTrust:serverTrust]);
        return;
    }

    if ([self.delegate respondsToSelector:@selector(raspGuard:didDetectPinningFailureForHost:)]) {
        NSString *host = challenge.protectionSpace.host ?: @"<unknown>";
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.delegate raspGuard:self didDetectPinningFailureForHost:host];
        });
    }
    completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
}

- (void)dealloc {
    [self stopMonitoring];
}

@end
