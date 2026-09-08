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
#import "SessionManager.h"
#import "NXSecurityPolicy.h"
#import <stdatomic.h>

// Log channel khusus RASP — private agar tidak terbaca di Console.app tanpa entitlement
static NSData *nx_spki_for_key(SecKeyRef key);

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


@interface RASPGuard ()
@property (nonatomic, strong, nullable) dispatch_source_t monitorTimer;
@property (nonatomic, strong, nullable) dispatch_source_t recoveryTimer;
@property (nonatomic, copy, nullable) NSString *primaryPin;
@property (nonatomic, copy, nullable) NSString *backupPin;
@property (nonatomic, copy) NSDictionary<NSString *, NSArray<NSString *> *> *additionalPinsByHost;
@property (nonatomic, copy) NSDictionary<NSString *, NSArray<NSString *> *> *hostPinFloor;
@property (nonatomic, copy, nullable) NSString *expectedBundleID;
@property (nonatomic, copy, nullable) NSString *expectedApplicationID;
@property (nonatomic, copy, nullable) NSString *expectedTeamID;
@property (nonatomic, copy, nullable) NSString *expectedAppAttestEnvironment;
@property (nonatomic, readwrite) uint32_t lastThreatMask;
@property (nonatomic, readwrite) BOOL deviceClean;
@end

/*
 * The verdict is written by the launch checks, the periodic sweep, the recovery re-check and the
 * pinning delegate - four different threads - and read from every protected operation the host
 * performs. Synthesised accessors, atomic or not, cannot make `mask |= FLAG` safe either: that is
 * a read, a modify and a write, and a sweep landing between them drops the flag. Explicit atomics
 * throughout, with a fetch_or for the flag case.
 */
@implementation RASPGuard {
    _Atomic(uint32_t) _atomicThreatMask;
    _Atomic(bool) _atomicDeviceClean;
}

- (uint32_t)lastThreatMask { return atomic_load(&_atomicThreatMask); }
- (void)setLastThreatMask:(uint32_t)mask { atomic_store(&_atomicThreatMask, mask); }
- (BOOL)deviceClean { return atomic_load(&_atomicDeviceClean) ? YES : NO; }
- (void)setDeviceClean:(BOOL)clean { atomic_store(&_atomicDeviceClean, clean ? true : false); }

/// Adds a flag without losing one a concurrent writer set at the same moment.
- (void)raiseThreatFlag:(uint32_t)flag {
    atomic_fetch_or(&_atomicThreatMask, flag);
    atomic_store(&_atomicDeviceClean, false);
}

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
        atomic_store(&_atomicThreatMask, RASP_THREAT_NONE);
        atomic_store(&_atomicDeviceClean, true);
        _additionalPinsByHost = @{};
        _hostPinFloor = @{};
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
        os_log_with_type(_rasp_log(), OS_LOG_TYPE_ERROR,
                         "Threats detected at launch: %{private}u", threats);
        // At .regular the finding is recorded and left to the host's own SecurityShield policy,
        // which the service configures. .hsa and .middle end the session over it.
        if ([NXSecurityPolicy revokesOnRuntimeThreat]) {
            [[SessionManager sharedManager] clearAll];
            [[NSNotificationCenter defaultCenter] postNotificationName:@"io.nexilis.zta.runtimeCompromise"
                                                                object:nil
                                                              userInfo:@{@"threat_mask": @(threats)}];
            // Without this a launch-time finding is a life sentence. The return below skips the
            // progression that arms the periodic sweep, so nothing ever re-runs the checks:
            // deviceClean stays NO for the life of the process, and at modes 1 and 2 that means
            // every protected call is refused until the app is killed - including long after a
            // false positive has gone away. Mode 3 is left exactly as it was: it does not consult
            // deviceClean for authorization, so it has nothing to recover.
            [guard startRecoveryReevaluation];
        }
        return;
    }

    // Status FE 11 — Native chain is complete. If compile-time identity expectations are
    // supplied, verify them pre-main; otherwise APISZTA configures and verifies the identity
    // before any authorization can be issued.
    if (stateGet() != NX_STATE_NATIVE_GOT_HOOK_CHECK) {
        [guard raiseThreatFlag:RASP_THREAT_TAMPERED];
        return;
    }
#if defined(NEXILIS_EXPECTED_BUNDLE_ID) && defined(NEXILIS_EXPECTED_APP_ID) && defined(NEXILIS_EXPECTED_TEAM_ID) && defined(NEXILIS_EXPECTED_APPATTEST_ENV)
    [guard configureExpectedBundleID:@NEXILIS_EXPECTED_BUNDLE_ID
                       applicationID:@NEXILIS_EXPECTED_APP_ID
                              teamID:@NEXILIS_EXPECTED_TEAM_ID
                appAttestEnvironment:@NEXILIS_EXPECTED_APPATTEST_ENV];
    if (![guard verifyCodeSignatureIntegrity]) {
        [guard raiseThreatFlag:RASP_THREAT_TAMPERED];
        os_log_with_type(_rasp_log(), OS_LOG_TYPE_ERROR, "Entitlement/signature mismatch at launch");
        return;
    }
#endif
    stateSet(NX_STATE_CODE_SIGNATURE_VERIFY); // -> 11; runtime identity gate still runs in APISZTA

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

/// Re-evaluates a launch-time finding until it clears.
///
/// It deliberately does NOT run the response path. Revoking, notifying and terminating belong to
/// a finding that appears during a session that was previously clean; here there is no session to
/// revoke, and a device that is still dirty has not got worse. Running the response path from
/// here would turn "mode 1 refuses to authorize on this device" into "mode 1 aborts the process
/// 30 seconds after launch", which is a crash where today there is none.
///
/// When the device does read clean it completes the flow-state progression the launch path
/// skipped - AppAttestService refuses to configure below NX_STATE_PERIODIC_MONITORING, so
/// clearing deviceClean alone would not be enough to let the chain start - hands over to the
/// normal sweep, and stops itself.
- (void)startRecoveryReevaluation {
    if (self.recoveryTimer != nil || self.monitorTimer != nil) return;

    dispatch_queue_t queue = dispatch_queue_create("io.nexilis.zta.rasp.recovery", DISPATCH_QUEUE_SERIAL);
    self.recoveryTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);
    if (self.recoveryTimer == nil) return;

    uint64_t interval = (uint64_t)(self.monitoringInterval * NSEC_PER_SEC);
    dispatch_source_set_timer(self.recoveryTimer,
                              dispatch_time(DISPATCH_TIME_NOW, (int64_t)interval),
                              interval,
                              (uint64_t)(1 * NSEC_PER_SEC));

    __weak typeof(self) weakSelf = self;
    dispatch_source_set_event_handler(self.recoveryTimer, ^{
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) return;

        uint32_t threats = rasp_run_all_checks();
        strongSelf.lastThreatMask = threats;
        strongSelf.deviceClean = (threats == RASP_THREAT_NONE);
        if (threats != RASP_THREAT_NONE) return;

        os_log_with_type(_rasp_log(), OS_LOG_TYPE_INFO, "Launch-time finding cleared on re-check");
        if (stateGet() == NX_STATE_NATIVE_GOT_HOOK_CHECK) {
            stateSet(NX_STATE_CODE_SIGNATURE_VERIFY); // -> 11
            stateSet(NX_STATE_FAIL_CLOSED_READY);     // -> 12
        }

        dispatch_source_t done = strongSelf.recoveryTimer;
        strongSelf.recoveryTimer = nil;
        if (done != nil) dispatch_source_cancel(done);

        [strongSelf startMonitoring];
        stateSet(NX_STATE_PERIODIC_MONITORING);       // -> 15
    });
    dispatch_resume(self.recoveryTimer);
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

            // At .hsa and .middle this is mandatory local enforcement: a compromised process
            // loses its ZTA token immediately, and the host observes the same notification and
            // stops protected operations. At .regular the delegate below is still told, and the
            // server still decides - the session is not torn down from here.
            if ([NXSecurityPolicy revokesOnRuntimeThreat]) {
                [[SessionManager sharedManager] clearAll];
                [[NSNotificationCenter defaultCenter] postNotificationName:@"io.nexilis.zta.runtimeCompromise"
                                                                    object:nil
                                                                  userInfo:@{@"threat_mask": @(threats)}];
            }

            // 2. Notify delegate for server-side revocation/telemetry as well.
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
            // Terminating the process is .hsa alone. .middle has already lost its token above,
            // which is what stops protected work there.
            if ([NXSecurityPolicy terminatesOnUnhandledThreat] &&
                ![strongSelf.delegate respondsToSelector:@selector(raspGuard:didDetectThreats:)]) {
                os_log_with_type(_rasp_log(), OS_LOG_TYPE_FAULT, "No RASP response delegate; terminating compromised process");
                abort();
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
    // The recovery re-check is the same kind of timer and has to go the same way; leaving it
    // running would keep re-arming the sweep this call was made to stop.
    if (self.recoveryTimer != nil) {
        dispatch_source_cancel(self.recoveryTimer);
        self.recoveryTimer = nil;
    }
}

- (uint32_t)runChecksNow {
    uint32_t threats = rasp_run_all_checks();
    self.lastThreatMask = threats;
    self.deviceClean = (threats == RASP_THREAT_NONE);
    return threats;
}

- (void)configureExpectedBundleID:(NSString *)bundleID
                     applicationID:(NSString *)applicationID
                            teamID:(NSString *)teamID
              appAttestEnvironment:(NSString *)environment {
    self.expectedBundleID = [bundleID copy];
    self.expectedApplicationID = [applicationID copy];
    self.expectedTeamID = [teamID copy];
    self.expectedAppAttestEnvironment = [environment copy];
}

- (BOOL)releaseIdentityConfigured {
    return self.expectedBundleID.length > 0 && self.expectedApplicationID.length > 0 &&
           self.expectedTeamID.length > 0 && self.expectedAppAttestEnvironment.length > 0;
}

- (BOOL)verifyCodeSignatureIntegrity {
    // v2.0.1: use public, App-Store-safe local checks only. SecTask* entitlement
    // introspection is intentionally not used on iOS. Cryptographic verification of
    // the real application identity (Team ID / bundle ID / App Attest environment)
    // is performed by the server when it verifies the mandatory App Attest object.
    // .hsa refuses to answer YES for an identity it was never given - that is the fail-closed
    // half of NX-08. .middle and .regular do not require the expectation at all, so an absent
    // one is simply nothing to compare, not a tamper finding. SecurityShield's isTempering()
    // reads this same verdict.
    if (![self releaseIdentityConfigured]) return ![NXSecurityPolicy isHSA];

    NSBundle *bundle = [NSBundle mainBundle];
    NSString *bundleId = bundle.bundleIdentifier ?: @"";
    if (![bundleId isEqualToString:self.expectedBundleID]) return NO;

    // The configured application identifier must be internally consistent. This
    // catches release misconfiguration locally before any protected session starts.
    NSString *derivedApplicationID = [NSString stringWithFormat:@"%@.%@",
                                      self.expectedTeamID, self.expectedBundleID];
    if (![self.expectedApplicationID isEqualToString:derivedApplicationID]) return NO;

    NSString *environment = self.expectedAppAttestEnvironment.lowercaseString;
#if DEBUG
    if (!([environment isEqualToString:@"development"] ||
          [environment isEqualToString:@"production"])) return NO;
#else
    // Hardened production releases must use the production App Attest environment.
    if (![environment isEqualToString:@"production"]) return NO;
#endif

    // Sanity-check that the running executable is the executable of the main bundle.
    // This is not used as a substitute for code-signing/App Attest verification; it
    // is a local fail-closed consistency check using public Foundation APIs.
    NSURL *bundleURL = bundle.bundleURL.URLByStandardizingPath;
    NSURL *executableURL = bundle.executableURL.URLByStandardizingPath;
    if (bundleURL == nil || executableURL == nil) return NO;
    NSString *bundlePath = bundleURL.path.stringByStandardizingPath;
    NSString *executablePath = executableURL.path.stringByStandardizingPath;
    NSString *bundlePrefix = [bundlePath stringByAppendingString:@"/"];
    if (![executablePath hasPrefix:bundlePrefix]) return NO;

    return YES;
}

- (void)configurePinningWithPrimaryPin:(NSString *)primaryPin backupPin:(NSString *)backupPin {
    self.primaryPin = [primaryPin copy];
    self.backupPin = [backupPin copy];
}

- (BOOL)pinningConfigured {
    return self.primaryPin.length > 0 && self.backupPin.length > 0 && ![self.primaryPin isEqualToString:self.backupPin];
}

- (void)configureHostPinFloor:(NSDictionary<NSString *, NSArray<NSString *> *> *)pinsByHost {
    NSMutableDictionary *lowercased = [NSMutableDictionary dictionaryWithCapacity:pinsByHost.count];
    [pinsByHost enumerateKeysAndObjectsUsingBlock:^(NSString *host, NSArray<NSString *> *pins, BOOL *stop) {
        if (host.length > 0 && pins.count > 0) lowercased[host.lowercaseString] = [pins copy];
    }];
    self.hostPinFloor = [lowercased copy];
}

- (void)configureAdditionalPins:(NSArray<NSString *> *)pins forHost:(NSString *)host {
    if (host.length == 0) return;
    NSMutableDictionary *next = [self.additionalPinsByHost mutableCopy] ?: [NSMutableDictionary dictionary];
    next[host.lowercaseString] = [pins copy] ?: @[];
    self.additionalPinsByHost = [next copy];
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

    BOOL matched = (self.primaryPin.length > 0 && [serverPin isEqualToString:self.primaryPin]) ||
                   (self.backupPin.length > 0 && [serverPin isEqualToString:self.backupPin]) ||
                   [self.additionalPinsByHost[host.lowercaseString] containsObject:serverPin] ||
                   [self.hostPinFloor[host.lowercaseString] containsObject:serverPin];
    // A.3 — channel binding is updated only after a successful pin match. A rejected
    // attacker certificate must never become the binding consumed by a concurrent request.
    if (matched) self.lastPinnedLeafSPKIHex = serverPin;
    return matched;
}

- (void)reportPinningFailureForHost:(NSString *)host {
    os_log_with_type(_rasp_log(), OS_LOG_TYPE_ERROR,
                     "Certificate pinning failure for host: %{private}@", host);
    // The connection itself is already refused by the caller at every mode. What differs is the
    // blast radius: .hsa and .middle treat a first-party pin mismatch as a compromised process
    // and revoke, .regular reports it and leaves the session alone.
    if ([NXSecurityPolicy revokesOnRuntimeThreat]) {
        [self raiseThreatFlag:RASP_THREAT_TAMPERED];
        [[SessionManager sharedManager] clearAll];
        [[NSNotificationCenter defaultCenter] postNotificationName:@"io.nexilis.zta.runtimeCompromise"
                                                            object:nil
                                                          userInfo:@{@"threat_mask": @(RASP_THREAT_TAMPERED)}];
    }
    if ([self.delegate respondsToSelector:@selector(raspGuard:didDetectPinningFailureForHost:)]) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.delegate raspGuard:self didDetectPinningFailureForHost:host ?: @"<unknown>"];
        });
    }
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

    NSString *host = challenge.protectionSpace.host ?: @"";
    if (![self isPinnedHost:host]) {
        completionHandler(NSURLSessionAuthChallengeUseCredential,
                          [NSURLCredential credentialForTrust:serverTrust]);
        return;
    }

    // First-party/ZTA hosts are always fail-closed. Primary + independent backup form
    // the immutable floor; PinSetStore feeds only signature-verified additive pins into
    // additionalPinsByHost. No build mode may silently downgrade this to system trust.
    if (![self serverTrust:serverTrust matchesPinnedSPKIForHost:host]) {
        [self reportPinningFailureForHost:host];
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        return;
    }

    completionHandler(NSURLSessionAuthChallengeUseCredential,
                      [NSURLCredential credentialForTrust:serverTrust]);
}

- (void)dealloc {
    [self stopMonitoring];
}

@end
