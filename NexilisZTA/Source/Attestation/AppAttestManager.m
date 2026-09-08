/*
 * AppAttestManager.m
 * Nexilis iOS ZTA Bundle V4 — App Attest + Secure Enclave Key Delivery
 */

#import "AppAttestManager.h"
#import "RASPGuard.h"
#import "NXSecurityPolicy.h"
#import "SessionManager.h"
#import <DeviceCheck/DeviceCheck.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonCryptor.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <UIKit/UIKit.h>
#import <sys/utsname.h>
#import <os/log.h>

NSString * const NXAppAttestErrorDomain = @"io.nexilis.appattest";

static NSString * const kKeychainKeyIdKey                    = @"io.nexilis.zta.keyId";
static NSString * const kKeychainSignKeyTag                  = @"io.nexilis.zta.signkey";
static NSString * const kKeychainDeliveryKeyTag              = @"io.nexilis.zta.deliverykey";
static NSString * const kKeychainDeliveryKeyFingerprintKey   = @"io.nexilis.zta.deliverykey.fp";
static NSString * const kKeyEnvelopeAlgorithm                = @"ECDH_P256_X963_SHA256_AES256CTR_HMAC256_V1";

static os_log_t sAttestLog(void) {
    static os_log_t log;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        log = os_log_create("io.nexilis.SampleAppShield", "AppAttest");
    });
    return log;
}

@interface AppAttestManager ()
@property (nonatomic, strong, nullable) NSString *storedKeyId;
@property (nonatomic, strong) NSURLSession *session;
@end

@implementation AppAttestManager

#pragma mark - Utility helpers

static NSData *NXSHA256(NSData *data) {
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, hash);
    return [NSData dataWithBytes:hash length:CC_SHA256_DIGEST_LENGTH];
}

static NSString *NXBase64(NSData *data) {
    return [data base64EncodedStringWithOptions:0];
}

static NSData *NXDataFromBase64(id value) {
    if (![value isKindOfClass:[NSString class]]) return nil;
    return [[NSData alloc] initWithBase64EncodedString:(NSString *)value options:0];
}

static NSError *NXError(NSInteger code, NSString *message) {
    return [NSError errorWithDomain:NXAppAttestErrorDomain
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey: message ?: @"Unknown error"}];
}

/*
 * Tells "the server is busy" apart from "the server said no". A 502 from a gateway, a 504 while a
 * backend restarts, a 429 under load - all of those clear themselves, and none of them are a
 * statement about this device. They were reported with the same code as a genuine policy refusal,
 * and that code is the one the screen treats as final, which is how a reader ended up looking at
 * an error with no retry offered for a backend that was fine again a minute later.
 */
static NSError *NXServerError(NSInteger statusCode, NSString *message) {
    BOOL transient = (statusCode >= 500) || (statusCode == 408) || (statusCode == 429) || (statusCode == 0);
    return NXError(transient ? NXAppAttestErrorServerUnavailable : NXAppAttestErrorServerRejected, message);
}

static NSString *NXEscapeJSONString(NSString *input) {
    NSMutableString *s = [NSMutableString stringWithCapacity:input.length + 8];
    for (NSUInteger i = 0; i < input.length; i++) {
        unichar c = [input characterAtIndex:i];
        switch (c) {
            case '"': [s appendString:@"\\\""]; break;
            case '\\': [s appendString:@"\\\\"]; break;
            case '\b': [s appendString:@"\\b"]; break;
            case '\f': [s appendString:@"\\f"]; break;
            case '\n': [s appendString:@"\\n"]; break;
            case '\r': [s appendString:@"\\r"]; break;
            case '\t': [s appendString:@"\\t"]; break;
            default:
                if (c < 0x20) {
                    [s appendFormat:@"\\u%04x", c];
                } else {
                    [s appendFormat:@"%C", c];
                }
        }
    }
    return s;
}

static void NXAppendCanonicalJSON(id obj, NSMutableString *out) {
    if (obj == nil || obj == [NSNull null]) {
        [out appendString:@"null"];
    } else if ([obj isKindOfClass:[NSString class]]) {
        [out appendFormat:@"\"%@\"", NXEscapeJSONString((NSString *)obj)];
    } else if ([obj isKindOfClass:[NSNumber class]]) {
        CFTypeID boolType = CFBooleanGetTypeID();
        if (CFGetTypeID((__bridge CFTypeRef)obj) == boolType) {
            [out appendString:[(NSNumber *)obj boolValue] ? @"true" : @"false"];
        } else {
            [out appendString:[(NSNumber *)obj stringValue]];
        }
    } else if ([obj isKindOfClass:[NSArray class]]) {
        [out appendString:@"["];
        NSArray *array = (NSArray *)obj;
        for (NSUInteger i = 0; i < array.count; i++) {
            if (i > 0) [out appendString:@","];
            NXAppendCanonicalJSON(array[i], out);
        }
        [out appendString:@"]"];
    } else if ([obj isKindOfClass:[NSDictionary class]]) {
        [out appendString:@"{"];
        NSDictionary *dict = (NSDictionary *)obj;
        NSArray<NSString *> *keys = [[dict allKeys] sortedArrayUsingSelector:@selector(compare:)];
        for (NSUInteger i = 0; i < keys.count; i++) {
            if (i > 0) [out appendString:@","];
            NSString *key = keys[i];
            [out appendFormat:@"\"%@\":", NXEscapeJSONString(key)];
            NXAppendCanonicalJSON(dict[key], out);
        }
        [out appendString:@"}"];
    } else {
        [out appendString:@"null"];
    }
}

static NSData *NXCanonicalJSONData(NSDictionary *dict, NSError **error) {
    if (![NSJSONSerialization isValidJSONObject:dict]) {
        if (error) *error = NXError(NXAppAttestErrorDecodeFailed, @"Object is not valid JSON");
        return nil;
    }
    NSMutableString *json = [NSMutableString stringWithCapacity:256];
    NXAppendCanonicalJSON(dict, json);
    NSData *data = [json dataUsingEncoding:NSUTF8StringEncoding];
    if (data == nil && error) {
        *error = NXError(NXAppAttestErrorDecodeFailed, @"Failed to encode canonical JSON");
    }
    return data;
}

static BOOL NXConstantTimeEqual(NSData *a, NSData *b) {
    if (a.length != b.length) return NO;
    const uint8_t *aa = a.bytes;
    const uint8_t *bb = b.bytes;
    uint8_t diff = 0;
    for (NSUInteger i = 0; i < a.length; i++) diff |= (aa[i] ^ bb[i]);
    return diff == 0;
}

static NSData *NXHMACSHA256(NSData *key, NSData *message) {
    unsigned char mac[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, key.bytes, key.length, message.bytes, message.length, mac);
    return [NSData dataWithBytes:mac length:CC_SHA256_DIGEST_LENGTH];
}

static NSData *NXBuildEnvelopeMACInput(NSData *ephemeralPub, NSData *iv, NSData *ciphertext, NSData *context) {
    NSMutableData *data = [NSMutableData data];
    [data appendData:[kKeyEnvelopeAlgorithm dataUsingEncoding:NSUTF8StringEncoding]];
    uint8_t sep = 0x00;
    [data appendBytes:&sep length:1];
    [data appendData:ephemeralPub ?: [NSData data]];
    [data appendData:iv ?: [NSData data]];
    [data appendData:ciphertext ?: [NSData data]];
    [data appendData:context ?: [NSData data]];
    return data;
}

static NSData *NXAESCTR(NSData *key, NSData *iv, NSData *input, CCOperation operation, NSError **error) {
    if (key.length != kCCKeySizeAES256 || iv.length != kCCBlockSizeAES128) {
        if (error) *error = NXError(NXAppAttestErrorCryptoFailed, @"Invalid AES-CTR key/IV length");
        return nil;
    }

    CCCryptorRef cryptor = NULL;
    CCCryptorStatus status = CCCryptorCreateWithMode(operation,
                                                     kCCModeCTR,
                                                     kCCAlgorithmAES,
                                                     ccNoPadding,
                                                     iv.bytes,
                                                     key.bytes,
                                                     key.length,
                                                     NULL,
                                                     0,
                                                     0,
                                                     0,
                                                     &cryptor);
    if (status != kCCSuccess || cryptor == NULL) {
        if (error) *error = NXError(NXAppAttestErrorCryptoFailed, @"Failed to create AES-CTR cryptor");
        return nil;
    }

    NSMutableData *out = [NSMutableData dataWithLength:input.length + kCCBlockSizeAES128];
    size_t outMoved = 0;
    status = CCCryptorUpdate(cryptor, input.bytes, input.length, out.mutableBytes, out.length, &outMoved);
    size_t finalMoved = 0;
    if (status == kCCSuccess) {
        status = CCCryptorFinal(cryptor, ((uint8_t *)out.mutableBytes) + outMoved, out.length - outMoved, &finalMoved);
    }
    CCCryptorRelease(cryptor);

    if (status != kCCSuccess) {
        if (error) *error = NXError(NXAppAttestErrorCryptoFailed, @"AES-CTR operation failed");
        return nil;
    }
    out.length = outMoved + finalMoved;
    return out;
}

static NSString *NXDeviceModel(void) {
    struct utsname systemInfo;
    memset(&systemInfo, 0, sizeof(systemInfo));
    uname(&systemInfo);
    return [NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding] ?: @"<unknown>";
}

#pragma mark - Singleton / lifecycle

+ (instancetype)sharedManager {
    static AppAttestManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[AppAttestManager alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _storedKeyId = [self loadStringFromKeychain:kKeychainKeyIdKey account:@"nexilis_attest"];
        _session = [[RASPGuard sharedGuard] pinnedURLSession];
        _minimumOSMajor = 14; // where App Attest begins; overridden from the configuration
    }
    return self;
}

- (void)resetURLSession {
#ifdef DEBUG
    if (self.bypassPinningForDev) {
        NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        config.timeoutIntervalForRequest  = 15.0;
        config.timeoutIntervalForResource = 30.0;
        self.session = [NSURLSession sessionWithConfiguration:config
                                                     delegate:nil
                                                delegateQueue:nil];
        os_log_info(sAttestLog(), "[Nexilis/Attest] %{public}s", "✅ DEV session — pinning BYPASSED");
        return;
    }
    os_log_info(sAttestLog(), "[Nexilis/Attest] %{public}s", "⚠️ bypassPinningForDev = NO — pakai pinned session");
#endif
    self.session = [[RASPGuard sharedGuard] pinnedURLSession];
    os_log_info(sAttestLog(), "[Nexilis/Attest] %{public}s", "URLSession reset dengan pin");
}

- (BOOL)isSupported {
    if (NSProcessInfo.processInfo.operatingSystemVersion.majorVersion < self.minimumOSMajor) {
        return NO;
    }
    if (@available(iOS 14.0, *)) {
        return [DCAppAttestService sharedService].isSupported;
    }
    return NO;
}

- (BOOL)isRegistered {
    return self.storedKeyId != nil;
}

- (NSString *)keyId {
    return self.storedKeyId;
}

#pragma mark - Generic Keychain helpers

- (BOOL)saveDataToKeychain:(NSData *)data service:(NSString *)service account:(NSString *)account {
    if (data == nil || service.length == 0 || account.length == 0) return NO;
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: service,
        (__bridge id)kSecAttrAccount: account,
    };
    SecItemDelete((__bridge CFDictionaryRef)query);

    NSMutableDictionary *add = [query mutableCopy];
    add[(__bridge id)kSecValueData] = data;
    add[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)add, NULL);
    return status == errSecSuccess;
}

- (NSData *)loadDataFromKeychain:(NSString *)service account:(NSString *)account {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: service,
        (__bridge id)kSecAttrAccount: account,
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne,
    };
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status == errSecSuccess && result != NULL) {
        return (__bridge_transfer NSData *)result;
    }
    return nil;
}

- (NSString *)loadStringFromKeychain:(NSString *)service account:(NSString *)account {
    NSData *data = [self loadDataFromKeychain:service account:account];
    return data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : nil;
}

- (void)deleteKeychainItem:(NSString *)service account:(NSString *)account {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: service,
        (__bridge id)kSecAttrAccount: account,
    };
    SecItemDelete((__bridge CFDictionaryRef)query);
}

- (void)saveKeyIdToKeychain:(NSString *)keyId {
    if ([self saveDataToKeychain:[keyId dataUsingEncoding:NSUTF8StringEncoding]
                         service:kKeychainKeyIdKey
                         account:@"nexilis_attest"]) {
        self.storedKeyId = keyId;
    }
}

- (void)deleteKeyIdFromKeychain {
    [self deleteKeychainItem:kKeychainKeyIdKey account:@"nexilis_attest"];
    self.storedKeyId = nil;
}

- (NSString *)deliveryKeyFingerprint {
    return [self loadStringFromKeychain:kKeychainDeliveryKeyFingerprintKey account:@"nexilis_attest"];
}

- (void)saveDeliveryKeyFingerprint:(NSString *)fingerprint {
    if (fingerprint.length == 0) return;
    [self saveDataToKeychain:[fingerprint dataUsingEncoding:NSUTF8StringEncoding]
                    service:kKeychainDeliveryKeyFingerprintKey
                    account:@"nexilis_attest"];
}

- (void)deleteDeliveryKeyFingerprint {
    [self deleteKeychainItem:kKeychainDeliveryKeyFingerprintKey account:@"nexilis_attest"];
}

#pragma mark - Secure Enclave keys

- (NSDictionary *)secureEnclaveKeyQueryForTag:(NSString *)tag returnRef:(BOOL)returnRef prompt:(NSString * _Nullable)prompt {
    NSMutableDictionary *query = [@{
        (__bridge id)kSecClass: (__bridge id)kSecClassKey,
        (__bridge id)kSecAttrApplicationTag: [tag dataUsingEncoding:NSUTF8StringEncoding],
        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
        (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave,
    } mutableCopy];
    if (returnRef) {
        query[(__bridge id)kSecReturnRef] = @YES;
    }
    if (prompt.length > 0) {
        query[(__bridge id)kSecUseOperationPrompt] = prompt;
    }
    return query;
}

- (SecKeyRef)loadExistingSecureEnclaveKeyForTag:(NSString *)tag prompt:(NSString * _Nullable)prompt {
    NSDictionary *query = [self secureEnclaveKeyQueryForTag:tag returnRef:YES prompt:prompt];
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status == errSecSuccess && result != NULL) {
        return (SecKeyRef)result;
    }
    return NULL;
}

- (SecKeyRef)createSecureEnclavePrivateKeyWithTag:(NSString *)tag access:(SecAccessControlRef)access error:(NSError **)error {
    NSDictionary *attrs = @{
        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
        (__bridge id)kSecAttrKeySizeInBits: @256,
        (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave,
        (__bridge id)kSecPrivateKeyAttrs: @{
            (__bridge id)kSecAttrIsPermanent: @YES,
            (__bridge id)kSecAttrApplicationTag: [tag dataUsingEncoding:NSUTF8StringEncoding],
            (__bridge id)kSecAttrAccessControl: (__bridge id)access,
        },
    };
    CFErrorRef createError = NULL;
    SecKeyRef key = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attrs, &createError);
    if (key == NULL && error) {
        *error = createError ? (__bridge_transfer NSError *)createError : NXError(NXAppAttestErrorSecureEnclaveFail, @"Failed to create Secure Enclave key");
    } else if (createError) {
        CFRelease(createError);
    }
    return key;
}

- (SecKeyRef)loadOrCreateDeliveryPrivateKey:(NSError **)error {
    SecKeyRef existing = [self loadExistingSecureEnclaveKeyForTag:kKeychainDeliveryKeyTag prompt:nil];
    if (existing != NULL) return existing;

    CFErrorRef accessError = NULL;
    SecAccessControlRef access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                                 kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                                 kSecAccessControlPrivateKeyUsage,
                                                                 &accessError);
    if (access == NULL) {
        if (error) *error = accessError ? (__bridge_transfer NSError *)accessError : NXError(NXAppAttestErrorSecureEnclaveFail, @"Delivery key access control creation failed");
        return NULL;
    }
    SecKeyRef created = [self createSecureEnclavePrivateKeyWithTag:kKeychainDeliveryKeyTag access:access error:error];
    CFRelease(access);
    return created;
}

- (NSData *)deliveryPublicKeyX963:(NSError **)error {
    SecKeyRef privateKey = [self loadOrCreateDeliveryPrivateKey:error];
    if (privateKey == NULL) {
        if (error && *error == nil) *error = NXError(NXAppAttestErrorSecureEnclaveFail, @"Unable to access Secure Enclave delivery key");
        return nil;
    }
    SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
    CFRelease(privateKey);
    if (publicKey == NULL) {
        if (error) *error = NXError(NXAppAttestErrorSecureEnclaveFail, @"Unable to derive delivery public key");
        return nil;
    }
    CFErrorRef exportError = NULL;
    CFDataRef publicData = SecKeyCopyExternalRepresentation(publicKey, &exportError);
    CFRelease(publicKey);
    if (publicData == NULL) {
        if (error) *error = exportError ? (__bridge_transfer NSError *)exportError : NXError(NXAppAttestErrorSecureEnclaveFail, @"Unable to export delivery public key");
        else if (exportError) CFRelease(exportError);
        return nil;
    }
    return CFBridgingRelease(publicData);
}

- (NSString *)deliveryKeyFingerprintFromPublicKey:(NSData *)deliveryPubKey {
    NSData *hash = NXSHA256(deliveryPubKey ?: [NSData data]);
    return [hash base64EncodedStringWithOptions:0];
}

- (SecKeyRef)loadSigningKeyWithPrompt:(NSString *)prompt createIfMissing:(BOOL)createIfMissing error:(NSError **)error {
    SecKeyRef existing = [self loadExistingSecureEnclaveKeyForTag:kKeychainSignKeyTag prompt:prompt ?: @"Authenticate to sign"]; 
    if (existing != NULL) return existing;
    if (!createIfMissing) {
        if (error) *error = NXError(NXAppAttestErrorSecureEnclaveFail, @"Failed to load signing key from Secure Enclave");
        return NULL;
    }

    CFErrorRef createError = NULL;
    SecAccessControlRef access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                                 kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                                 kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryCurrentSet,
                                                                 &createError);
    if (access == NULL) {
        if (error) *error = createError ? (__bridge_transfer NSError *)createError : NXError(NXAppAttestErrorSecureEnclaveFail, @"Failed to create access control");
        return NULL;
    }
    SecKeyRef created = [self createSecureEnclavePrivateKeyWithTag:kKeychainSignKeyTag access:access error:error];
    CFRelease(access);
    if (created == NULL) {
        return NULL;
    }
    CFRelease(created);
    return [self loadExistingSecureEnclaveKeyForTag:kKeychainSignKeyTag prompt:prompt ?: @"Authenticate to sign"];
}

#pragma mark - Network helpers

- (void)requestChallengeForPurpose:(NSString *)purpose
                        completion:(void (^)(NSData * _Nullable nonce,
                                             NSString * _Nullable nonceId,
                                             NSError * _Nullable error))completion {
    if (self.challengeEndpoint.length == 0) {
        completion(nil, nil, NXError(NXAppAttestErrorNetworkFailed, @"challengeEndpoint not configured"));
        return;
    }

    NSURLComponents *components = [NSURLComponents componentsWithString:self.challengeEndpoint];
    NSMutableArray<NSURLQueryItem *> *items = components.queryItems.mutableCopy ?: [NSMutableArray array];
    if (purpose.length > 0) {
        [items addObject:[NSURLQueryItem queryItemWithName:@"purpose" value:purpose]];
    }
    components.queryItems = items;

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:components.URL];
    request.HTTPMethod = @"GET";
    request.timeoutInterval = 8.0;

    [[self.session dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error) { completion(nil, nil, error); return; }
        NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)response;
        if (httpResp.statusCode != 200) {
            completion(nil, nil, NXServerError(httpResp.statusCode,
                                               [NSString stringWithFormat:@"Challenge returned %ld", (long)httpResp.statusCode]));
            return;
        }

        NSError *jsonError = nil;
        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];
        if (jsonError != nil || ![json isKindOfClass:[NSDictionary class]]) {
            completion(nil, nil, jsonError ?: NXError(NXAppAttestErrorDecodeFailed, @"Invalid challenge payload"));
            return;
        }
        NSData *nonce = NXDataFromBase64(json[@"nonce"]);
        NSString *nonceId = [json[@"nonce_id"] isKindOfClass:[NSString class]] ? json[@"nonce_id"] : nil;
        if (nonce == nil || nonceId.length == 0) {
            completion(nil, nil, NXError(NXAppAttestErrorDecodeFailed, @"Challenge payload missing nonce/nonce_id"));
            return;
        }
        completion(nonce, nonceId, nil);
    }] resume];
}

- (void)POSTJSONBody:(NSDictionary *)body
            endpoint:(NSString *)endpoint
          completion:(void (^)(NSDictionary * _Nullable json, NSHTTPURLResponse * _Nullable response, NSError * _Nullable error))completion {
    if (endpoint.length == 0) {
        completion(nil, nil, NXError(NXAppAttestErrorNetworkFailed, @"Endpoint not configured"));
        return;
    }
    NSError *jsonError = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:body options:0 error:&jsonError];
    if (jsonData == nil || jsonError != nil) {
        completion(nil, nil, jsonError ?: NXError(NXAppAttestErrorDecodeFailed, @"Failed to encode request JSON"));
        return;
    }

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:endpoint]];
    request.HTTPMethod = @"POST";
    request.HTTPBody = jsonData;
    request.timeoutInterval = 12.0;
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];

    [[self.session dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error) {
            completion(nil, (NSHTTPURLResponse *)response, error);
            return;
        }
        NSDictionary *json = nil;
        if (data.length > 0) {
            NSError *parseError = nil;
            id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:&parseError];
            if (parseError == nil && [obj isKindOfClass:[NSDictionary class]]) {
                json = obj;
            }
        }
        completion(json, (NSHTTPURLResponse *)response, nil);
    }] resume];
}

static NSString *NXCurrentChannelBinding(void) {
    NSString *pin = [RASPGuard sharedGuard].lastPinnedLeafSPKIHex;
    return pin.length > 0 ? pin : nil;
}

#pragma mark - Registration / delivery-key synchronization

- (void)registerDeviceWithCompletion:(NXAttestRegistrationCompletion)completion {
    if (!self.isSupported) {
        completion(NO, NXError(NXAppAttestErrorNotSupported,
                               [NSString stringWithFormat:@"App Attest is not supported here (requires an App Attest-capable Secure Enclave and iOS %ld+)", (long)self.minimumOSMajor]));
        return;
    }

    if (self.isRegistered) {
        [self refreshDeliveryKeyRegistrationWithCompletion:completion];
        return;
    }

    NSError *deliveryKeyError = nil;
    NSData *deliveryPubKey = [self deliveryPublicKeyX963:&deliveryKeyError];
    if (deliveryPubKey == nil) {
        completion(NO, deliveryKeyError ?: NXError(NXAppAttestErrorSecureEnclaveFail, @"Unable to prepare delivery key"));
        return;
    }
    NSString *deliveryFingerprint = [self deliveryKeyFingerprintFromPublicKey:deliveryPubKey];

    if (@available(iOS 14.0, *)) {
        DCAppAttestService *service = [DCAppAttestService sharedService];
        [service generateKeyWithCompletionHandler:^(NSString * _Nullable keyId, NSError * _Nullable error) {
            if (error != nil || keyId.length == 0) {
                completion(NO, error ?: NXError(NXAppAttestErrorKeyGenFailed, @"App Attest key generation failed"));
                return;
            }

            [self requestChallengeForPurpose:@"attestation" completion:^(NSData * _Nullable nonce, NSString * _Nullable nonceId, NSError * _Nullable challengeError) {
                if (challengeError != nil || nonce == nil || nonceId.length == 0) {
                    completion(NO, challengeError ?: NXError(NXAppAttestErrorNonceExpired, @"Unable to fetch registration challenge"));
                    return;
                }

                NSData *clientDataHash = NXSHA256(nonce);
                [service attestKey:keyId clientDataHash:clientDataHash completionHandler:^(NSData * _Nullable attestationObject, NSError * _Nullable attestError) {
                    if (attestError != nil || attestationObject == nil) {
                        completion(NO, attestError ?: NXError(NXAppAttestErrorAttestFailed, @"App Attest attestation failed"));
                        return;
                    }

                    // .hsa and .middle will not attest over a channel they have not pinned.
                    // .regular may legitimately have none - a host pointing at its own domain,
                    // which isPinnedHost does not cover - so it binds when it can and goes on
                    // when it cannot, rather than refusing to register at all.
                    NSString *channelBinding = NXCurrentChannelBinding();
                    if (channelBinding.length == 0 && [NXSecurityPolicy requiresServerChain]) {
                        completion(NO, NXError(NXAppAttestErrorPinningFailed, @"Pinned TLS channel binding unavailable during registration"));
                        return;
                    }
                    NSMutableDictionary *body = [@{
                        @"attestation_object": NXBase64(attestationObject),
                        @"key_id": keyId,
                        @"nonce_id": nonceId,
                        @"delivery_key_pub": NXBase64(deliveryPubKey),
                        @"os_version": [[UIDevice currentDevice] systemVersion] ?: @"<unknown>",
                        @"device_model": NXDeviceModel(),
                        @"bundle_id": [[NSBundle mainBundle] bundleIdentifier] ?: @"<unknown>",
                    } mutableCopy];
                    // v2.0.1: channel binding is a mandatory precondition and is appended only
                    // after the non-empty guard above. This avoids ever constructing an
                    // NSDictionary literal with a nullable value.
                    if (channelBinding.length > 0) body[@"tls_spki"] = channelBinding;

            // Sent at every mode. The decision endpoint refuses a transaction whose approval key
            // it never recorded, so withholding this at mode 3 was what made sensitive
            // transactions impossible there - and mode 3 is the default, which is to say most of
            // the installed base. The server has always recorded this field only when a client
            // sends one, so adding it does not break a client that still does not.
            //
            // Additive, and it degrades rather than fails: `approvalPublicKeyBase64` creates the
            // Secure Enclave key with `prompt:nil` and derives only the public half, so no
            // biometric prompt appears during registration, and a device that cannot create a
            // biometry-bound key returns nil and simply omits the field.
            NSString *approvalKey = [self approvalPublicKeyBase64];
            if (approvalKey.length > 0) body[@"approval_public_key_b64"] = approvalKey;
                    [self POSTJSONBody:body endpoint:self.attestEndpoint completion:^(NSDictionary * _Nullable json, NSHTTPURLResponse * _Nullable response, NSError * _Nullable networkError) {
                        if (networkError != nil) {
                            completion(NO, networkError);
                            return;
                        }
                        NSInteger statusCode = response.statusCode;
                        if (statusCode != 200 && statusCode != 201) {
                            NSString *message = [json[@"error"] isKindOfClass:[NSString class]] ? json[@"error"] : [NSString stringWithFormat:@"Server rejected attestation: %ld", (long)statusCode];
                            completion(NO, NXServerError(statusCode, message));
                            return;
                        }
                        [self saveKeyIdToKeychain:keyId];
                        [self saveDeliveryKeyFingerprint:deliveryFingerprint];
                        completion(YES, nil);
                    }];
                }];
            }];
        }];
    } else {
        completion(NO, NXError(NXAppAttestErrorNotSupported, @"App Attest requires iOS 14 or later"));
    }
}

- (void)refreshDeliveryKeyRegistrationWithCompletion:(NXAttestRegistrationCompletion)completion {
    if (!self.isRegistered || self.storedKeyId.length == 0) {
        completion(NO, NXError(NXAppAttestErrorKeyNotRegistered, @"Device not registered with App Attest"));
        return;
    }
    NSError *deliveryKeyError = nil;
    NSData *deliveryPubKey = [self deliveryPublicKeyX963:&deliveryKeyError];
    if (deliveryPubKey == nil) {
        completion(NO, deliveryKeyError ?: NXError(NXAppAttestErrorSecureEnclaveFail, @"Unable to load delivery key"));
        return;
    }
    NSString *currentFingerprint = [self deliveryKeyFingerprintFromPublicKey:deliveryPubKey];
    NSString *storedFingerprint = [self deliveryKeyFingerprint];
    /*
     * The fingerprint only says the delivery key on THIS device has not changed. It says nothing
     * about whether the server still holds the matching registration, and the server's copy is
     * bound to a session that expires. Skipping the re-registration on a fingerprint match alone
     * meant that once the session had lapsed - which is what a two or three day gap guarantees -
     * key delivery was asked for against a record the server had already let go, and it failed
     * every launch with a rejection no retry could clear. A live session is the second half of
     * the condition: while one is valid, nothing needs re-sending; once it is gone, the delivery
     * key is registered again so the server's record is current before the key is asked for.
     */
    BOOL sessionStillValid = [[SessionManager sharedManager] hasValidSession];
    if (storedFingerprint.length > 0 && [storedFingerprint isEqualToString:currentFingerprint] && sessionStillValid) {
        completion(YES, nil);
        return;
    }
    if (self.registerEndpoint.length == 0) {
        completion(NO, NXError(NXAppAttestErrorNetworkFailed, @"registerEndpoint not configured"));
        return;
    }

    [self requestChallengeForPurpose:@"register" completion:^(NSData * _Nullable nonce, NSString * _Nullable nonceId, NSError * _Nullable challengeError) {
        if (challengeError != nil || nonce == nil || nonceId.length == 0) {
            completion(NO, challengeError ?: NXError(NXAppAttestErrorNonceExpired, @"Unable to obtain delivery-key registration challenge"));
            return;
        }

        NSMutableDictionary *body = [NSMutableDictionary dictionary];
        body[@"key_id"] = self.storedKeyId;
        body[@"nonce_id"] = nonceId;
        body[@"challenge"] = NXBase64(nonce);
        body[@"delivery_key_pub"] = NXBase64(deliveryPubKey);
        body[@"os_version"] = [[UIDevice currentDevice] systemVersion] ?: @"<unknown>";
        body[@"device_model"] = NXDeviceModel();
        body[@"bundle_id"] = [[NSBundle mainBundle] bundleIdentifier] ?: @"<unknown>";
        body[@"timestamp_ms"] = @((long long)([[NSDate date] timeIntervalSince1970] * 1000.0));
        NSString *channelBinding = NXCurrentChannelBinding();
        if (channelBinding.length == 0 && [NXSecurityPolicy requiresServerChain]) {
            completion(NO, NXError(NXAppAttestErrorPinningFailed, @"Pinned TLS channel binding unavailable during delivery-key registration"));
            return;
        }
        if (channelBinding.length > 0) body[@"tls_spki"] = channelBinding;

        NSError *canonicalError = nil;
        NSData *canonical = NXCanonicalJSONData(body, &canonicalError);
        if (canonical == nil || canonicalError != nil) {
            completion(NO, canonicalError ?: NXError(NXAppAttestErrorDecodeFailed, @"Failed to canonicalize delivery-key registration request"));
            return;
        }

        [self generateAssertionForClientData:canonical completion:^(NSData * _Nullable assertion, NSError * _Nullable assertError) {
            if (assertError != nil || assertion == nil) {
                completion(NO, assertError ?: NXError(NXAppAttestErrorAssertFailed, @"Failed to generate delivery-key registration assertion"));
                return;
            }
            NSMutableDictionary *finalBody = [body mutableCopy];
            finalBody[@"assertion"] = NXBase64(assertion);
            [self POSTJSONBody:finalBody endpoint:self.registerEndpoint completion:^(NSDictionary * _Nullable json, NSHTTPURLResponse * _Nullable response, NSError * _Nullable networkError) {
                if (networkError != nil) {
                    completion(NO, networkError);
                    return;
                }
                NSInteger statusCode = response.statusCode;
                if (statusCode != 200) {
                    NSString *message = [json[@"error"] isKindOfClass:[NSString class]] ? json[@"error"] : [NSString stringWithFormat:@"Server rejected delivery-key registration: %ld", (long)statusCode];
                    completion(NO, NXServerError(statusCode, message));
                    return;
                }
                [self saveDeliveryKeyFingerprint:currentFingerprint];
                completion(YES, nil);
            }];
        }];
    }];
}

#pragma mark - Assertion

- (void)generateAssertionForClientData:(NSData *)clientData completion:(NXAssertionCompletion)completion {
    if (!self.isRegistered || self.storedKeyId.length == 0) {
        completion(nil, NXError(NXAppAttestErrorKeyNotRegistered, @"Device not registered with App Attest"));
        return;
    }
    if (@available(iOS 14.0, *)) {
        NSData *clientDataHash = NXSHA256(clientData);
        [[DCAppAttestService sharedService] generateAssertion:self.storedKeyId
                                      clientDataHash:clientDataHash
                                   completionHandler:^(NSData * _Nullable assertion, NSError * _Nullable error) {
            if (error != nil || assertion == nil) {
                completion(nil, error ?: NXError(NXAppAttestErrorAssertFailed, @"Failed to generate assertion"));
                return;
            }
            completion(assertion, nil);
        }];
    } else {
        completion(nil, NXError(NXAppAttestErrorNotSupported, @"App Attest requires iOS 14 or later"));
    }
}

#pragma mark - Key delivery

- (void)requestKeyDeliveryWithPosture:(NSDictionary *)devicePosture completion:(NXKeyDeliveryCompletion)completion {
    if (!self.isRegistered || self.storedKeyId.length == 0) {
        completion(nil, NXError(NXAppAttestErrorKeyNotRegistered, @"Device not registered with App Attest"));
        return;
    }
    if (self.keyDeliveryEndpoint.length == 0) {
        completion(nil, NXError(NXAppAttestErrorNetworkFailed, @"keyDeliveryEndpoint not configured"));
        return;
    }

    [self refreshDeliveryKeyRegistrationWithCompletion:^(BOOL syncOK, NSError * _Nullable syncError) {
        if (!syncOK) {
            completion(nil, syncError ?: NXError(NXAppAttestErrorServerRejected, @"Delivery key registration sync failed"));
            return;
        }

        [self requestChallengeForPurpose:@"assertion" completion:^(NSData * _Nullable nonce, NSString * _Nullable nonceId, NSError * _Nullable challengeError) {
            if (challengeError != nil || nonce == nil || nonceId.length == 0) {
                completion(nil, challengeError ?: NXError(NXAppAttestErrorNonceExpired, @"Unable to obtain key delivery challenge"));
                return;
            }

            NSMutableDictionary *body = [NSMutableDictionary dictionary];
            body[@"key_id"] = self.storedKeyId;
            body[@"nonce_id"] = nonceId;
            body[@"challenge"] = NXBase64(nonce);
            body[@"device_posture"] = devicePosture ?: @{};
            body[@"os_version"] = [[UIDevice currentDevice] systemVersion] ?: @"<unknown>";
            body[@"timestamp_ms"] = @((long long)([[NSDate date] timeIntervalSince1970] * 1000.0));
            NSString *channelBinding = NXCurrentChannelBinding();
            if (channelBinding.length == 0 && [NXSecurityPolicy requiresServerChain]) {
                completion(nil, NXError(NXAppAttestErrorPinningFailed, @"Pinned TLS channel binding unavailable during key delivery"));
                return;
            }
            if (channelBinding.length > 0) body[@"tls_spki"] = channelBinding;

            NSError *canonicalError = nil;
            NSData *canonical = NXCanonicalJSONData(body, &canonicalError);
            if (canonical == nil || canonicalError != nil) {
                completion(nil, canonicalError ?: NXError(NXAppAttestErrorDecodeFailed, @"Failed to canonicalize key delivery request"));
                return;
            }

            [self generateAssertionForClientData:canonical completion:^(NSData * _Nullable assertion, NSError * _Nullable assertError) {
                if (assertError != nil || assertion == nil) {
                    completion(nil, assertError ?: NXError(NXAppAttestErrorAssertFailed, @"Failed to generate key delivery assertion"));
                    return;
                }

                NSMutableDictionary *finalBody = [body mutableCopy];
                finalBody[@"assertion"] = NXBase64(assertion);
                [self POSTJSONBody:finalBody endpoint:self.keyDeliveryEndpoint completion:^(NSDictionary * _Nullable jsonResp, NSHTTPURLResponse * _Nullable response, NSError * _Nullable networkError) {
                    if (networkError != nil) {
                        completion(nil, networkError);
                        return;
                    }
                    NSInteger statusCode = response.statusCode;
                    if (statusCode != 200) {
                        NSString *message = [jsonResp[@"error"] isKindOfClass:[NSString class]] ? jsonResp[@"error"] : [NSString stringWithFormat:@"Key delivery rejected: %ld", (long)statusCode];
                        completion(nil, NXServerError(statusCode, message));
                        return;
                    }
                    if (![jsonResp isKindOfClass:[NSDictionary class]]) {
                        completion(nil, NXError(NXAppAttestErrorDecodeFailed, @"Invalid key delivery response"));
                        return;
                    }

                    NSError *decryptError = nil;
                    NSData *payloadKey = [self decryptKeyEnvelopeFromResponse:jsonResp error:&decryptError];
                    if (payloadKey == nil || decryptError != nil) {
                        completion(nil, decryptError ?: NXError(NXAppAttestErrorCryptoFailed, @"Unable to decrypt key envelope"));
                        return;
                    }

                    NSError *sessionError = nil;
                    if (![self persistSessionFromResponse:jsonResp error:&sessionError]) {
                        completion(nil, sessionError ?: NXError(NXAppAttestErrorDecodeFailed, @"Missing or invalid session_token response"));
                        return;
                    }
                    completion(payloadKey, nil);
                }];
            }];
        }];
    }];
}

- (BOOL)persistSessionFromResponse:(NSDictionary *)response error:(NSError **)error {
    NSString *sessionToken = [response[@"session_token"] isKindOfClass:[NSString class]] ? response[@"session_token"] : nil;
    id ttlValue = response[@"session_ttl"];
    NSTimeInterval ttl = 0;
    if ([ttlValue isKindOfClass:[NSNumber class]]) {
        ttl = [(NSNumber *)ttlValue doubleValue];
    } else if ([ttlValue isKindOfClass:[NSString class]]) {
        ttl = [(NSString *)ttlValue doubleValue];
    }
    if (sessionToken.length == 0 || ttl <= 0) {
        if (error) *error = NXError(NXAppAttestErrorDecodeFailed, @"Server response missing valid session_token/session_ttl");
        return NO;
    }
    NSDate *expiry = [NSDate dateWithTimeIntervalSinceNow:ttl];
    [[SessionManager sharedManager] storeSessionToken:sessionToken expiresAt:expiry];
    return YES;
}

- (NSData *)decryptKeyEnvelopeFromResponse:(NSDictionary *)response error:(NSError **)error {
    NSDictionary *envelope = [response[@"key_envelope"] isKindOfClass:[NSDictionary class]] ? response[@"key_envelope"] : nil;
    if (envelope == nil) {
        if (error) *error = NXError(NXAppAttestErrorDecodeFailed, @"Response missing key_envelope");
        return nil;
    }

    NSString *algorithm = [envelope[@"algorithm"] isKindOfClass:[NSString class]] ? envelope[@"algorithm"] : nil;
    NSData *ephemeralPub = NXDataFromBase64(envelope[@"ephemeral_public_key"]);
    NSData *iv = NXDataFromBase64(envelope[@"iv"]);
    NSData *ciphertext = NXDataFromBase64(envelope[@"ciphertext"]);
    NSData *mac = NXDataFromBase64(envelope[@"mac"]);
    NSData *context = NXDataFromBase64(envelope[@"kdf_info"] ?: @"");

    if (![algorithm isEqualToString:kKeyEnvelopeAlgorithm] || ephemeralPub == nil || iv == nil || ciphertext == nil || mac == nil) {
        if (error) *error = NXError(NXAppAttestErrorDecodeFailed, @"Invalid or incomplete key envelope");
        return nil;
    }

    NSError *loadError = nil;
    SecKeyRef privateKey = [self loadOrCreateDeliveryPrivateKey:&loadError];
    if (privateKey == NULL) {
        if (error) *error = loadError ?: NXError(NXAppAttestErrorSecureEnclaveFail, @"Unable to access Secure Enclave delivery key");
        return nil;
    }

    CFErrorRef keyError = NULL;
    NSDictionary *pubAttrs = @{
        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
        (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPublic,
        (__bridge id)kSecAttrKeySizeInBits: @256,
    };
    SecKeyRef peerPublic = SecKeyCreateWithData((__bridge CFDataRef)ephemeralPub,
                                                (__bridge CFDictionaryRef)pubAttrs,
                                                &keyError);
    if (peerPublic == NULL) {
        CFRelease(privateKey);
        if (error) *error = keyError ? (__bridge_transfer NSError *)keyError : NXError(NXAppAttestErrorCryptoFailed, @"Invalid envelope public key");
        return nil;
    }

    NSDictionary *params = @{
        (__bridge id)kSecKeyKeyExchangeParameterRequestedSize: @64,
        (__bridge id)kSecKeyKeyExchangeParameterSharedInfo: context ?: [NSData data],
    };
    CFDataRef keyMaterialRef = SecKeyCopyKeyExchangeResult(privateKey,
                                                           kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256,
                                                           peerPublic,
                                                           (__bridge CFDictionaryRef)params,
                                                           &keyError);
    CFRelease(privateKey);
    CFRelease(peerPublic);
    if (keyMaterialRef == NULL) {
        if (error) *error = keyError ? (__bridge_transfer NSError *)keyError : NXError(NXAppAttestErrorCryptoFailed, @"Key agreement failed");
        return nil;
    }

    NSData *keyMaterial = CFBridgingRelease(keyMaterialRef);
    if (keyMaterial.length != 64) {
        if (error) *error = NXError(NXAppAttestErrorCryptoFailed, @"Unexpected key agreement output length");
        return nil;
    }

    NSData *encKey = [keyMaterial subdataWithRange:NSMakeRange(0, 32)];
    NSData *macKey = [keyMaterial subdataWithRange:NSMakeRange(32, 32)];
    NSData *macInput = NXBuildEnvelopeMACInput(ephemeralPub, iv, ciphertext, context);
    NSData *expectedMac = NXHMACSHA256(macKey, macInput);
    if (!NXConstantTimeEqual(expectedMac, mac)) {
        if (error) *error = NXError(NXAppAttestErrorCryptoFailed, @"Envelope MAC validation failed");
        return nil;
    }

    NSError *decryptError = nil;
    NSData *plaintext = NXAESCTR(encKey, iv, ciphertext, kCCDecrypt, &decryptError);
    if (plaintext == nil || decryptError != nil) {
        if (error) *error = decryptError ?: NXError(NXAppAttestErrorCryptoFailed, @"Envelope decryption failed");
        return nil;
    }
    if (plaintext.length != 32) {
        if (error) *error = NXError(NXAppAttestErrorCryptoFailed, @"Unexpected decrypted payload key length");
        return nil;
    }
    return plaintext;
}

#pragma mark - Transaction signing

- (NSString *)approvalPublicKeyBase64 {
    NSError *loadError = nil;
    SecKeyRef privateKey = [self loadSigningKeyWithPrompt:nil createIfMissing:YES error:&loadError];
    if (privateKey == NULL) return nil;

    SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
    CFRelease(privateKey);
    if (publicKey == NULL) return nil;

    CFErrorRef exportError = NULL;
    CFDataRef external = SecKeyCopyExternalRepresentation(publicKey, &exportError);
    CFRelease(publicKey);
    if (external == NULL) {
        if (exportError) CFRelease(exportError);
        return nil;
    }
    NSData *raw = CFBridgingRelease(external);
    // 0x04 || X || Y. Anything else is not the uncompressed P-256 point the server will parse.
    if (raw.length != 65 || ((const uint8_t *)raw.bytes)[0] != 0x04) return nil;
    return NXBase64(raw);
}

- (void)signTransactionData:(NSData *)data
                 completion:(void (^)(NSData * _Nullable signature, NSError * _Nullable error))completion {
    NSError *loadError = nil;
    SecKeyRef privateKey = [self loadSigningKeyWithPrompt:@"Authenticate to approve secure transaction"
                                           createIfMissing:YES
                                                     error:&loadError];
    if (privateKey == NULL) {
        completion(nil, loadError ?: NXError(NXAppAttestErrorSecureEnclaveFail, @"Failed to access biometric signing key"));
        return;
    }

    CFErrorRef signError = NULL;
    CFDataRef signatureRef = SecKeyCreateSignature(privateKey,
                                                   kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
                                                   (__bridge CFDataRef)data,
                                                   &signError);
    CFRelease(privateKey);
    if (signatureRef == NULL) {
        completion(nil, signError ? (__bridge_transfer NSError *)signError : NXError(NXAppAttestErrorCryptoFailed, @"Transaction signing failed"));
        return;
    }
    completion(CFBridgingRelease(signatureRef), nil);
}

#pragma mark - Cleanup

- (void)clearRegistration {
    [self clearRegistrationWithCompletion:nil];
}

- (void)clearRegistrationWithCompletion:(NXServerCleanupCompletion)completion {
    NSString *keyId = [self.storedKeyId copy];
    if (keyId.length == 0 || self.revokeEndpoint.length == 0) {
        [self clearLocalRegistrationStateForKeyId:keyId];
        if (completion) completion(NO, nil);
        return;
    }

    [self requestChallengeForPurpose:@"revoke" completion:^(NSData * _Nullable nonce, NSString * _Nullable nonceId, NSError * _Nullable challengeError) {
        if (challengeError != nil || nonce == nil || nonceId.length == 0) {
            [self clearLocalRegistrationStateForKeyId:keyId];
            if (completion) completion(NO, challengeError ?: NXError(NXAppAttestErrorNonceExpired, @"Unable to obtain revocation challenge"));
            return;
        }

        NSMutableDictionary *body = [NSMutableDictionary dictionary];
        body[@"key_id"] = keyId;
        body[@"nonce_id"] = nonceId;
        body[@"challenge"] = NXBase64(nonce);
        body[@"reason"] = @"client_clear_registration";
        body[@"timestamp_ms"] = @((long long)([[NSDate date] timeIntervalSince1970] * 1000.0));
        NSString *channelBinding = NXCurrentChannelBinding();
        if (channelBinding.length > 0) body[@"tls_spki"] = channelBinding;

        NSError *canonicalError = nil;
        NSData *canonical = NXCanonicalJSONData(body, &canonicalError);
        if (canonical == nil || canonicalError != nil) {
            [self clearLocalRegistrationStateForKeyId:keyId];
            if (completion) completion(NO, canonicalError ?: NXError(NXAppAttestErrorDecodeFailed, @"Failed to canonicalize revocation request"));
            return;
        }

        [self generateAssertionForClientData:canonical completion:^(NSData * _Nullable assertion, NSError * _Nullable assertError) {
            if (assertError != nil || assertion == nil) {
                [self clearLocalRegistrationStateForKeyId:keyId];
                if (completion) completion(NO, assertError ?: NXError(NXAppAttestErrorAssertFailed, @"Failed to generate revocation assertion"));
                return;
            }

            NSMutableDictionary *finalBody = [body mutableCopy];
            finalBody[@"assertion"] = NXBase64(assertion);
            [self POSTJSONBody:finalBody endpoint:self.revokeEndpoint completion:^(NSDictionary * _Nullable json, NSHTTPURLResponse * _Nullable response, NSError * _Nullable networkError) {
                BOOL serverRevoked = NO;
                NSError *finalError = networkError;
                if (networkError == nil) {
                    NSInteger statusCode = response.statusCode;
                    serverRevoked = (statusCode == 200);
                    if (!serverRevoked) {
                        NSString *message = [json[@"error"] isKindOfClass:[NSString class]] ? json[@"error"] : [NSString stringWithFormat:@"Revocation rejected: %ld", (long)statusCode];
                        finalError = NXError(NXAppAttestErrorServerRejected, message);
                    }
                }
                [self clearLocalRegistrationStateForKeyId:keyId];
                if (completion) completion(serverRevoked, finalError);
            }];
        }];
    }];
}

- (void)verifySessionStatusWithAuditHead:(NSString *)auditHead
                              completion:(void (^)(NSDictionary * _Nullable, NSError * _Nullable))completion {
    if (self.storedKeyId.length == 0) {
        completion(nil, NXError(NXAppAttestErrorKeyNotRegistered, @"Device not registered with App Attest"));
        return;
    }
    if (self.statusVerifyEndpoint.length == 0) {
        completion(nil, NXError(NXAppAttestErrorNotSupported, @"Status endpoint is not configured"));
        return;
    }
    NSString *sessionToken = [[SessionManager sharedManager] validSessionToken];
    if (sessionToken.length == 0) {
        completion(nil, NXError(NXAppAttestErrorKeyNotRegistered, @"No live session to verify"));
        return;
    }

    [self requestChallengeForPurpose:@"status" completion:^(NSData * _Nullable nonce, NSString * _Nullable nonceId, NSError * _Nullable challengeError) {
        if (challengeError != nil || nonce == nil || nonceId.length == 0) {
            completion(nil, challengeError ?: NXError(NXAppAttestErrorNonceExpired, @"Unable to obtain status challenge"));
            return;
        }

        NSMutableDictionary *body = [NSMutableDictionary dictionary];
        body[@"key_id"] = self.storedKeyId;
        body[@"nonce_id"] = nonceId;
        body[@"challenge"] = NXBase64(nonce);
        body[@"session_token"] = sessionToken;
        body[@"timestamp_ms"] = @((long long)([[NSDate date] timeIntervalSince1970] * 1000.0));
        if (auditHead.length > 0) body[@"audit_chain_head"] = auditHead;
        body[@"device_posture"] = @{
            @"threat_mask": @([RASPGuard sharedGuard].lastThreatMask),
            @"rasp_clean": @([RASPGuard sharedGuard].deviceClean),
            @"os_version": [[UIDevice currentDevice] systemVersion] ?: @"<unknown>",
            @"device_model": NXDeviceModel(),
        };
        NSString *channelBinding = NXCurrentChannelBinding();
        if (channelBinding.length == 0 && [NXSecurityPolicy requiresServerChain]) {
            completion(nil, NXError(NXAppAttestErrorPinningFailed, @"Pinned TLS channel binding unavailable during status verify"));
            return;
        }
        if (channelBinding.length > 0) body[@"tls_spki"] = channelBinding;

        NSError *canonicalError = nil;
        NSData *canonical = NXCanonicalJSONData(body, &canonicalError);
        if (canonical == nil) {
            completion(nil, canonicalError ?: NXError(NXAppAttestErrorDecodeFailed, @"Unable to canonicalize status body"));
            return;
        }

        [self generateAssertionForClientData:canonical completion:^(NSData * _Nullable assertion, NSError * _Nullable assertError) {
            if (assertion == nil) {
                completion(nil, assertError ?: NXError(NXAppAttestErrorAssertFailed, @"Status assertion failed"));
                return;
            }
            NSMutableDictionary *finalBody = [body mutableCopy];
            finalBody[@"assertion"] = NXBase64(assertion);
            [self POSTJSONBody:finalBody endpoint:self.statusVerifyEndpoint completion:^(NSDictionary * _Nullable json, NSHTTPURLResponse * _Nullable response, NSError * _Nullable networkError) {
                if (networkError != nil) { completion(nil, networkError); return; }
                if (response.statusCode < 200 || response.statusCode >= 300) {
                    completion(nil, NXServerError(response.statusCode, json[@"error"] ?: @"Status verification refused"));
                    return;
                }
                completion(json, nil);
            }];
        }];
    }];
}

- (void)clearLocalRegistrationImmediately {
    NSString *keyId = [self.storedKeyId copy];
    [self clearLocalRegistrationStateForKeyId:keyId];
}

- (void)clearLocalRegistrationStateForKeyId:(NSString *)keyId {
    [self deleteKeyIdFromKeychain];
    [self deleteDeliveryKeyFingerprint];
    [[SessionManager sharedManager] clearAll];

    NSDictionary *signingDelete = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassKey,
        (__bridge id)kSecAttrApplicationTag: [kKeychainSignKeyTag dataUsingEncoding:NSUTF8StringEncoding],
        (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave,
    };
    SecItemDelete((__bridge CFDictionaryRef)signingDelete);

    NSDictionary *deliveryDelete = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassKey,
        (__bridge id)kSecAttrApplicationTag: [kKeychainDeliveryKeyTag dataUsingEncoding:NSUTF8StringEncoding],
        (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave,
    };
    SecItemDelete((__bridge CFDictionaryRef)deliveryDelete);

    os_log_info(sAttestLog(), "[Nexilis/Attest] %{public}s", "Local registration cleared (keyId=%@). Note: App Attest key persists until app uninstall");
}

@end
