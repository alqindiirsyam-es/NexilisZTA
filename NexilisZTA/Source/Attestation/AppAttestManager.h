/*
 * AppAttestManager.h
 * Nexilis iOS ZTA Bundle V4 — App Attest + Secure Enclave Key Delivery
 */

#ifndef NEXILIS_APP_ATTEST_MANAGER_H
#define NEXILIS_APP_ATTEST_MANAGER_H

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^NXAttestRegistrationCompletion)(BOOL success, NSError * _Nullable error);
typedef void (^NXAssertionCompletion)(NSData * _Nullable assertion, NSError * _Nullable error);
typedef void (^NXKeyDeliveryCompletion)(NSData * _Nullable decryptionKey, NSError * _Nullable error);
typedef void (^NXServerCleanupCompletion)(BOOL serverRevoked, NSError * _Nullable error);

extern NSString * const NXAppAttestErrorDomain;

typedef NS_ENUM(NSInteger, NXAppAttestError) {
    NXAppAttestErrorNotSupported      = 1000,
    NXAppAttestErrorKeyGenFailed      = 1001,
    NXAppAttestErrorAttestFailed      = 1002,
    NXAppAttestErrorAssertFailed      = 1003,
    NXAppAttestErrorServerRejected    = 1004,
    NXAppAttestErrorNonceExpired      = 1005,
    NXAppAttestErrorKeyNotRegistered  = 1006,
    NXAppAttestErrorSecureEnclaveFail = 1007,
    NXAppAttestErrorNetworkFailed     = 1008,
    NXAppAttestErrorDecodeFailed      = 1009,
    NXAppAttestErrorCryptoFailed      = 1010,
    /* The boot chain was not where this step needs it to be. Reported instead of a bare
     * failure so the screen and the support inbox can name the stage that stopped. */
    NXAppAttestErrorFlowStateInvalid  = 1011,
    /* The server could not answer right now - a gateway error, a timeout, a rate limit. Kept
     * apart from ServerRejected, which means the server understood the request and said no:
     * one clears itself in a minute, the other is a decision about this device. Collapsing
     * both into ServerRejected is what put a reader in front of a screen with no way forward
     * for what was only a busy backend. */
    NXAppAttestErrorServerUnavailable = 1012,
    NXAppAttestErrorPinningFailed      = 1013,
};

@interface AppAttestManager : NSObject

+ (instancetype)sharedManager;

@property (nonatomic, strong, nullable) NSString *challengeEndpoint;
@property (nonatomic, strong, nullable) NSString *attestEndpoint;
@property (nonatomic, strong, nullable) NSString *registerEndpoint;
@property (nonatomic, strong, nullable) NSString *keyDeliveryEndpoint;
@property (nonatomic, strong, nullable) NSString *revokeEndpoint;
/// Where a live session is re-checked, and where the server hands back the signals it cannot
/// push: a revoked install, a signed pin rotation. Modes 1 and 2 only.
@property (nonatomic, strong, nullable) NSString *statusVerifyEndpoint;

/// Lowest iOS major version this app may attest from.
///
/// App Attest itself exists from iOS 14, but the ZTA service refuses a registration below its own
/// `minIosMajor` and answers `NXAppAttestErrorServerRejected`. Asking anyway turns a device the
/// service was never going to accept into a failed launch, so the client holds the same line and
/// reports it as unsupported instead. Defaults to 16, which is the service's own default.
@property (nonatomic, assign) NSInteger minimumOSMajor;
@property (nonatomic, readonly) BOOL isSupported;
@property (nonatomic, readonly) BOOL isRegistered;
@property (nonatomic, readonly, nullable) NSString *keyId;
#if DEBUG
/// Development-only escape hatch. This symbol is absent from non-Debug builds.
@property (nonatomic, assign) BOOL bypassPinningForDev;
#endif

- (void)registerDeviceWithCompletion:(NXAttestRegistrationCompletion)completion;
- (void)refreshDeliveryKeyRegistrationWithCompletion:(NXAttestRegistrationCompletion)completion;
- (void)generateAssertionForClientData:(NSData *)clientData completion:(NXAssertionCompletion)completion;
- (void)requestKeyDeliveryWithPosture:(NSDictionary *)devicePosture completion:(NXKeyDeliveryCompletion)completion;
/// Re-checks the live session against the server and returns whatever it answered.
///
/// The request is a nonce-bound App Attest assertion over the same canonical body the server
/// verifies, so a reply cannot be replayed and the poll cannot be spoofed by the network. The
/// audit head travels with it to be witnessed.
- (void)verifySessionStatusWithAuditHead:(nullable NSString *)auditHead
                              completion:(void (^)(NSDictionary * _Nullable status,
                                                   NSError * _Nullable error))completion;
/// X9.63 (uncompressed point) public half of the Secure Enclave approval key, base64.
///
/// Reading it never presents a prompt - only using the private half does - and creating the key
/// when it is missing does not either. Returns nil on a device where the key cannot exist, such as
/// one with no biometry enrolled, and a nil here is not a failure: the caller simply omits the
/// field, and the server then refuses sensitive decisions rather than accepting a weaker proof.
- (nullable NSString *)approvalPublicKeyBase64;

- (void)signTransactionData:(NSData *)data
                 completion:(void (^)(NSData * _Nullable signature,
                                      NSError * _Nullable error))completion;
- (void)clearRegistration;
- (void)clearRegistrationWithCompletion:(nullable NXServerCleanupCompletion)completion;
/// Emergency/duress path: destroys local App Attest registration and Secure-Enclave delivery/signing keys synchronously.
- (void)clearLocalRegistrationImmediately;
- (void)resetURLSession;

@end

NS_ASSUME_NONNULL_END

#endif /* NEXILIS_APP_ATTEST_MANAGER_H */
