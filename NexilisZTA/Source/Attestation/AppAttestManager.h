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
};

@interface AppAttestManager : NSObject

+ (instancetype)sharedManager;

@property (nonatomic, strong, nullable) NSString *challengeEndpoint;
@property (nonatomic, strong, nullable) NSString *attestEndpoint;
@property (nonatomic, strong, nullable) NSString *registerEndpoint;
@property (nonatomic, strong, nullable) NSString *keyDeliveryEndpoint;
@property (nonatomic, strong, nullable) NSString *revokeEndpoint;

@property (nonatomic, readonly) BOOL isSupported;
@property (nonatomic, readonly) BOOL isRegistered;
@property (nonatomic, readonly, nullable) NSString *keyId;
@property (nonatomic, assign) BOOL bypassPinningForDev;

- (void)registerDeviceWithCompletion:(NXAttestRegistrationCompletion)completion;
- (void)refreshDeliveryKeyRegistrationWithCompletion:(NXAttestRegistrationCompletion)completion;
- (void)generateAssertionForClientData:(NSData *)clientData completion:(NXAssertionCompletion)completion;
- (void)requestKeyDeliveryWithPosture:(NSDictionary *)devicePosture completion:(NXKeyDeliveryCompletion)completion;
- (void)signTransactionData:(NSData *)data
                 completion:(void (^)(NSData * _Nullable signature,
                                      NSError * _Nullable error))completion;
- (void)clearRegistration;
- (void)clearRegistrationWithCompletion:(nullable NXServerCleanupCompletion)completion;
- (void)resetURLSession;

@end

NS_ASSUME_NONNULL_END

#endif /* NEXILIS_APP_ATTEST_MANAGER_H */
