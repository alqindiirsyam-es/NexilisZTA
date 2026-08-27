#ifndef NEXILIS_NETWORK_POSTURE_H
#define NEXILIS_NETWORK_POSTURE_H

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface NetworkPosture : NSObject
+ (NSDictionary *)currentPosture;
+ (NSArray<NSString *> *)trustedVPNInterfacePrefixes;
@end

NS_ASSUME_NONNULL_END

#endif
