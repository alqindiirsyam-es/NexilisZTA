#ifndef NEXILIS_PRIVACY_SHIELD_H
#define NEXILIS_PRIVACY_SHIELD_H

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface PrivacyShield : NSObject
+ (instancetype)sharedShield;
- (void)installWithWindow:(UIWindow *)window;
@property (nonatomic, readonly) BOOL captureActive;
@property (nonatomic, readonly, nullable) NSDate *lastScreenshotDate;
@end

NS_ASSUME_NONNULL_END

#endif
