#ifndef NEXILIS_PRIVACY_SHIELD_H
#define NEXILIS_PRIVACY_SHIELD_H

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

/// Builds the view the privacy cover shows. Set by the Swift half (SentinelPrivacy) to the
/// Sentinel screen; without one the cover is a plain dark view.
typedef UIView * _Nonnull (^NXPrivacyCoverProvider)(void);

/// Covers the app while it is inactive (app switcher snapshot, Control Centre, calls) and while the
/// screen is being recorded, mirrored or AirPlayed. Screenshots cannot be covered here - iOS says
/// nothing until after the image is taken - and are handled by SentinelPrivacy's secure layer.
///
/// Capture state and the last screenshot time are tracked from `installWithWindow:` on whatever
/// the switches say, because the environment report reads them.
@interface PrivacyShield : NSObject
+ (instancetype)sharedShield;
- (void)installWithWindow:(nullable UIWindow *)window;

/// Cover while the app is not active. Default YES.
@property (nonatomic, assign) BOOL coverOnInactive;
/// Cover while the screen is recorded, mirrored or AirPlayed. Default YES.
@property (nonatomic, assign) BOOL coverOnCapture;
@property (nonatomic, copy, nullable) NXPrivacyCoverProvider coverProvider;

@property (nonatomic, readonly) BOOL captureActive;
@property (nonatomic, readonly, nullable) NSDate *lastScreenshotDate;
@end

NS_ASSUME_NONNULL_END

#endif
