#import "PrivacyShield.h"

@interface PrivacyShield ()
@property (nonatomic, weak) UIWindow *window;
@property (nonatomic, strong) UIView *privacyCoverView;
@property (nonatomic, assign, readwrite) BOOL captureActive;
@property (nonatomic, strong, readwrite, nullable) NSDate *lastScreenshotDate;
@end

@implementation PrivacyShield

+ (instancetype)sharedShield {
    static PrivacyShield *shield;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ shield = [PrivacyShield new]; });
    return shield;
}

- (void)installWithWindow:(UIWindow *)window {
    self.window = window;
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(appWillResign:) name:UIApplicationWillResignActiveNotification object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(appDidBecomeActive:) name:UIApplicationDidBecomeActiveNotification object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(userDidTakeScreenshot:) name:UIApplicationUserDidTakeScreenshotNotification object:nil];
    if (@available(iOS 11.0, *)) {
        [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(captureStateChanged:) name:UIScreenCapturedDidChangeNotification object:nil];
        self.captureActive = UIScreen.mainScreen.isCaptured;
        if (self.captureActive) {
            [self showCover];
        }
    }
}

- (void)appWillResign:(NSNotification *)note { [self showCover]; }
- (void)appDidBecomeActive:(NSNotification *)note {
    if (!self.captureActive) {
        [self hideCover];
    } else {
        [self showCover];
    }
}
- (void)userDidTakeScreenshot:(NSNotification *)note { self.lastScreenshotDate = [NSDate date]; }
- (void)captureStateChanged:(NSNotification *)note {
    if (@available(iOS 11.0, *)) {
        self.captureActive = UIScreen.mainScreen.isCaptured;
        if (self.captureActive) {
            [self showCover];
        } else if (UIApplication.sharedApplication.applicationState == UIApplicationStateActive) {
            [self hideCover];
        }
    }
}

- (void)showCover {
    UIWindow *targetWindow = self.window;
    if (targetWindow == nil) {
        for (UIWindow *candidate in UIApplication.sharedApplication.windows) {
            if (candidate.isHidden == NO) { targetWindow = candidate; break; }
        }
    }
    if (targetWindow == nil) return;
    if (self.privacyCoverView.superview == targetWindow) return;
    [self.privacyCoverView removeFromSuperview];
    UIView *cover = [[UIView alloc] initWithFrame:targetWindow.bounds];
    cover.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    if (@available(iOS 13.0, *)) { cover.backgroundColor = UIColor.systemBackgroundColor; } else { cover.backgroundColor = UIColor.whiteColor; }
    UILabel *label = [[UILabel alloc] initWithFrame:cover.bounds];
    label.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    label.textAlignment = NSTextAlignmentCenter;
    label.numberOfLines = 0;
    label.text = @"Protected view hidden while inactive or captured";
    [cover addSubview:label];
    self.privacyCoverView = cover;
    [targetWindow addSubview:cover];
}

- (void)hideCover {
    [self.privacyCoverView removeFromSuperview];
}

@end
