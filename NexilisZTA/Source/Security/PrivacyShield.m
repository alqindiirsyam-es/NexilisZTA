#import "PrivacyShield.h"

@interface PrivacyShield ()
@property (nonatomic, weak) UIWindow *window;
@property (nonatomic, strong, nullable) UIWindow *coverWindow;
@property (nonatomic, assign) BOOL observing;
@property (nonatomic, assign, readwrite) BOOL captureActive;
@property (nonatomic, strong, readwrite, nullable) NSDate *lastScreenshotDate;
@end

@implementation PrivacyShield

+ (instancetype)sharedShield {
    static PrivacyShield *shield;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shield = [PrivacyShield new];
        shield.coverOnInactive = YES;
        shield.coverOnCapture = YES;
    });
    return shield;
}

- (void)installWithWindow:(UIWindow *)window {
    if (window != nil) self.window = window;
    if (self.observing) { [self refresh]; return; }
    self.observing = YES;
    NSNotificationCenter *center = [NSNotificationCenter defaultCenter];
    [center addObserver:self selector:@selector(appWillResign:) name:UIApplicationWillResignActiveNotification object:nil];
    [center addObserver:self selector:@selector(appDidBecomeActive:) name:UIApplicationDidBecomeActiveNotification object:nil];
    [center addObserver:self selector:@selector(userDidTakeScreenshot:) name:UIApplicationUserDidTakeScreenshotNotification object:nil];
    [center addObserver:self selector:@selector(captureStateChanged:) name:UIScreenCapturedDidChangeNotification object:nil];
    self.captureActive = UIScreen.mainScreen.isCaptured;
    [self refresh];
}

- (void)appWillResign:(NSNotification *)note {
    if (self.coverOnInactive) [self showCover];
}
- (void)appDidBecomeActive:(NSNotification *)note { [self refresh]; }
- (void)userDidTakeScreenshot:(NSNotification *)note { self.lastScreenshotDate = [NSDate date]; }
- (void)captureStateChanged:(NSNotification *)note {
    self.captureActive = UIScreen.mainScreen.isCaptured;
    [self refresh];
}

/// The cover the current state calls for, on or off.
- (void)refresh {
    BOOL inactive = UIApplication.sharedApplication.applicationState != UIApplicationStateActive;
    if ((self.coverOnCapture && self.captureActive) || (self.coverOnInactive && inactive && self.coverWindow != nil)) {
        [self showCover];
    } else {
        [self hideCover];
    }
}

- (UIWindowScene *)scene {
    UIWindowScene *scene = self.window.windowScene;
    if (scene != nil) return scene;
    for (UIScene *candidate in UIApplication.sharedApplication.connectedScenes) {
        if ([candidate isKindOfClass:[UIWindowScene class]]) return (UIWindowScene *)candidate;
    }
    return nil;
}

/// A window of its own above everything the app shows - the host, the shield's cover, policy
/// alerts - so the app-switcher snapshot and a recording show the cover and nothing under it.
/// Never key: it must not take input or the first responder away from the host.
- (void)showCover {
    if (self.coverWindow != nil) { self.coverWindow.hidden = NO; return; }
    UIWindowScene *scene = [self scene];
    if (scene == nil) return;
    UIWindow *cover = [[UIWindow alloc] initWithWindowScene:scene];
    cover.windowLevel = UIWindowLevelAlert + 10;
    cover.backgroundColor = UIColor.blackColor;
    UIViewController *host = [UIViewController new];
    UIView *view = self.coverProvider ? self.coverProvider() : nil;
    if (view == nil) {
        view = [[UIView alloc] initWithFrame:cover.bounds];
        view.backgroundColor = [UIColor colorWithRed:0x0B / 255.0 green:0x14 / 255.0 blue:0x20 / 255.0 alpha:1];
    }
    view.frame = cover.bounds;
    view.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    host.view = view;
    cover.rootViewController = host;
    cover.userInteractionEnabled = NO;
    cover.hidden = NO;
    self.coverWindow = cover;
}

- (void)hideCover {
    self.coverWindow.hidden = YES;
    self.coverWindow = nil;
}

@end
