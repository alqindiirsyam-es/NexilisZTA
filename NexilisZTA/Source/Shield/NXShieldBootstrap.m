//
//  NXShieldBootstrap.m
//  Nexilis iOS ZTA — no-code shielding entry point
//
#import "NXShieldBootstrap.h"
#import <UIKit/UIKit.h>

@implementation NXShieldBootstrap

+ (void)load {
    // Pre-main, and cheap: one bundle lookup. Everything else waits for the app to exist.
    if ([[NSBundle mainBundle] URLForResource:@"NexilisShield" withExtension:@"plist"] == nil) {
        return;
    }
    __block id token = nil;
    token = [[NSNotificationCenter defaultCenter]
             addObserverForName:UIApplicationDidFinishLaunchingNotification
                         object:nil
                          queue:[NSOperationQueue mainQueue]
                     usingBlock:^(NSNotification * _Nonnull note) {
        [[NSNotificationCenter defaultCenter] removeObserver:token];
        token = nil;
        // By runtime name, not by import: the Swift half is a separate module under SwiftPM, and
        // this file must not depend on the generated Swift header in either build system.
        Class autostart = NSClassFromString(@"NXShieldAutostart");
        SEL start = NSSelectorFromString(@"start");
        if ([autostart respondsToSelector:start]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
            [autostart performSelector:start];
#pragma clang diagnostic pop
        } else {
            NSLog(@"[NexilisShield] NexilisShield.plist present but NXShieldAutostart is missing");
        }
    }];
}

@end
