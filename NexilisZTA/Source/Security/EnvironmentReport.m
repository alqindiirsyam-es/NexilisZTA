/*
 * EnvironmentReport.m
 * Nexilis iOS ZTA Bundle V4 — Device Posture Aggregation
 */

#import "EnvironmentReport.h"
#import "RASPGuard.h"
#import "NetworkPosture.h"
#import "PrivacyShield.h"
#import <UIKit/UIKit.h>
#import <sys/utsname.h>

static NSTimeInterval _lastCheckTimestamp = 0;
static const NSTimeInterval kDefaultMaxAge = 60.0;

@implementation EnvironmentReport

+ (NSDictionary *)generateReport {
    return [self generateReportWithMaxAge:kDefaultMaxAge];
}

+ (NSDictionary *)generateReportWithMaxAge:(NSTimeInterval)maxAge {
    RASPGuard *guard = [RASPGuard sharedGuard];
    NSTimeInterval now = [[NSProcessInfo processInfo] systemUptime];

    uint32_t threats;
    if (_lastCheckTimestamp > 0 && (now - _lastCheckTimestamp) < maxAge && guard.lastThreatMask != UINT32_MAX) {
        /* Use cached result from periodic monitor */
        threats = guard.lastThreatMask;
    } else {
        /* Stale or first call — run fresh checks */
        threats = [guard runChecksNow];
        _lastCheckTimestamp = now;
    }

    struct utsname info;
    memset(&info, 0, sizeof(info));
    uname(&info);

    NSBundle *bundle = [NSBundle mainBundle];
    NSString *version = [bundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"0";
    NSString *build = [bundle objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"0";
    NSString *bundleId = bundle.bundleIdentifier ?: @"<unknown>";

    NSMutableDictionary *report = [@{
        @"bundle_id": bundleId,
        @"app_version": version,
        @"build_number": build,
        @"os_version": [[UIDevice currentDevice] systemVersion] ?: @"<unknown>",
        @"device_model": [NSString stringWithCString:info.machine encoding:NSUTF8StringEncoding] ?: @"<unknown>",
        @"threat_mask": @(threats),
        @"threats_detected": @(threats != RASP_THREAT_NONE),
        @"rasp_clean": @(threats == RASP_THREAT_NONE),
        @"pinning_enabled": @(guard.pinningConfigured),
        @"timestamp_ms": @((long long)([[NSDate date] timeIntervalSince1970] * 1000.0)),
    } mutableCopy];
    [report addEntriesFromDictionary:[NetworkPosture currentPosture]];
    PrivacyShield *shield = [PrivacyShield sharedShield];
    report[@"capture_active"] = @(shield.captureActive);
    report[@"last_screenshot_ms"] = shield.lastScreenshotDate ? @((long long)(shield.lastScreenshotDate.timeIntervalSince1970 * 1000.0)) : [NSNull null];
    return report;
}

+ (BOOL)isEnvironmentClean {
    NSDictionary *report = [self generateReportWithMaxAge:kDefaultMaxAge];
    NSNumber *clean = [report[@"rasp_clean"] isKindOfClass:[NSNumber class]] ? report[@"rasp_clean"] : nil;
    return clean.boolValue;
}

+ (NSDictionary *)riskEnvelope {
    return [self generateReportWithMaxAge:kDefaultMaxAge];
}

@end
