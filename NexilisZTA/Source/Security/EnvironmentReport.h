/*
 * EnvironmentReport.h
 * Nexilis iOS ZTA Bundle V4 — Device Posture Aggregation
 */

#ifndef NEXILIS_ENVIRONMENT_REPORT_H
#define NEXILIS_ENVIRONMENT_REPORT_H

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface EnvironmentReport : NSObject

/**
 * Generate a device posture report using cached RASP results.
 *
 * Uses the last periodic-monitor result (RASPGuard.lastThreatMask) if
 * it is less than maxAge seconds old. If stale or no monitor has run,
 * executes a fresh check. Default maxAge: 60 seconds.
 *
 * This avoids the 600ms+ worst-case of running fresh Frida port scans
 * on every key delivery request.
 */
+ (NSDictionary *)generateReport;
+ (NSDictionary *)generateReportWithMaxAge:(NSTimeInterval)maxAge;
+ (BOOL)isEnvironmentClean;
+ (NSDictionary *)riskEnvelope;

@end

NS_ASSUME_NONNULL_END
#endif
