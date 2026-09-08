//
//  NXSecurityPolicy.m
//  NexilisZTA
//

#import "NXSecurityPolicy.h"
#import <stdatomic.h>

// Read from RASP callbacks and background URLSession queues as well as the main
// thread, so it is an atomic rather than a plain static.
static _Atomic(NSInteger) _nx_app_mode = NXAppModeRegular;

@implementation NXSecurityPolicy

+ (NXAppMode)mode {
    return (NXAppMode)atomic_load(&_nx_app_mode);
}

+ (void)setMode:(NXAppMode)mode {
    // An out-of-range number is the tolerant mode, not an undefined one: this value arrives from
    // a host's own integer, and the same guard exists on the Android side.
    if (mode != NXAppModeHSA && mode != NXAppModeMiddle && mode != NXAppModeRegular) {
        mode = NXAppModeRegular;
    }
    atomic_store(&_nx_app_mode, (NSInteger)mode);
}

+ (BOOL)isHSA                     { return [self mode] == NXAppModeHSA; }
+ (BOOL)requiresServerChain       { return [self mode] <= NXAppModeMiddle; }
+ (BOOL)bindsKeysToUserAuth       { return [self mode] == NXAppModeHSA; }
+ (BOOL)revokesOnRuntimeThreat    { return [self mode] <= NXAppModeMiddle; }
+ (BOOL)terminatesOnUnhandledThreat { return [self mode] == NXAppModeHSA; }

@end
