//
//  RASPBridge.m
//  SampleAppShield
//
//  Created by Qindi on 01/04/26.
//


#import "RASPGuard.h"

@interface NexilisRASPBridge : NSObject
@end

@implementation NexilisRASPBridge

+ (void)load {
    [RASPGuard install];

//    uint32_t mask = (uint32_t)[[RASPGuard sharedGuard] lastThreatMask];
//    NSString *log = [NSString stringWithFormat:
//        @"threatMask: 0x%08X\ndeviceClean: %@\ntimestamp: %@\n",
//        mask,
//        [RASPGuard sharedGuard].deviceClean ? @"YES" : @"NO",
//        [NSDate date]];
//    
//    NSString *path = [NSSearchPathForDirectoriesInDomains(
//        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
//    NSString *file = [path stringByAppendingPathComponent:@"rasp_log.txt"];
//    [log writeToFile:file atomically:YES encoding:NSUTF8StringEncoding error:nil];
//    
//    // Print ke console dengan prefix filter khusus
//    NSLog(@"[NEXILIS_RASP] ================================");
//    NSLog(@"[NEXILIS_RASP] threatMask : 0x%08X", mask);
//    NSLog(@"[NEXILIS_RASP] deviceClean: %@", [RASPGuard sharedGuard].deviceClean ? @"YES" : @"NO");
//    NSLog(@"[NEXILIS_RASP] timestamp  : %@", [NSDate date]);
//    NSLog(@"[NEXILIS_RASP] ================================");
}

@end
