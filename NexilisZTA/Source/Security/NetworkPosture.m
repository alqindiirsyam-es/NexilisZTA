#import "NetworkPosture.h"
#import <CFNetwork/CFNetwork.h>

@implementation NetworkPosture

+ (NSArray<NSString *> *)trustedVPNInterfacePrefixes {
    id value = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"NexilisTrustedVPNInterfacePrefixes"];
    if (![value isKindOfClass:[NSArray class]]) {
        return @[];
    }
    NSMutableArray<NSString *> *prefixes = [NSMutableArray array];
    for (id item in (NSArray *)value) {
        if ([item isKindOfClass:[NSString class]] && [(NSString *)item length] > 0) {
            [prefixes addObject:[(NSString *)item lowercaseString]];
        }
    }
    return prefixes.copy;
}

+ (NSDictionary *)currentPosture {
    NSDictionary *proxy = CFBridgingRelease(CFNetworkCopySystemProxySettings());
    if (![proxy isKindOfClass:[NSDictionary class]]) {
        proxy = @{};
    }

    BOOL httpProxy  = [proxy[@"HTTPEnable"] boolValue];
    BOOL httpsProxy = [proxy[@"HTTPSEnable"] boolValue];
    BOOL socksProxy = [proxy[@"SOCKSEnable"] boolValue];
    BOOL vpn = NO;
    BOOL trustedVPN = NO;
    NSString *vpnInterface = nil;

    NSDictionary *scoped = proxy[@"__SCOPED__"];
    NSArray<NSString *> *trustedPrefixes = [self trustedVPNInterfacePrefixes];
    if ([scoped isKindOfClass:[NSDictionary class]]) {
        for (NSString *key in scoped.allKeys) {
            NSString *lower = [key lowercaseString];
            if ([lower hasPrefix:@"tap"] || [lower hasPrefix:@"tun"] || [lower hasPrefix:@"ppp"] || [lower hasPrefix:@"ipsec"] || [lower hasPrefix:@"utun"]) {
                vpn = YES;
                vpnInterface = key;
                for (NSString *trustedPrefix in trustedPrefixes) {
                    if ([lower hasPrefix:trustedPrefix]) {
                        trustedVPN = YES;
                        break;
                    }
                }
                break;
            }
        }
    }

    return @{
        @"vpn_active": @(vpn),
        @"vpn_trusted": @(trustedVPN),
        @"vpn_risky": @(vpn && !trustedVPN),
        @"vpn_interface": vpnInterface ?: [NSNull null],
        @"http_proxy_enabled": @(httpProxy),
        @"https_proxy_enabled": @(httpsProxy),
        @"socks_proxy_enabled": @(socksProxy)
    };
}

@end
