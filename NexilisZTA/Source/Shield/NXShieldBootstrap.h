//
//  NXShieldBootstrap.h
//  Nexilis iOS ZTA — no-code shielding entry point
//
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Loaded into a host that never calls NexilisZTA itself - the `nexilis-shield` tool adds the
/// framework to an already-built app and a load command to its executable. `+load` looks for
/// `NexilisShield.plist` in the main bundle and, only if it is there, starts the ZTA chain as soon
/// as the application has finished launching. A host that links NexilisZTA the ordinary way ships
/// no such plist, and this class does nothing.
@interface NXShieldBootstrap : NSObject
@end

NS_ASSUME_NONNULL_END
