//
//  NXSecurityPolicy.h
//  NexilisZTA
//
//  The one number that says how much a host is willing to be stopped by.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// The host's application mode, the same 1/2/3 the Android SDK calls `mode_app` and the same
/// number `Utils.getAppMode()` has always carried on this side. It is deliberately not a second
/// vocabulary: one host, one number, one meaning on both platforms.
///
/// The login and 2FA half of this was already graded by mode long before Sentinel existed
/// (SignUpSignIn, SignInOption, MFAViewController, TFAPasswordVC). What the enum below adds is
/// the security-posture half: how much of the NX-01..NX-23 remediation is a precondition.
typedef NS_ENUM(NSInteger, NXAppMode) {
    /// High Security Assurance. No tolerance. App Attest and a live server-issued ZTA token are
    /// preconditions, release identity and the pin-rotation signer must be configured, the master
    /// key is held behind a Keychain biometric ACL with no process cache and no unattended
    /// access, and a runtime compromise ends the session - terminating the process when the host
    /// installed no delegate to handle it.
    NXAppModeHSA = 1,

    /// The server half of HSA with the user half of Regular. App Attest, the ZTA token, the
    /// distinct pins and the offline park are all still preconditions, and a runtime compromise
    /// still revokes - but the process is never terminated, and the master key stays a
    /// device-only item the app can read in the background, with biometry offered rather than
    /// enforced by the OS.
    NXAppModeMiddle = 2,

    /// Tolerant, and the default. The service decides whether App Attest applies, a launch with
    /// no network still opens the session, and the host keeps working without a ZTA token.
    /// Detection still runs and is still reported; what happens next is the server-configured
    /// SecurityShield policy's decision, not this layer's.
    NXAppModeRegular = 3,
};

/// Process-wide, pushed from `APIS.setAppMode(mode:)` or the ZTA configuration before the chain
/// starts. It is read from pre-main RASP callbacks and background URLSession queues, so it is a
/// plain atomic with no I/O - never a preference lookup.
///
/// Defaults to `NXAppModeRegular`, because this is the application mode and that has always been
/// its default. A host that wants to be stopped by these controls says so.
@interface NXSecurityPolicy : NSObject

@property (class, nonatomic, assign) NXAppMode mode;

/// Mode 1. The strictest handling of local data: biometric-ACL master key, no legacy server
/// envelope, no plaintext materialization.
+ (BOOL)isHSA;

/// Modes 1 and 2. App Attest is mandatory, a live server-issued token gates protected traffic,
/// an unreachable service parks instead of opening the session, and the API key and the two
/// distinct pins are preconditions rather than options.
+ (BOOL)requiresServerChain;

/// Mode 1. The master key is held under a Keychain `SecAccessControl` with `biometryCurrentSet`,
/// kept out of any process cache, and refused to unattended background work.
+ (BOOL)bindsKeysToUserAuth;

/// Modes 1 and 2. A RASP finding, a first-party pin mismatch or a severe legacy SecurityShield
/// detection revokes the current authorization instead of only being reported.
+ (BOOL)revokesOnRuntimeThreat;

/// Mode 1. A compromised process with no RASP response delegate installed is terminated rather
/// than left running.
+ (BOOL)terminatesOnUnhandledThreat;

@end

NS_ASSUME_NONNULL_END
