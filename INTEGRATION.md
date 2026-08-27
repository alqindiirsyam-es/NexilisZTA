# NexilisZTA — integration

Zero Trust hardening for iOS, packaged the same way as NexilisLite. RASP (jailbreak, debugger,
Frida, injection, inline/GOT hooks, code signature), App Attest with key delivery, certificate
pinning with rotation, secure input, privacy shield, session teardown.

## Install

```ruby
target 'YourApp' do
  use_frameworks!
  pod 'NexilisZTA', :path => '../NexilisZTA'
end
```

```swift
import NexilisZTA
```

No bridging header. The Objective-C and C headers are public headers of the pod, so Swift reaches
`RASPGuard`, `AppAttestManager`, `stateGet()/stateSet()` and the `NXEncrypted*` functions through
the module.

The pod has no dependencies — not on NexilisLite either — so it drops into a host that uses none of
the rest of the Nexilis stack.

## What is in it

| Area | Entry points |
| --- | --- |
| RASP | `RASPGuard`, `rasp_native.h`, installed from `RASPBridge`'s `+load` |
| Attestation | `AppAttestService`, `AppAttestManager`, `NXAppAttestErrorDomain` |
| Pinning | `RASPGuard.configurePinning`, `PinnedURLSessionDelegate`, `PinSetStore` (rotation) |
| Secure input | `SensitiveTextField`, `SecureNumericKeypad`, `SecureInput` |
| Screen privacy | `PrivacyShield` |
| Teardown | `SecureWipe`, `SessionManager` |
| Posture | `EnvironmentReport`, `NetworkPosture`, `DuressManager`, `GeofencePolicy` |
| Web | `SecureWebViewFactory` |
| Flow state | `GlobalState.h` — the `NX_STATE_*` chain |
| Logging | `NXLogger` |

## What the host must provide

These cannot live in a library — they belong to the app that ships:

| Requirement | Where |
| --- | --- |
| `com.apple.developer.devicecheck.appattest-environment` | app entitlements — App Attest does nothing without it |
| `com.apple.developer.networking.wifi-info` | app entitlements — only if `NetworkPosture` reads the SSID |
| `NSLocationWhenInUseUsageDescription` | Info.plist — only if `GeofencePolicy` is used |

## Configuration

`configure` is optional. Left uncalled, the layer runs on the values compiled into
`EncryptedStrings.mm`, which are OneApp's — that host needs to do nothing.

Any other host points it at its own service:

```swift
NexilisZTA.configure(
    baseURL: "https://your.host/zta-ios",
    appName: "YourApp",
    apiKey:  "…",
    primaryPin: "sha256/…",
    backupPin:  "sha256/…"
)
```

The seven endpoints are derived from `baseURL` with the paths the service already uses
(`/zta/challenge`, `/zta/attest`, `/zta/assert`, `/zta/status/verify`, `/zta/register`, `/zta/key`,
`/zta/revoke`). Pass a fully built `NexilisZTAConfiguration` instead if any of them differs.

`configure` applies the two things that are applied once — the certificate pins and the App Attest
endpoints — so call it from `application(_:didFinishLaunchingWithOptions:)`, before anything
reaches the network.

### The obfuscated constants

The built-in values are encrypted at compile time and never appear as strings in the binary:

```
$ strings NexilisZTA.framework/NexilisZTA | grep -c nexilis.io/zta
0
```

Three things have to hold for that, and all three are set up in this pod — worth knowing before
anyone moves the files around:

- **`EncryptedStrings.mm`, not `.m`.** `ENCRYPTED_NSSTRING` only encrypts under `__cplusplus`; in a
  plain `.m` it falls through to `ENCRYPTED_NSSTRING_RUNTIME`, which hands back the literal
  untouched. The file was `.m` while the code lived inside OneApp, so none of the values were
  actually obfuscated then, whatever the names suggested.
- **`extern "C"` in `EncryptedStrings.h`.** Compiled as C++, the definitions would otherwise get
  C++ linkage and mangled names while every caller looks for the plain C symbol, and the framework
  would not link.
- **`gnu++20`.** The ciphertext is built in a `constexpr` constructor; below that standard the
  compiler rejects it as *"must be initialized by a constant expression"*. Set in the podspec's
  `pod_target_xcconfig`, so a host gets it without doing anything.

To add a constant, declare it in `EncryptedStrings.h` inside the `extern "C"` block, define it in
`EncryptedStrings.mm`, and wrap the literal in `ENCRYPTED_NSSTRING(...)`.

If the encoder in `StringEncryptor.h` is ever touched, round-trip it across a range of lengths
first. Its shuffle step is `(i * stride + 11) mod N`, which is only reversible while `stride` and
`N` are coprime — with the stride fixed at 7, every string whose length + 1 was a multiple of 7
came back corrupted, `"OneApp"` among them, and nothing said so. The stride is chosen per length
now. Verified over lengths 1–299.

A value the host passes to `configure` is the host's own literal and is obfuscated only as well as
the host obfuscates it. `ENCRYPTED_NSSTRING` is available to hosts that want the same treatment,
provided they compile the call site as Objective-C++.

## Startup

`RASPBridge` runs `[RASPGuard install]` from `+load`, so the RASP chain still arms itself when the
framework loads. The state machine in `GlobalState.h` is strictly sequential and expects to run
once per launch; `AppAttestService` refuses to move if the previous step has not been reached.

Typical flow, as OneApp drives it:

```swift
RASPGuard.shared().configurePinning(withPrimaryPin: …, backupPin: …)   // or NexilisZTA.configure
AppAttestService.shared.configure()                                    // -> state 16
AppAttestService.shared.registerDevice { … }                           // -> state 21
AppAttestService.shared.performAssertion { … }                         // -> state 22
AppAttestService.shared.requestKeyDelivery { key, error in … }         // -> state 23
```

Failures arrive as `NSError` in the `NXAppAttestErrorDomain` domain.

OneApp calls those two setup steps itself rather than going through `NexilisZTA.configure`, and on
purpose: it pins at launch but holds the App Attest endpoints back until its feature-access policy
says attestation is on at all. `configure` does both at once, which is right for a host with no
such switch and wrong for this one. A host that wants the split can call
`RASPGuard.configurePinning` and `AppAttestService.configure` separately the same way.
