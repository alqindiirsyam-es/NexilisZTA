# NexilisZTA — Swift Package Manager

Zero Trust hardening for iOS: RASP (jailbreak, debugger, Frida, injection, inline/GOT
hooks, code signature), App Attest with key delivery, certificate pinning with rotation,
secure input, privacy shield, and session teardown.

## Install

```swift
.package(url: "https://github.com/alqindiirsyam-es/NexilisZTA.git", from: "1.0.0")
```

Then add the product to your target:

```swift
.product(name: "NexilisZTA", package: "NexilisZTA")
```

In Xcode: **File → Add Package Dependencies…**, paste the URL above.

## Use

```swift
import NexilisZTA

NexilisZTA.configure(
    baseURL: "https://your.host",
    // …
)
```

Only `NexilisZTA` is meant to be imported. `NexilisZTACore` exists for the reason below
and is not the public surface, even though SwiftPM makes it visible.

## Why there are two targets

CocoaPods builds Swift and Objective-C as a single mixed-language target, so the Swift
half of this library sees `RASPGuard`, `AppAttestManager` and the rest through the
generated umbrella header without anyone importing anything.

SwiftPM has no mixed-language target. The Objective-C, Objective-C++ and C files
therefore live in their own target, `NexilisZTACore`, and the Swift target depends on
it. The four Swift files that reach into that half carry:

```swift
#if SWIFT_PACKAGE
import NexilisZTACore
#endif
```

so the CocoaPods build is unchanged — the guard compiles to nothing there.

Both targets are rooted at the same directory (`NexilisZTA/Source`) with explicit,
disjoint `sources` lists, so the tree stays laid out exactly as the pod expects it and
the two build systems read the same files.

### Header search paths

CocoaPods flattens every public header into one directory, which is why the sources can
say `#import "RASPGuard.h"` from anywhere. SwiftPM keeps the tree as it is, so each
directory that holds a header is put on the search path in `Package.swift`. The sources
themselves are untouched.

### C++

`StringEncryptor.h` builds its ciphertext in a `constexpr` constructor, which needs
C++20. The package sets `cxxLanguageStandard: .gnucxx20` at the package level rather
than reaching for `unsafeFlags` — a package that uses `unsafeFlags` cannot be depended on
by version, which would make this package unusable as a released dependency.

The C++ in `StringEncryptor.h`, `EncryptedStrings.h` and `rasp_native.h` sits behind
`__cplusplus` guards, so those headers stay importable from Swift.

## Simulator

This package builds and runs on the Simulator, including Apple Silicon. It has no binary
dependency.

That is worth stating because the sibling libraries in this family do *not*: NexilisLite
depends on `nuSDKService`, which ships a device-only `ios-arm64` slice, so those podspecs
set `EXCLUDED_ARCHS[sdk=iphonesimulator*] = arm64`. NexilisZTA carries no such
restriction, and its podspec deliberately does not copy that setting.

## Publishing

```bash
# From the repository root
git subtree split --prefix=NexilisZTA -b spm-nexeliszta
git push https://github.com/alqindiirsyam-es/NexilisZTA.git spm-nexeliszta:main

# Tag it. Keep the tag in step with spec.version in the podspec, so CocoaPods and
# SwiftPM consumers get the same code for a given version number.
git clone https://github.com/alqindiirsyam-es/NexilisZTA.git /tmp/NexilisZTA
cd /tmp/NexilisZTA && git tag 1.0.0 && git push origin 1.0.0
```

The podspec resolves from the same tag:

```ruby
spec.source = { :git => "https://github.com/alqindiirsyam-es/NexilisZTA.git",
                :tag => spec.version.to_s }
```

Unlike NexilisLite, this is a plain source pod — no prebuilt framework, no zip attached
to a GitHub release. `pod trunk push` can compile it for the Simulator, which is what
trunk validation does, so nothing has to be worked around.

## CocoaPods

```ruby
pod 'NexilisZTA', '1.0.0'
```

See `INTEGRATION.md` (English) or `PANDUAN-INTEGRASI.md` (Bahasa Indonesia) for the
integration steps themselves.
