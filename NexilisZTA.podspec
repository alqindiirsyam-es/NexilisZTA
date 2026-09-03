Pod::Spec.new do |spec|
  spec.name         = "NexilisZTA"
  spec.version      = "1.2.0"
  spec.summary      = "NexilisZTA Framework"
  spec.description  = <<-DESC
  Zero Trust Architecture hardening for iOS: RASP (jailbreak, debugger, Frida, injection,
  inline/GOT hooks, code signature), App Attest device attestation with key delivery,
  certificate pinning with rotation, secure input, privacy shield, and session teardown.
                   DESC

  spec.homepage     = "https://nexilis.io/"
  spec.license      = "MIT"
  spec.author       = { "Nexilis" => "ya2n.wicaksono@gmail.com" }
  spec.ios.deployment_target = "15.0"
  spec.source       = { :git => "https://github.com/alqindiirsyam-es/NexilisZTA.git",
                        :tag => spec.version.to_s }
  spec.source_files = 'NexilisZTA/Source/**/*'
  spec.swift_version = '5.5.1'

  # Every header is public: the Swift half of this pod reaches the ObjC/C half through the
  # generated umbrella header, and a host that drives RASPGuard or AppAttestManager directly
  # needs them too. The C++ in StringEncryptor.h and rasp_native.h sits behind __cplusplus
  # guards, so the umbrella header stays importable from Swift.
  spec.public_header_files = 'NexilisZTA/Source/**/*.h'

  spec.frameworks = 'Foundation', 'UIKit', 'DeviceCheck', 'CryptoKit', 'Security',
                    'CoreLocation', 'WebKit', 'OSLog', 'SystemConfiguration', 'LocalAuthentication'

  # StringEncryptor.h builds its ciphertext in a constexpr constructor that writes through
  # std::array and runs a search loop. That needs the same C++ the app target was giving it while
  # these files lived inside OneApp; at the pod default the compiler rejects _nxEnc as "must be
  # initialized by a constant expression" and the obfuscation will not build at all.
  # No EXCLUDED_ARCHS here on purpose. The other pods in this family exclude arm64 for the
  # Simulator because nuSDKService ships a device-only slice; this pod has no binary
  # dependency at all and builds and runs on the Simulator, so excluding arm64 would take
  # that away for nothing — and would leave `pod lib lint` with no destination to build for.
  spec.pod_target_xcconfig = { 'ENABLE_BITCODE' => 'NO',
                               'CLANG_CXX_LANGUAGE_STANDARD' => 'gnu++20', 'CLANG_CXX_LIBRARY' => 'libc++' }
  spec.user_target_xcconfig = { 'ENABLE_BITCODE' => 'NO' }
end
