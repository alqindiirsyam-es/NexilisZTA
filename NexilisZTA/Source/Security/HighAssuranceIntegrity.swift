//
//  HighAssuranceIntegrity.swift
//  Nexilis iOS ZTA — High Assurance: the running executable is the one that was released
//
//  Ported from Nexilis Sentinel v3.0 High Assurance (SentinelHighAssuranceIntegrity). A release
//  ships `sentinel_high_assurance_manifest.json` next to its protected asset, generated after link
//  and before code signing by tools/xcode_high_assurance_finalize.sh:
//
//      { "schema": "sentinel-ios-high-assurance-v1",
//        "build_id": "...",
//        "protected_asset_sha256": "...",     SentinelProtectedAssets.spa as shipped
//        "executable_text_sha256": "...",     the main executable's __TEXT,__text section
//        "shield_profile_sha256": "...",      optional here; "" when no shield profile is used
//        "frameworks_text_sha256": {           optional: every bundled framework, the contents of
//            "App.framework": "..." } }        all its __TEXT sections
//
//  The framework digests cover the whole __TEXT segment, not __text alone: a Flutter app keeps its
//  Dart snapshot data and string literals in App.framework's __TEXT,__const, so __text alone would
//  let the Dart side be swapped unnoticed. They are taken from the loaded images (a framework not
//  loaded yet is loaded for it), the set of frameworks in the bundle must be exactly the manifest's,
//  and `bundled_frameworks_sha256` - SHA-256 over sorted "<name>:<hex>\n" lines - goes to the
//  service, which compares it with the release when the release pins one.
//
//  At runtime the same two digests are taken again - the asset from the bundle, __TEXT,__text
//  from the loaded Mach-O image in memory - and compared to the manifest. Code-signature bytes
//  live outside __text, which is what lets the manifest be produced before signing and still
//  match afterwards. The three digests plus the manifest's own digest go to the service in the
//  /key posture, where they are compared against the release the operator approved: an executable
//  that was patched, re-linked or swapped no longer matches, and the key is never delivered.
//
//  What this is not: a substitute for App Attest or code signing. It is one more thing an
//  attacker has to keep consistent - the executable bytes, the asset, the manifest, the server's
//  record of the release - and one the server can check without trusting the client's word.
//
//  Departure from RC5: the shield profile is optional. This repository declares its obfuscation
//  tool through SENTINEL_LLVM_SHIELD_ENABLED and has no profile file to hash; a manifest may carry
//  an empty shield_profile_sha256, and the evidence omits the field.
//

import Foundation
import CryptoKit
import MachO
#if SWIFT_PACKAGE
import NexilisZTACore
#endif

public enum SentinelHighAssuranceIntegrity {

    public static let manifestResourceName = "sentinel_high_assurance_manifest"
    public static let errorDomain = "io.nexilis.zta.highassurance"

    public struct Manifest: Decodable {
        public let schema: String
        public let build_id: String
        public let protected_asset_sha256: String
        public let executable_text_sha256: String
        public let shield_profile_sha256: String?
        public let frameworks_text_sha256: [String: String]?
    }

    public enum Failure: Int {
        case manifestMissing = 1, manifestInvalid, machOUnavailable, machOUnsupported,
             textUnmapped, textNotFound, executableMismatch, assetMissing, assetMismatch,
             frameworkMissing, frameworkMismatch, frameworkUnexpected
    }

    /// Whether this build ships a manifest at all. A build without one is a legitimate
    /// configuration at modes 2 and 3; at mode 1 the chain treats it as a misconfigured release.
    public static func isAvailable(in bundle: Bundle = .main) -> Bool {
        bundle.url(forResource: manifestResourceName, withExtension: "json") != nil
    }

    public static func loadManifest(bundle: Bundle = .main) throws -> (manifest: Manifest, raw: Data, sha256: String) {
        guard let url = bundle.url(forResource: manifestResourceName, withExtension: "json") else {
            throw failure(.manifestMissing, "High Assurance manifest missing from bundle")
        }
        let data = try Data(contentsOf: url, options: .mappedIfSafe)
        let manifest = try JSONDecoder().decode(Manifest.self, from: data)
        guard manifest.schema == "sentinel-ios-high-assurance-v1",
              isHex64(manifest.protected_asset_sha256),
              isHex64(manifest.executable_text_sha256),
              manifest.shield_profile_sha256.map({ $0.isEmpty || isHex64($0) }) ?? true,
              manifest.frameworks_text_sha256.map({ !$0.isEmpty && $0.values.allSatisfy(isHex64) }) ?? true,
              !manifest.build_id.isEmpty else {
            throw failure(.manifestInvalid, "High Assurance manifest invalid")
        }
        return (manifest, data, sha256(data))
    }

    /// SHA-256 of the main executable's `__TEXT,__text` as it sits in memory right now.
    ///
    /// Image 0 is the main executable. Its `__text` carries no fixups on arm64, so the bytes in
    /// memory are the bytes in the file, and the digest the release tool computed over the file
    /// is the digest a genuine, unmodified load produces here.
    public static func executableTextSHA256() throws -> String {
        guard let header = _dyld_get_image_header(0) else {
            throw failure(.machOUnavailable, "Mach-O header unavailable")
        }
        let raw = UnsafeRawPointer(header)
        guard raw.assumingMemoryBound(to: mach_header_64.self).pointee.magic == MH_MAGIC_64 else {
            throw failure(.machOUnsupported, "Unsupported Mach-O")
        }
        let ncmds = raw.assumingMemoryBound(to: mach_header_64.self).pointee.ncmds
        var cursor = raw.advanced(by: MemoryLayout<mach_header_64>.size)
        for _ in 0 ..< ncmds {
            let command = cursor.assumingMemoryBound(to: load_command.self).pointee
            guard command.cmdsize >= MemoryLayout<load_command>.size else { break }
            if command.cmd == LC_SEGMENT_64 {
                let segment = cursor.assumingMemoryBound(to: segment_command_64.self).pointee
                if tupleString(segment.segname) == "__TEXT" {
                    var sectionCursor = cursor.advanced(by: MemoryLayout<segment_command_64>.size)
                    for _ in 0 ..< segment.nsects {
                        let section = sectionCursor.assumingMemoryBound(to: section_64.self).pointee
                        if tupleString(section.sectname) == "__text", tupleString(section.segname) == "__TEXT" {
                            let slide = _dyld_get_image_vmaddr_slide(0)
                            guard let start = UnsafeRawPointer(bitPattern: UInt(section.addr) &+ UInt(bitPattern: slide)) else {
                                throw failure(.textUnmapped, "__TEXT,__text not mapped")
                            }
                            let bytes = UnsafeRawBufferPointer(start: start, count: Int(section.size))
                            return hex(SHA256.hash(data: bytes))
                        }
                        sectionCursor = sectionCursor.advanced(by: MemoryLayout<section_64>.size)
                    }
                }
            }
            cursor = cursor.advanced(by: Int(command.cmdsize))
        }
        throw failure(.textNotFound, "__TEXT,__text not found")
    }

    /// SHA-256 over the contents of every `__TEXT` section of a loaded image, in load-command order -
    /// what the release tool computes from the file with --frameworks-dir. Read-only text carries no
    /// fixups, so a genuine load gives the file's bytes.
    static func textSegmentSHA256(imageIndex index: UInt32) throws -> String {
        guard let header = _dyld_get_image_header(index) else {
            throw failure(.machOUnavailable, "Mach-O header unavailable")
        }
        let raw = UnsafeRawPointer(header)
        guard raw.assumingMemoryBound(to: mach_header_64.self).pointee.magic == MH_MAGIC_64 else {
            throw failure(.machOUnsupported, "Unsupported Mach-O")
        }
        let slide = _dyld_get_image_vmaddr_slide(index)
        let ncmds = raw.assumingMemoryBound(to: mach_header_64.self).pointee.ncmds
        var hasher = SHA256()
        var found = false
        var cursor = raw.advanced(by: MemoryLayout<mach_header_64>.size)
        for _ in 0 ..< ncmds {
            let command = cursor.assumingMemoryBound(to: load_command.self).pointee
            guard command.cmdsize >= MemoryLayout<load_command>.size else { break }
            if command.cmd == LC_SEGMENT_64,
               tupleString(cursor.assumingMemoryBound(to: segment_command_64.self).pointee.segname) == "__TEXT" {
                let segment = cursor.assumingMemoryBound(to: segment_command_64.self).pointee
                var sectionCursor = cursor.advanced(by: MemoryLayout<segment_command_64>.size)
                for _ in 0 ..< segment.nsects {
                    let section = sectionCursor.assumingMemoryBound(to: section_64.self).pointee
                    let type = section.flags & UInt32(SECTION_TYPE)
                    let zerofill = type == UInt32(S_ZEROFILL) || type == UInt32(S_GB_ZEROFILL) || type == UInt32(S_THREAD_LOCAL_ZEROFILL)
                    if !zerofill, section.size > 0 {
                        guard let start = UnsafeRawPointer(bitPattern: UInt(section.addr) &+ UInt(bitPattern: slide)) else {
                            throw failure(.textUnmapped, "__TEXT section not mapped")
                        }
                        hasher.update(bufferPointer: UnsafeRawBufferPointer(start: start, count: Int(section.size)))
                        found = true
                    }
                    sectionCursor = sectionCursor.advanced(by: MemoryLayout<section_64>.size)
                }
            }
            cursor = cursor.advanced(by: Int(command.cmdsize))
        }
        guard found else { throw failure(.textNotFound, "__TEXT sections not found") }
        return hex(hasher.finalize())
    }

    /// Digests of the bundled frameworks, from their loaded images, keyed by "<Name>.framework".
    /// Throws unless the frameworks in the bundle are exactly the ones the manifest names.
    static func bundledFrameworkDigests(expected: [String: String], bundle: Bundle) throws -> [String: String] {
        let present = Set(((try? FileManager.default.contentsOfDirectory(atPath: bundle.privateFrameworksPath ?? "")) ?? [])
            .filter { $0.hasSuffix(".framework") })
        if let extra = present.subtracting(expected.keys).sorted().first {
            throw failure(.frameworkUnexpected, "Bundled framework not in the High Assurance manifest: \(extra)")
        }
        var out: [String: String] = [:]
        for name in expected.keys.sorted() {
            guard present.contains(name), let fwPath = bundle.privateFrameworksPath.map({ $0 + "/" + name }) else {
                throw failure(.frameworkMissing, "Bundled framework missing: \(name)")
            }
            let exe = Bundle(path: fwPath)?.executableURL?.lastPathComponent ?? String(name.dropLast(".framework".count))
            let suffix = "/Frameworks/" + name + "/" + exe
            func loadedIndex() -> UInt32? {
                (0 ..< _dyld_image_count()).first { i in
                    guard let c = _dyld_get_image_name(i) else { return false }
                    return String(cString: c).hasSuffix(suffix)
                }
            }
            // A framework the host loads lazily (Flutter's App.framework is dlopen'ed by the engine)
            // is loaded here instead; the engine's own dlopen then gets the same image.
            var index = loadedIndex()
            if index == nil, dlopen(fwPath + "/" + exe, RTLD_NOW) != nil { index = loadedIndex() }
            guard let index else { throw failure(.frameworkMissing, "Bundled framework not loadable: \(name)") }
            let digest = try textSegmentSHA256(imageIndex: index)
            guard let pinned = expected[name], constantTimeEqual(digest, pinned) else {
                throw failure(.frameworkMismatch, "Bundled framework integrity mismatch: \(name)")
            }
            out[name] = digest
        }
        return out
    }

    static func combinedFrameworksSHA256(_ digests: [String: String]) -> String {
        sha256(Data(digests.keys.sorted().map { "\($0):\(digests[$0]!)\n" }.joined().utf8))
    }

    /// The posture fields for /key: the manifest checked against the running executable and the
    /// shipped asset. Throws on any mismatch - that is a local tamper finding, and the chain
    /// decides by mode what to do with it.
    public static func evidence(bundle: Bundle = .main) throws -> [String: Any] {
        let (manifest, _, manifestSHA) = try loadManifest(bundle: bundle)
        let runtimeText = try executableTextSHA256()
        guard constantTimeEqual(runtimeText, manifest.executable_text_sha256) else {
            throw failure(.executableMismatch, "Executable integrity mismatch")
        }
        guard ProtectedAssetStore.isAvailable(in: bundle) else {
            throw failure(.assetMissing, "Protected asset missing")
        }
        let assetSHA = try ProtectedAssetStore.sha256Hex(in: bundle)
        guard constantTimeEqual(assetSHA, manifest.protected_asset_sha256) else {
            throw failure(.assetMismatch, "Protected asset integrity mismatch")
        }
        let info = bundle.infoDictionary ?? [:]
        var out: [String: Any] = [
            "high_assurance": true,
            "protected_asset_sha256": assetSHA,
            "executable_text_sha256": runtimeText,
            "high_assurance_manifest_sha256": manifestSHA,
            "high_assurance_build_id": manifest.build_id,
            "app_short_version": info["CFBundleShortVersionString"] as? String ?? "",
            "app_build_version": info["CFBundleVersion"] as? String ?? "",
        ]
        if let shield = manifest.shield_profile_sha256, !shield.isEmpty {
            out["shield_profile_sha256"] = shield.lowercased()
        }
        if let pinned = manifest.frameworks_text_sha256 {
            out["bundled_frameworks_sha256"] = combinedFrameworksSHA256(
                try bundledFrameworkDigests(expected: pinned, bundle: bundle))
        }
        return out
    }

    /// What the chain adds to the /key posture, by mode.
    ///
    ///   - manifest present: `evidence()`. A mismatch fails at .hsa/.middle; at .regular it is
    ///     recorded, and the posture carries `high_assurance_error` so the service sees it too.
    ///   - manifest absent: `.hsa` fails (a mode-1 release ships one); the others send the asset
    ///     digest when an asset ships, and nothing otherwise.
    public static func posture(bundle: Bundle = .main) -> Result<[String: Any], Error> {
        let enforce = NXSecurityPolicy.requiresServerChain()
        guard isAvailable(in: bundle) else {
            if NXSecurityPolicy.isHSA() {
                return .failure(failure(.manifestMissing, "Mode 1 requires a High Assurance manifest in the bundle and none was found."))
            }
            var out: [String: Any] = ["high_assurance": false]
            if ProtectedAssetStore.isAvailable(in: bundle),
               let assetSHA = try? ProtectedAssetStore.sha256Hex(in: bundle) {
                out["protected_asset_sha256"] = assetSHA
            }
            return .success(out)
        }
        do {
            let evidence = try evidence(bundle: bundle)
            let frameworks = (evidence["bundled_frameworks_sha256"] as? String).map { " frameworks=\($0.prefix(16))…" } ?? ""
            let line = "[HighAssurance] manifest cocok dengan executable & aset: build_id=\(evidence["high_assurance_build_id"] ?? "") text=\(String(describing: evidence["executable_text_sha256"] ?? "").prefix(16))…\(frameworks)"
            print(line)
            NXLogger.appAttest.publicInfo(line)
            SecurityAuditChain.append(event: "high_assurance_verified",
                                      detail: ["build_id": evidence["high_assurance_build_id"] ?? "",
                                               "executable_text_sha256": evidence["executable_text_sha256"] ?? ""])
            return .success(evidence)
        } catch {
            print("[HighAssurance] tidak cocok: \(error.localizedDescription)\(enforce ? "" : " - mode 3 mencatat, tidak memblokir")")
            NXLogger.appAttest.publicInfo("[HighAssurance] tidak cocok: \(error.localizedDescription)\(enforce ? "" : " - mode 3 mencatat, tidak memblokir")")
            SecurityAuditChain.append(event: enforce ? "high_assurance_failed" : "high_assurance_recorded",
                                      detail: ["error": (error as NSError).code, "message": error.localizedDescription])
            if enforce { return .failure(error) }
            NXLogger.appAttest.publicInfo("[HighAssurance] Temuan dicatat, mode 3 tidak memblokir: \(error.localizedDescription)")
            return .success(["high_assurance": false,
                             "high_assurance_error": (error as NSError).code])
        }
    }

    // MARK: - Helpers

    private static func sha256(_ data: Data) -> String { hex(SHA256.hash(data: data)) }
    private static func hex<D: Sequence>(_ digest: D) -> String where D.Element == UInt8 {
        digest.map { String(format: "%02x", $0) }.joined()
    }
    private static func isHex64(_ s: String) -> Bool { s.count == 64 && s.allSatisfy { $0.isHexDigit } }
    private static func constantTimeEqual(_ a: String, _ b: String) -> Bool {
        let x = Array(a.lowercased().utf8), y = Array(b.lowercased().utf8)
        guard x.count == y.count else { return false }
        var diff: UInt8 = 0
        for i in 0 ..< x.count { diff |= x[i] ^ y[i] }
        return diff == 0
    }
    private static func tupleString<T>(_ tuple: T) -> String {
        withUnsafeBytes(of: tuple) { raw in String(bytes: raw.prefix { $0 != 0 }, encoding: .utf8) ?? "" }
    }
    private static func failure(_ code: Failure, _ message: String) -> NSError {
        NSError(domain: errorDomain, code: code.rawValue, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
