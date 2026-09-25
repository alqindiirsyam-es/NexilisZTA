//
//  ProtectedAssetStore.swift
//  Nexilis iOS ZTA — Sentinel A6: App-Attest-gated protected asset
//

import Foundation
import CryptoKit

// MARK: - A6 — a bundled asset the app cannot open by itself
//
// An asset shipped inside the app is an asset any copy of the app can read: pull the IPA, unzip
// it, and the file is there. This closes that by never shipping the key. The asset is sealed with
// AES-GCM at build time, and the only way to the plaintext is a key the ZTA service delivers after
// App Attest has proved this is a genuine, unmodified install of this app on real Apple hardware.
// An attacker with the IPA has the ciphertext and nothing else; an attacker on a jailbroken device
// fails attestation and never gets the key.
//
// The file format is deliberately trivial, because a format with options is a format with a
// downgrade attack in it. It is the Nexilis Sentinel v3.0.1 RC5 SPA1 container, byte for byte,
// so the RC5 build tool (tools/build_ios_protected_asset.py) and the RC5 server contract apply
// unchanged:
//
//     "SPA1"  (4 bytes)  ||  12-byte nonce  ||  ciphertext  ||  16-byte GCM tag
//     AAD = "SENTINEL_IOS_PROTECTED_ASSET_V1"
//
// There is one algorithm, one version, and no header field an attacker can edit to ask for
// something weaker. A blob that does not start with the magic, or whose tag does not verify, is
// refused — GCM authenticates, so a modified asset fails to open rather than opening as garbage.
// The AAD ties the ciphertext to this purpose: a GCM blob sealed for anything else under the
// same key does not open here.
//
// This replaced the earlier "NSPA1" layout (8-byte magic, no AAD) before any host shipped an
// asset, so there is no legacy blob to keep reading.
//
// Nothing here writes plaintext anywhere. `withDecryptedAsset` is the API production call sites
// should use: it scopes the bytes to a closure so a caller does not have to decide where to keep
// them, which is where "just cache it in Documents" quietly undoes all of the above.
public enum ProtectedAssetStore {

    /// `SPA1`.
    private static let magic = Data([0x53, 0x50, 0x41, 0x31])
    private static let nonceLength = 12
    private static let tagLength = 16
    /// What the sealing tool authenticated alongside the ciphertext.
    private static let additionalData = Data("SENTINEL_IOS_PROTECTED_ASSET_V1".utf8)

    /// Smallest blob that could possibly be well-formed: the magic, a 12-byte nonce, a 16-byte
    /// tag, and at least one byte of ciphertext.
    private static let minimumLength = 4 + 12 + 16 + 1

    /// AES-256. A delivered key of any other length is a protocol mismatch, not something to try.
    private static let keyLength = 32

    /// Where the sealed asset lives in the bundle. Settable so a host that ships more than one, or
    /// names theirs differently, does not have to fork this file.
    public static var resourceName = "SentinelProtectedAssets"
    public static var resourceExtension = "spa"

    public enum Failure: Int {
        case missing        = 1
        case invalidKey     = 2
        case invalidFormat  = 3
    }

    /// Data assets beside the activation asset: `<name>.spa` in the bundle, sealed with the same
    /// per-app key (tools/build_ios_protected_asset.py), opened by name through
    /// APISZTA.withProtectedAsset(named:). Kept apart from the Barrier #2 asset so the host's own
    /// data is never what the activation proof is computed over.
    public static func protectedAssetURL(named name: String, in bundle: Bundle = .main) throws -> URL {
        let safe = name.replacingOccurrences(of: ".spa", with: "")
        guard !safe.isEmpty, !safe.contains("/"), !safe.contains("..") else {
            throw error(.missing, "protected asset name invalid")
        }
        guard let url = bundle.url(forResource: safe, withExtension: "spa") else {
            throw error(.missing, "protected asset \(safe).spa not in bundle")
        }
        return url
    }

    /// Opens a named data asset; see `protectedAssetURL(named:)`.
    public static func decrypt(deliveredKey: Data, named name: String, in bundle: Bundle = .main) throws -> Data {
        try open(Data(contentsOf: protectedAssetURL(named: name, in: bundle), options: [.mappedIfSafe]), key: deliveredKey)
    }

    public static func protectedAssetURL(in bundle: Bundle = .main) throws -> URL {
        guard let url = bundle.url(forResource: resourceName, withExtension: resourceExtension) else {
            throw error(.missing, "protected asset missing from bundle")
        }
        return url
    }

    /// Digest of the sealed bytes as they sit in the bundle.
    ///
    /// This is what a server binds a key delivery to: it hands back the key for *this* asset, so a
    /// tampered or swapped asset gets a key that will not open it, and the mismatch is visible
    /// server-side rather than only as a decryption failure nobody reports.
    public static func sha256Hex(in bundle: Bundle = .main) throws -> String {
        let data = try Data(contentsOf: protectedAssetURL(in: bundle), options: [.mappedIfSafe])
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// Whether this build actually ships a protected asset. Nothing else here is safe to call when
    /// this is false, and a host with no sealed asset is a legitimate configuration.
    public static func isAvailable(in bundle: Bundle = .main) -> Bool {
        bundle.url(forResource: resourceName, withExtension: resourceExtension) != nil
    }

    /// Opens the asset with a key the ZTA service delivered after attestation.
    ///
    /// Prefer `withDecryptedAsset` — this returns the plaintext to a caller who then owns the
    /// problem of not leaving it somewhere.
    public static func decrypt(deliveredKey: Data, in bundle: Bundle = .main) throws -> Data {
        try open(Data(contentsOf: protectedAssetURL(in: bundle), options: [.mappedIfSafe]), key: deliveredKey)
    }

    private static func open(_ blob: Data, key deliveredKey: Data) throws -> Data {
        guard deliveredKey.count == keyLength else {
            throw error(.invalidKey, "delivered key must be \(keyLength) bytes")
        }
        guard blob.count >= minimumLength, blob.prefix(magic.count) == magic else {
            throw error(.invalidFormat, "protected asset format invalid")
        }
        let nonceEnd = magic.count + nonceLength
        let nonce = try AES.GCM.Nonce(data: blob.subdata(in: magic.count ..< nonceEnd))
        let ciphertext = blob.subdata(in: nonceEnd ..< (blob.count - tagLength))
        let tag = blob.suffix(tagLength)
        let sealed = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        return try AES.GCM.open(sealed, using: SymmetricKey(data: deliveredKey), authenticating: additionalData)
    }

    /// Scopes the decrypted bytes to the operation that needs them.
    ///
    /// The plaintext is zeroed on the way out whether `body` returned or threw, so the window in
    /// which it exists is the call itself. That is as close to "not in memory" as a managed
    /// runtime gets — Swift may still have copied the bytes if `body` did — but it removes the
    /// case that actually matters, which is a long-lived `Data` property nobody remembers holds
    /// the asset.
    @discardableResult
    public static func withDecryptedAsset<T>(deliveredKey: Data,
                                             in bundle: Bundle = .main,
                                             _ body: (Data) throws -> T) throws -> T {
        var plaintext = try decrypt(deliveredKey: deliveredKey, in: bundle)
        defer { plaintext.resetBytes(in: 0 ..< plaintext.count) }
        return try body(plaintext)
    }

    private static func error(_ failure: Failure, _ message: String) -> NSError {
        NSError(domain: "io.nexilis.zta.protectedasset", code: failure.rawValue,
                userInfo: [NSLocalizedDescriptionKey: message])
    }
}
