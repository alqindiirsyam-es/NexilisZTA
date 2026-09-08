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
// downgrade attack in it:
//
//     "NSPA1\0\0\0"  (8 bytes)  ||  AES.GCM combined  (12-byte nonce || ciphertext || 16-byte tag)
//
// There is one algorithm, one version, and no header field an attacker can edit to ask for
// something weaker. A blob that does not start with the magic, or whose tag does not verify, is
// refused — GCM authenticates, so a modified asset fails to open rather than opening as garbage.
//
// Nothing here writes plaintext anywhere. `withDecryptedAsset` is the API production call sites
// should use: it scopes the bytes to a closure so a caller does not have to decide where to keep
// them, which is where "just cache it in Documents" quietly undoes all of the above.
public enum ProtectedAssetStore {

    /// `NSPA1` and three padding bytes, so the payload that follows starts 8-byte aligned.
    private static let magic = Data([0x4e, 0x53, 0x50, 0x41, 0x31, 0x00, 0x00, 0x00])

    /// Smallest blob that could possibly be well-formed: the magic, a 12-byte nonce, a 16-byte
    /// tag, and at least one byte of ciphertext.
    private static let minimumLength = 8 + 12 + 16 + 1

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
        guard deliveredKey.count == keyLength else {
            throw error(.invalidKey, "delivered key must be \(keyLength) bytes")
        }
        let blob = try Data(contentsOf: protectedAssetURL(in: bundle), options: [.mappedIfSafe])
        guard blob.count >= minimumLength, blob.prefix(magic.count) == magic else {
            throw error(.invalidFormat, "protected asset format invalid")
        }
        let sealed = try AES.GCM.SealedBox(combined: Data(blob.dropFirst(magic.count)))
        return try AES.GCM.open(sealed, using: SymmetricKey(data: deliveredKey))
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
