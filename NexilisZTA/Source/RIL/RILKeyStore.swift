import Foundation
import CryptoKit
import Security

struct RILStoredKey: Codable {
    let wrappedKey: Data
    let publicKeySPKI: Data
    var keyID: String { "device-" + RILCore.base64URL(RILCore.sha256(publicKeySPKI)) }
}

struct RILLocalState: Codable {
    var version = 1
    let scope: String
    let appAttestKeyID: String
    var active: RILStoredKey?
    var pending: RILStoredKey?
    // Saved before enrollment: retries use the same key and replaces_key_id after restart.
    var replacesKeyID = ""
    var confirmationPending = false
}

protocol RILStateStorage {
    func load() throws -> RILLocalState?
    func save(_ state: RILLocalState) throws
    func delete() throws
}

protocol RILKeyCryptography {
    func generate() throws -> RILStoredKey
    func signer(for key: RILStoredKey) throws -> RILSigningKey
}

struct RILSecureEnclaveCryptography: RILKeyCryptography {
    func generate() throws -> RILStoredKey {
        guard SecureEnclave.isAvailable else { throw RILError.secureEnclaveUnavailable }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                                                         .privateKeyUsage, &error) else {
            throw error?.takeRetainedValue() as Error? ?? RILError.secureEnclaveUnavailable
        }
        // Separate key: no userPresence/biometry prompt on routine background requests.
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        return RILStoredKey(wrappedKey: key.dataRepresentation, publicKeySPKI: key.publicKey.derRepresentation)
    }
    func signer(for stored: RILStoredKey) throws -> RILSigningKey {
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: stored.wrappedKey)
        guard key.publicKey.derRepresentation == stored.publicKeySPKI else { throw RILError.corruptState }
        return EnclaveSigner(key: key)
    }
    private struct EnclaveSigner: RILSigningKey {
        let key: SecureEnclave.P256.Signing.PrivateKey
        var publicKeySPKI: Data { key.publicKey.derRepresentation }
        func signP1363(_ message: Data) throws -> Data { try key.signature(for: message).rawRepresentation }
    }
}

/// A single Keychain item commits active key, candidate and rotation status together.
/// Wrapped Secure Enclave representations are device-bound, not exported private scalars.
final class RILKeychainStorage: RILStateStorage {
    private let account: String
    init(scope: String) { account = RILCore.base64URL(RILCore.sha256(Data(scope.utf8))) }
    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: "io.nexilis.zta.ril.v2",
         kSecAttrAccount as String: account,
         kSecAttrSynchronizable as String: false]
    }
    func load() throws -> RILLocalState? {
        var q = query
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw RILError.keychain(status) }
        guard let bytes = result as? Data, let state = try? JSONDecoder().decode(RILLocalState.self, from: bytes),
              state.version == 1 else { throw RILError.corruptState }
        return state
    }
    func save(_ state: RILLocalState) throws {
        let bytes = try JSONEncoder().encode(state)
        let values: [String: Any] = [kSecValueData as String: bytes,
                                    kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        var status = SecItemUpdate(query as CFDictionary, values as CFDictionary)
        if status == errSecItemNotFound {
            status = SecItemAdd(query.merging(values) { _, new in new } as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw RILError.keychain(status) }
    }
    func delete() throws {
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw RILError.keychain(status) }
    }
}
