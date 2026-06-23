import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif
#if canImport(Security)
import Security
#endif

public struct ProofOfPossession: Codable, Equatable {
    public let keyId: String
    public let algorithm: String
    public let challengeBase64: String
    public let signatureBase64: String
    public let protection: String
    public let createdAt: String
}

public enum DeviceSigningKeyError: Error {
    case keychainFailure(Int32)
    case missingPrivateKey
    case invalidChallenge
}

#if canImport(CryptoKit) && canImport(Security)
public final class DeviceSigningKeyManager {
    private let tag: String

    public init(tag: String = "org.echo-guardian.device-signing.v0.5") {
        self.tag = tag
    }

    public func createOrLoadSigningKey() throws -> Curve25519.Signing.PrivateKey {
        if let key = try loadSigningKey() { return key }
        let key = Curve25519.Signing.PrivateKey()
        try storeSigningKey(key)
        return key
    }

    public func publicKeyBase64() throws -> String {
        let key = try createOrLoadSigningKey()
        return key.publicKey.rawRepresentation.base64EncodedString()
    }

    public func signChallenge(_ challenge: Data) throws -> ProofOfPossession {
        guard !challenge.isEmpty else { throw DeviceSigningKeyError.invalidChallenge }
        let key = try createOrLoadSigningKey()
        let signature = try key.signature(for: challenge)
        return ProofOfPossession(
            keyId: try publicKeyBase64(),
            algorithm: "ed25519",
            challengeBase64: challenge.base64EncodedString(),
            signatureBase64: signature.base64EncodedString(),
            protection: "keychain_or_supported_secure_enclave_profile",
            createdAt: ISO8601DateFormatter().string(from: Date())
        )
    }

    private func loadSigningKey() throws -> Curve25519.Signing.PrivateKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: tag,
            kSecAttrAccount as String: "device-signing-key",
            kSecReturnData as String: true
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw DeviceSigningKeyError.keychainFailure(status) }
        guard let data = item as? Data else { throw DeviceSigningKeyError.missingPrivateKey }
        return try Curve25519.Signing.PrivateKey(rawRepresentation: data)
    }

    private func storeSigningKey(_ key: Curve25519.Signing.PrivateKey) throws {
        let data = key.rawRepresentation
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: tag,
            kSecAttrAccount as String: "device-signing-key",
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw DeviceSigningKeyError.keychainFailure(status) }
    }
}
#else
public final class DeviceSigningKeyManager {
    private let tag: String

    public init(tag: String = "org.echo-guardian.device-signing.v0.5") {
        self.tag = tag
    }

    public func publicKeyBase64() throws -> String {
        Data(("non_apple_development_key_" + tag).utf8).base64EncodedString()
    }

    public func signChallenge(_ challenge: Data) throws -> ProofOfPossession {
        guard !challenge.isEmpty else { throw DeviceSigningKeyError.invalidChallenge }
        let marker = Data(("non_production_compile_only_" + tag).utf8) + challenge
        return ProofOfPossession(
            keyId: try publicKeyBase64(),
            algorithm: "non_apple_compile_only_not_production",
            challengeBase64: challenge.base64EncodedString(),
            signatureBase64: marker.base64EncodedString(),
            protection: "non_apple_compile_only_no_keychain_or_secure_enclave_claim",
            createdAt: ISO8601DateFormatter().string(from: Date())
        )
    }
}
#endif
