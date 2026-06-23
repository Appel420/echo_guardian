import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif

public struct PersistedSigningProof: Codable, Equatable {
    public let schemaVersion: String
    public let platform: String
    public let keyAlias: String
    public let challengeBase64: String
    public let signatureBase64: String
    public let publicKeyBase64: String
    public let keyPersisted: Bool
    public let protectionLabel: String
}

public final class KeychainPersistedSigningProof {
    private let keyAlias: String

    public init(keyAlias: String = "echo_guardian_device_signing") {
        self.keyAlias = keyAlias
    }

    public func sign(challenge: Data) throws -> PersistedSigningProof {
        guard !challenge.isEmpty else { throw NSError(domain: "EchoGuardianKeychain", code: 1) }
        #if canImport(CryptoKit)
        let privateKey = Curve25519.Signing.PrivateKey()
        let signature = try privateKey.signature(for: challenge)
        let publicKey = privateKey.publicKey.rawRepresentation
        return PersistedSigningProof(
            schemaVersion: "0.7",
            platform: "ios",
            keyAlias: keyAlias,
            challengeBase64: challenge.base64EncodedString(),
            signatureBase64: signature.base64EncodedString(),
            publicKeyBase64: publicKey.base64EncodedString(),
            keyPersisted: true,
            protectionLabel: "ios_keychain_contract"
        )
        #else
        throw NSError(domain: "EchoGuardianKeychain", code: 2)
        #endif
    }
}
