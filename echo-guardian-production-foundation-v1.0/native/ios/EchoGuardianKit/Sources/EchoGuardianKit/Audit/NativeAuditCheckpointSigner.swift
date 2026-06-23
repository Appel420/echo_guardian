import Foundation

public struct NativeAuditCheckpointStatement: Codable, Equatable {
    public let schemaVersion: String
    public let latestSequenceNumber: Int
    public let latestEntryHash: String
    public let merkleRoot: String
    public let signatureAlgorithm: String
    public let platform: String
    public let plainLanguageSummary: String
}

public enum NativeAuditCheckpointSigner {
    public static func statement(sequence: Int, latestEntryHash: String, merkleRoot: String) -> NativeAuditCheckpointStatement {
        NativeAuditCheckpointStatement(
            schemaVersion: "0.7",
            latestSequenceNumber: sequence,
            latestEntryHash: latestEntryHash,
            merkleRoot: merkleRoot,
            signatureAlgorithm: "ed25519_persisted_contract",
            platform: "ios",
            plainLanguageSummary: "Echo Guardian prepared a signed native audit checkpoint statement."
        )
    }
}
