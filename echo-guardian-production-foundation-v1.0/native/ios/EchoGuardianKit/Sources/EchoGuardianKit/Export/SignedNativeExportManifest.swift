import Foundation

public struct SignedNativeExportManifest: Codable, Equatable {
    public let schemaVersion: String
    public let platform: String
    public let exportManifestHash: String
    public let signatureAlgorithm: String
    public let signatureHex: String
    public let publicKeyHex: String
    public let userConfirmed: Bool
    public let automaticExport: Bool
    public let plainLanguageSummary: String

    public init(exportManifestHash: String, signatureHex: String, publicKeyHex: String) {
        self.schemaVersion = "0.7"
        self.platform = "ios"
        self.exportManifestHash = exportManifestHash
        self.signatureAlgorithm = "ed25519_persisted_contract"
        self.signatureHex = signatureHex
        self.publicKeyHex = publicKeyHex
        self.userConfirmed = true
        self.automaticExport = false
        self.plainLanguageSummary = "Echo Guardian signed a user-confirmed native export manifest. No automatic export was used."
    }
}

public enum SignedNativeExportPolicy {
    public static func validate(userConfirmed: Bool, automaticExport: Bool, emergencyServicesUsed: Bool) -> Bool {
        userConfirmed == true && automaticExport == false && emergencyServicesUsed == false
    }
}
