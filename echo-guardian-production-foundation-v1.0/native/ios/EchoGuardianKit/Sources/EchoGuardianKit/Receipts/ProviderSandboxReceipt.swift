import Foundation

public struct ProviderSandboxReceipt: Codable, Equatable {
    public let schemaVersion: String
    public let provider: String
    public let providerMessageId: String
    public let deliveryStatus: String
    public let sandboxVerified: Bool
    public let sensitiveDetailsIncluded: Bool
    public let emergencyServicesUsed: Bool
}

public enum ProviderSandboxReceiptVerifier {
    public static func verify(provider: String, messageId: String, status: String, sandbox: Bool) -> ProviderSandboxReceipt? {
        guard sandbox == true else { return nil }
        guard status == "attempted" || status == "delivered" else { return nil }
        return ProviderSandboxReceipt(
            schemaVersion: "0.7",
            provider: provider,
            providerMessageId: messageId,
            deliveryStatus: status,
            sandboxVerified: true,
            sensitiveDetailsIncluded: false,
            emergencyServicesUsed: false
        )
    }
}
