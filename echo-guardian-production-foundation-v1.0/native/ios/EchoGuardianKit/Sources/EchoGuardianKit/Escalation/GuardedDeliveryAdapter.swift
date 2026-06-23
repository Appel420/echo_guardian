import Foundation

public struct GuardedAlertPayload: Codable, Equatable {
    public let severity: String
    public let reason: String
    public let locationContext: String
    public let recommendedAction: String
    public let sensitiveDetailsIncluded: Bool
    public let emergencyServicesUsed: Bool
}

public struct DeliveryResult: Codable, Equatable {
    public let status: String
    public let provider: String
    public let plainLanguageSummary: String
}

public protocol GuardedDeliveryProvider {
    func send(payload: GuardedAlertPayload, toAuthorizedContact contact: String) -> DeliveryResult
}

public final class LocalOutboxProvider: GuardedDeliveryProvider {
    public init() {}

    public func send(payload: GuardedAlertPayload, toAuthorizedContact contact: String) -> DeliveryResult {
        if payload.emergencyServicesUsed {
            return DeliveryResult(status: "blocked", provider: "local_outbox", plainLanguageSummary: "Emergency services are not contacted by default.")
        }
        if payload.sensitiveDetailsIncluded {
            return DeliveryResult(status: "blocked", provider: "local_outbox", plainLanguageSummary: "Sensitive details are blocked in minimal-disclosure mode.")
        }
        return DeliveryResult(status: "attempted", provider: "local_outbox", plainLanguageSummary: "A minimal safety alert was prepared for an authorized contact.")
    }
}
