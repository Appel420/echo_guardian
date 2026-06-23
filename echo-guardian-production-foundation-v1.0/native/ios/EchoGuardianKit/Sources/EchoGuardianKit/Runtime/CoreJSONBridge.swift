import Foundation

public enum CoreBridgeError: Error {
    case privateSpaceBlocked
    case rawRetentionBlocked
    case jsonEncodingFailed
}

public struct CoreCompatibleObservation: Codable, Equatable {
    public let schema_version: String
    public let observation_id: String
    public let created_at: String
    public let sensor_id: String
    public let signal_type: String
    public let space_id: String
    public let private_space: Bool
    public let quality: String
    public let permission_state: String
    public let availability_state: String
    public let raw_sensor_retained: Bool
    public let derived_metadata: [String: Int]
    public let plain_language_summary: String
}

public final class CoreJSONBridge {
    public init() {}

    public func bridge(_ native: MinimizedSensorObservation, sensorId: String = "ios-native-sensor", quality: String = "good") throws -> CoreCompatibleObservation {
        guard native.privateSpace == false else { throw CoreBridgeError.privateSpaceBlocked }
        guard native.rawSensorRetained == false else { throw CoreBridgeError.rawRetentionBlocked }
        return CoreCompatibleObservation(
            schema_version: "0.5",
            observation_id: native.observationId,
            created_at: native.createdAt,
            sensor_id: sensorId,
            signal_type: native.signalType.rawValue,
            space_id: native.spaceId,
            private_space: native.privateSpace,
            quality: quality,
            permission_state: native.permissionState,
            availability_state: native.availabilityState == "available" ? "healthy" : "unavailable",
            raw_sensor_retained: false,
            derived_metadata: native.derivedMetadata,
            plain_language_summary: native.plainLanguageSummary
        )
    }

    public func jsonData(for observation: CoreCompatibleObservation) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(observation)
    }
}
