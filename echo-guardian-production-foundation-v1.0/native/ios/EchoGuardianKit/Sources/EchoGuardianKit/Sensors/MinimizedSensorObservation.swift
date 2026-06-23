import Foundation
#if canImport(CoreMotion)
import CoreMotion
#endif

public enum SensorType: String, Codable {
    case accelerometer
    case gyroscope
    case devicePresence = "device_presence"
    case motion
}

public struct MinimizedSensorObservation: Codable, Equatable {
    public let schemaVersion: String
    public let observationId: String
    public let createdAt: String
    public let signalType: SensorType
    public let spaceId: String
    public let privateSpace: Bool
    public let permissionState: String
    public let availabilityState: String
    public let rawSensorRetained: Bool
    public let derivedMetadata: [String: Int]
    public let plainLanguageSummary: String

    public init(signalType: SensorType, spaceId: String, privateSpace: Bool, permissionState: String, availabilityState: String, derivedMetadata: [String: Int]) {
        precondition(privateSpace == false, "Private-space monitoring is blocked by default in v0.5")
        self.schemaVersion = "0.5"
        self.observationId = UUID().uuidString
        self.createdAt = ISO8601DateFormatter().string(from: Date())
        self.signalType = signalType
        self.spaceId = spaceId
        self.privateSpace = privateSpace
        self.permissionState = permissionState
        self.availabilityState = availabilityState
        self.rawSensorRetained = false
        self.derivedMetadata = derivedMetadata
        self.plainLanguageSummary = "Echo Guardian received a minimized safety signal for \(spaceId). Raw sensor data was not kept."
    }
}

public final class IOSSensorAdapter {
    #if canImport(CoreMotion)
    private let motionManager = CMMotionManager()
    #endif

    public init() {}

    public func accelerometerAvailability() -> String {
        #if canImport(CoreMotion)
        return motionManager.isAccelerometerAvailable ? "available" : "unavailable"
        #else
        return "unavailable_on_non_apple_runtime"
        #endif
    }

    public func makeMotionObservation(spaceId: String, confidenceScaled: Int, motionDetected: Bool) -> MinimizedSensorObservation {
        MinimizedSensorObservation(
            signalType: .motion,
            spaceId: spaceId,
            privateSpace: false,
            permissionState: "authorized_or_not_required",
            availabilityState: accelerometerAvailability(),
            derivedMetadata: [
                "confidence_scaled": max(0, min(100, confidenceScaled)),
                "motion_detected": motionDetected ? 1 : 0
            ]
        )
    }
}
