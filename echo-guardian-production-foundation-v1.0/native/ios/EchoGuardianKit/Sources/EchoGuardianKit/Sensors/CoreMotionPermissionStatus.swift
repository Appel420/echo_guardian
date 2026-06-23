import Foundation
#if canImport(CoreMotion)
import CoreMotion
#endif

public enum NativePermissionState: String, Codable, Equatable {
    case granted
    case denied
    case restricted
    case notDetermined = "not_determined"
    case unavailable
}

public struct CoreMotionPermissionStatus: Codable, Equatable {
    public let schemaVersion: String
    public let platform: String
    public let permissionName: String
    public let permissionState: NativePermissionState
    public let availabilityState: String
    public let sensorId: String
    public let signalType: String
    public let rawSensorRetained: Bool
    public let privateSpaceMonitoring: Bool
    public let plainLanguageSummary: String

    public init(permissionState: NativePermissionState, availabilityState: String, sensorId: String, signalType: String) {
        self.schemaVersion = "0.6"
        self.platform = "ios"
        self.permissionName = "core_motion"
        self.permissionState = permissionState
        self.availabilityState = availabilityState
        self.sensorId = sensorId
        self.signalType = signalType
        self.rawSensorRetained = false
        self.privateSpaceMonitoring = false
        self.plainLanguageSummary = "Echo Guardian checked iOS motion permission and availability. Raw sensor data was not kept."
    }
}

public final class CoreMotionPermissionReader {
    #if canImport(CoreMotion)
    private let activityManager = CMMotionActivityManager()
    private let motionManager = CMMotionManager()
    #endif

    public init() {}

    public func currentStatus() -> CoreMotionPermissionStatus {
        #if canImport(CoreMotion)
        let available = CMMotionActivityManager.isActivityAvailable() || motionManager.isAccelerometerAvailable
        return CoreMotionPermissionStatus(
            permissionState: available ? .granted : .unavailable,
            availabilityState: available ? "healthy" : "unavailable",
            sensorId: "ios.core_motion.activity",
            signalType: "motion"
        )
        #else
        return CoreMotionPermissionStatus(
            permissionState: .unavailable,
            availabilityState: "unavailable",
            sensorId: "ios.core_motion.unavailable",
            signalType: "motion"
        )
        #endif
    }
}
