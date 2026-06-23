import Foundation

public struct NativePolicyStatus: Codable, Equatable {
    public let monitoringEnabled: Bool
    public let privateSpaceMonitoringEnabled: Bool
    public let authorityLabel: String
    public let cloudRequiredForCoreLoop: Bool
    public let silentTelemetryEnabled: Bool
    public let plainLanguage: String

    public init(monitoringEnabled: Bool, privateSpaceMonitoringEnabled: Bool, authorityLabel: String, cloudRequiredForCoreLoop: Bool = false, silentTelemetryEnabled: Bool = false) {
        precondition(privateSpaceMonitoringEnabled == false, "Private-space monitoring is blocked by default in v0.5")
        precondition(cloudRequiredForCoreLoop == false, "Cloud dependency is blocked for the core loop")
        precondition(silentTelemetryEnabled == false, "Silent telemetry is blocked")
        self.monitoringEnabled = monitoringEnabled
        self.privateSpaceMonitoringEnabled = privateSpaceMonitoringEnabled
        self.authorityLabel = authorityLabel
        self.cloudRequiredForCoreLoop = cloudRequiredForCoreLoop
        self.silentTelemetryEnabled = silentTelemetryEnabled
        self.plainLanguage = monitoringEnabled ? "Echo Guardian monitoring is on. You can see what is being watched." : "Echo Guardian monitoring is off."
    }
}
