import Foundation

public enum EvidenceError: Error {
    case invalidDeviceEvidence(String)
}

public struct DeviceExecutionEvidence: Codable, Equatable {
    public let schemaVersion: String
    public let platform: String
    public let deviceModel: String
    public let osVersion: String
    public let appBuild: String
    public let physicalDevice: Bool
    public let simulatorOrEmulator: Bool
    public let permissionsVisible: Bool
    public let privateSpaceBlocked: Bool
    public let rawDataBlocked: Bool
    public let plainLanguageSummary: String

    public init(
        platform: String = "ios",
        deviceModel: String,
        osVersion: String,
        appBuild: String,
        physicalDevice: Bool,
        simulatorOrEmulator: Bool,
        permissionsVisible: Bool,
        privateSpaceBlocked: Bool,
        rawDataBlocked: Bool
    ) throws {
        if platform != "ios" { throw EvidenceError.invalidDeviceEvidence("iOS evidence must use ios platform") }
        if deviceModel.isEmpty || osVersion.isEmpty || appBuild.isEmpty { throw EvidenceError.invalidDeviceEvidence("device model, OS, and build are required") }
        if !physicalDevice || simulatorOrEmulator { throw EvidenceError.invalidDeviceEvidence("physical iOS device evidence is required") }
        if !permissionsVisible { throw EvidenceError.invalidDeviceEvidence("permission status must be visible") }
        if !privateSpaceBlocked { throw EvidenceError.invalidDeviceEvidence("private-space blocking must be evidenced") }
        if !rawDataBlocked { throw EvidenceError.invalidDeviceEvidence("raw-data blocking must be evidenced") }
        self.schemaVersion = "0.8"
        self.platform = platform
        self.deviceModel = deviceModel
        self.osVersion = osVersion
        self.appBuild = appBuild
        self.physicalDevice = physicalDevice
        self.simulatorOrEmulator = simulatorOrEmulator
        self.permissionsVisible = permissionsVisible
        self.privateSpaceBlocked = privateSpaceBlocked
        self.rawDataBlocked = rawDataBlocked
        self.plainLanguageSummary = "Echo Guardian recorded real iOS device evidence without raw data, private-space monitoring, or hidden behavior."
    }

    public func coreCompatibleJSONData() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(self)
    }
}

public struct AccessibilityEvidence: Codable, Equatable {
    public let schemaVersion: String
    public let screenName: String
    public let spokenOrVisibleText: [String]
    public let whatAreYouDoingAvailable: Bool
    public let emergencyClaimsAbsent: Bool

    public init(screenName: String, spokenOrVisibleText: [String]) throws {
        let joined = spokenOrVisibleText.joined(separator: " ").lowercased()
        if screenName.isEmpty || spokenOrVisibleText.isEmpty { throw EvidenceError.invalidDeviceEvidence("screen evidence is required") }
        if !joined.contains("what are you doing") { throw EvidenceError.invalidDeviceEvidence("what are you doing explanation is required") }
        for blocked in ["hipaa compliant", "gdpr compliant", "medical device", "emergency certified"] {
            if joined.contains(blocked) { throw EvidenceError.invalidDeviceEvidence("unsupported compliance or medical claim present") }
        }
        self.schemaVersion = "0.8"
        self.screenName = screenName
        self.spokenOrVisibleText = spokenOrVisibleText
        self.whatAreYouDoingAvailable = true
        self.emergencyClaimsAbsent = true
    }
}
