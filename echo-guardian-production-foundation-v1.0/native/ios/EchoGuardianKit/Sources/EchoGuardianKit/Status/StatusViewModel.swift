import Foundation

public struct PlainStatus: Codable, Equatable {
    public let monitoringOn: Bool
    public let activeSpaces: [String]
    public let activeSignalTypes: [String]
    public let authorityLabel: String
    public let degraded: Bool
    public let whatAreYouDoing: String
}

public final class StatusViewModel {
    public init() {}

    public func makeStatus(monitoringOn: Bool, spaces: [String], signals: [String], authority: String, degraded: Bool) -> PlainStatus {
        let onOff = monitoringOn ? "on" : "off"
        let spacesText = spaces.isEmpty ? "no rooms" : spaces.joined(separator: ", ")
        let signalText = signals.isEmpty ? "no safety signals" : signals.joined(separator: ", ")
        let degradedText = degraded ? " Some parts need attention." : " Everything needed for this local status view is working."
        return PlainStatus(
            monitoringOn: monitoringOn,
            activeSpaces: spaces,
            activeSignalTypes: signals,
            authorityLabel: authority,
            degraded: degraded,
            whatAreYouDoing: "Echo Guardian monitoring is \(onOff). Active spaces: \(spacesText). It uses: \(signalText). Control: \(authority).\(degradedText)"
        )
    }
}
