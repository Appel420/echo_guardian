import Foundation

public struct NativeCoreCycleBridgeResult: Codable, Equatable {
    public let schemaVersion: String
    public let observationJson: String
    public let rawSensorRetained: Bool
    public let privateSpace: Bool
    public let readyForCore: Bool
    public let plainLanguageSummary: String
}

public enum NativeCoreCycleBridgeError: Error {
    case privateSpaceBlocked
    case rawLikeMetadataBlocked
    case encodingFailed
}

public final class NativeCoreCycleBridge {
    public init() {}

    public func bridge(observation: MinimizedSensorObservation) throws -> NativeCoreCycleBridgeResult {
        if observation.privateSpace || observation.spaceId == "bathroom" || observation.spaceId == "bedroom" {
            throw NativeCoreCycleBridgeError.privateSpaceBlocked
        }
        if observation.rawSensorRetained {
            throw NativeCoreCycleBridgeError.rawLikeMetadataBlocked
        }
        let rawLike = ["raw", "raw_data", "raw_sample", "samples", "audio_buffer", "video_frame", "transcript", "waveform", "packet_capture"]
        if observation.derivedMetadata.keys.contains(where: { rawLike.contains($0.lowercased()) }) {
            throw NativeCoreCycleBridgeError.rawLikeMetadataBlocked
        }
        let data = try JSONEncoder().encode(observation)
        guard let json = String(data: data, encoding: .utf8) else { throw NativeCoreCycleBridgeError.encodingFailed }
        return NativeCoreCycleBridgeResult(
            schemaVersion: "0.6",
            observationJson: json,
            rawSensorRetained: false,
            privateSpace: false,
            readyForCore: true,
            plainLanguageSummary: "The native observation is minimized and ready for the Echo Guardian core loop."
        )
    }
}
