import Foundation

public struct NativeAuditRecord: Codable, Equatable {
    public let schema_version: String
    public let event_type: String
    public let severity: String
    public let authority_context: String
    public let plain_language: String
    public let created_at: String
}

public final class NativeAuditAppender {
    private let auditURL: URL

    public init(auditURL: URL) {
        self.auditURL = auditURL
    }

    public func append(_ record: NativeAuditRecord) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(record)
        var line = data
        line.append(0x0A)
        let manager = FileManager.default
        try manager.createDirectory(at: auditURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        if manager.fileExists(atPath: auditURL.path) {
            let handle = try FileHandle(forWritingTo: auditURL)
            try handle.seekToEnd()
            try handle.write(contentsOf: line)
            try handle.close()
        } else {
            try line.write(to: auditURL, options: [.atomic])
        }
    }

    public static func statusCheckRecord(message: String) -> NativeAuditRecord {
        NativeAuditRecord(
            schema_version: "0.5",
            event_type: "native_status_check",
            severity: "normal",
            authority_context: "user_controlled",
            plain_language: message,
            created_at: ISO8601DateFormatter().string(from: Date())
        )
    }
}
