import XCTest
@testable import EchoGuardianKit

final class V07DeviceExecutionTests: XCTestCase {
    func testSignedNativeExportPolicyBlocksAutomaticExport() {
        XCTAssertTrue(SignedNativeExportPolicy.validate(userConfirmed: true, automaticExport: false, emergencyServicesUsed: false))
        XCTAssertFalse(SignedNativeExportPolicy.validate(userConfirmed: false, automaticExport: false, emergencyServicesUsed: false))
        XCTAssertFalse(SignedNativeExportPolicy.validate(userConfirmed: true, automaticExport: true, emergencyServicesUsed: false))
    }

    func testProviderSandboxReceiptRequiresSandbox() {
        XCTAssertNotNil(ProviderSandboxReceiptVerifier.verify(provider: "local_outbox", messageId: "sandbox-1", status: "attempted", sandbox: true))
        XCTAssertNil(ProviderSandboxReceiptVerifier.verify(provider: "local_outbox", messageId: "sandbox-1", status: "attempted", sandbox: false))
    }

    func testNativeAuditCheckpointStatementIsPlainLanguage() {
        let statement = NativeAuditCheckpointSigner.statement(sequence: 1, latestEntryHash: String(repeating: "0", count: 64), merkleRoot: String(repeating: "1", count: 64))
        XCTAssertEqual(statement.schemaVersion, "0.7")
        XCTAssertTrue(statement.plainLanguageSummary.contains("audit checkpoint"))
    }
}
