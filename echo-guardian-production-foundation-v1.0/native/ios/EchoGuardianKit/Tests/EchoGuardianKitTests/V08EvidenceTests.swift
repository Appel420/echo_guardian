import XCTest
@testable import EchoGuardianKit

final class V08EvidenceTests: XCTestCase {
    func testIOSPhysicalDeviceEvidenceRequiresSafetyFlags() throws {
        let evidence = try DeviceExecutionEvidence(
            deviceModel: "iPhone physical device",
            osVersion: "iOS test evidence",
            appBuild: "0.8.0",
            physicalDevice: true,
            simulatorOrEmulator: false,
            permissionsVisible: true,
            privateSpaceBlocked: true,
            rawDataBlocked: true
        )
        XCTAssertEqual(evidence.schemaVersion, "0.8")
        XCTAssertTrue(evidence.plainLanguageSummary.contains("without raw data"))
        XCTAssertNoThrow(try evidence.coreCompatibleJSONData())
    }

    func testIOSPhysicalDeviceEvidenceRejectsSimulator() {
        XCTAssertThrowsError(try DeviceExecutionEvidence(
            deviceModel: "simulator",
            osVersion: "iOS test evidence",
            appBuild: "0.8.0",
            physicalDevice: false,
            simulatorOrEmulator: true,
            permissionsVisible: true,
            privateSpaceBlocked: true,
            rawDataBlocked: true
        ))
    }

    func testAccessibilityEvidenceRequiresWhatAreYouDoing() throws {
        let evidence = try AccessibilityEvidence(
            screenName: "Status",
            spokenOrVisibleText: ["What are you doing?", "Echo Guardian is checking safety signals."]
        )
        XCTAssertTrue(evidence.whatAreYouDoingAvailable)
        XCTAssertThrowsError(try AccessibilityEvidence(screenName: "Status", spokenOrVisibleText: ["HIPAA compliant medical device"]))
    }
}
