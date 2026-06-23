import XCTest
@testable import EchoGuardianKit

final class V05RuntimeTests: XCTestCase {
    func testSwiftObservationBridgesToCoreCompatibleJSON() throws {
        let native = MinimizedSensorObservation(signalType: .motion, spaceId: "living_room", privateSpace: false, permissionState: "granted", availabilityState: "available", derivedMetadata: ["motion_detected": 1, "confidence_scaled": 90])
        let bridged = try CoreJSONBridge().bridge(native)
        XCTAssertEqual(bridged.schema_version, "0.5")
        XCTAssertEqual(bridged.space_id, "living_room")
        XCTAssertFalse(bridged.raw_sensor_retained)
        let data = try CoreJSONBridge().jsonData(for: bridged)
        XCTAssertTrue(String(data: data, encoding: .utf8)!.contains("derived_metadata"))
    }

    func testPolicyStatusBlocksHiddenProductLawViolations() {
        let status = NativePolicyStatus(monitoringEnabled: true, privateSpaceMonitoringEnabled: false, authorityLabel: "User controlled")
        XCTAssertTrue(status.plainLanguage.contains("monitoring is on"))
    }

    func testAccessibilityFlowIncludesWhatAreYouDoing() {
        let screens = AccessibilityFlowFactory.defaultScreens()
        XCTAssertTrue(screens.contains { $0.voicePrompt == "What are you doing?" })
    }
}
