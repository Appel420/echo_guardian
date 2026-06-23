import XCTest
@testable import EchoGuardianKit

final class EchoGuardianKitTests: XCTestCase {
    func testStatusIsPlainLanguage() {
        let status = StatusViewModel().makeStatus(monitoringOn: true, spaces: ["living room"], signals: ["movement"], authority: "User controlled", degraded: false)
        XCTAssertTrue(status.whatAreYouDoing.contains("Echo Guardian monitoring is on"))
    }

    func testLocalOutboxBlocksEmergencyServices() {
        let provider = LocalOutboxProvider()
        let payload = GuardedAlertPayload(severity: "severe", reason: "No response", locationContext: "Home", recommendedAction: "Check on the user", sensitiveDetailsIncluded: false, emergencyServicesUsed: true)
        XCTAssertEqual(provider.send(payload: payload, toAuthorizedContact: "authorized").status, "blocked")
    }
}
