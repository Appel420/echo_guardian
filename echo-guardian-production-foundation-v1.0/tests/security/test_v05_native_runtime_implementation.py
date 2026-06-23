from __future__ import annotations

from pathlib import Path
import json

import pytest

from echo_guardian_core.platform.native_runtime_bridge import NativeCoreObservation
from echo_guardian_core.sensor import SensorPolicyViolation
from echo_guardian_core.delivery.provider_adapter import LocalOutboxDeliveryProvider, MinimalDisclosureAlert

ROOT = Path(__file__).resolve().parents[2]


def test_ios_runtime_bridge_artifacts_exist():
    required = [
        "native/ios/EchoGuardianKit/Sources/EchoGuardianKit/Runtime/CoreJSONBridge.swift",
        "native/ios/EchoGuardianKit/Sources/EchoGuardianKit/Audit/NativeAuditAppender.swift",
        "native/ios/EchoGuardianKit/Sources/EchoGuardianKit/Policy/NativePolicyStatus.swift",
        "native/ios/EchoGuardianKit/Sources/EchoGuardianKit/Accessibility/AccessibilityFlowModel.swift",
        "native/ios/EchoGuardianKit/Tests/EchoGuardianKitTests/V05RuntimeTests.swift",
    ]
    for item in required:
        assert (ROOT / item).exists(), item


def test_android_runtime_bridge_artifacts_exist():
    required = [
        "native/android/echo-guardian-core/src/main/java/org/echoguardian/runtime/CoreJsonBridge.kt",
        "native/android/echo-guardian-core/src/main/java/org/echoguardian/audit/NativeAuditAppender.kt",
        "native/android/echo-guardian-core/src/main/java/org/echoguardian/policy/NativePolicyStatus.kt",
        "native/android/echo-guardian-core/src/main/java/org/echoguardian/accessibility/AccessibilityFlowModel.kt",
        "native/android/echo-guardian-core/src/test/java/org/echoguardian/V05RuntimeTest.kt",
    ]
    for item in required:
        assert (ROOT / item).exists(), item


def test_native_core_observation_converts_to_device_signal_sample():
    native = {
        "schema_version": "0.5",
        "observation_id": "obs-native-1",
        "created_at": "2026-06-22T14:15:00Z",
        "sensor_id": "ios-native-sensor",
        "signal_type": "motion",
        "space_id": "living_room",
        "private_space": False,
        "quality": "good",
        "permission_state": "granted",
        "availability_state": "healthy",
        "raw_sensor_retained": False,
        "derived_metadata": {"motion_detected": 1, "confidence_scaled": 90},
        "plain_language_summary": "Echo Guardian received a minimized safety signal for living_room. Raw sensor data was not kept.",
    }
    obs = NativeCoreObservation.from_native_json(native)
    sample = obs.to_device_signal_sample()
    assert sample.raw_sample is None
    assert sample.space_id == "living_room"
    assert sample.derived_metadata["motion_detected"] == 1


@pytest.mark.parametrize(
    "patch, message",
    [
        ({"private_space": True}, "private-space"),
        ({"space_id": "bathroom"}, "bathroom/bedroom"),
        ({"raw_sensor_retained": True}, "raw sensor"),
        ({"derived_metadata": {"raw_sample": "bad"}}, "raw-like"),
    ],
)
def test_native_core_observation_rejects_product_law_violations(patch, message):
    native = {
        "schema_version": "0.5",
        "observation_id": "obs-native-1",
        "created_at": "2026-06-22T14:15:00Z",
        "sensor_id": "ios-native-sensor",
        "signal_type": "motion",
        "space_id": "living_room",
        "private_space": False,
        "quality": "good",
        "permission_state": "granted",
        "availability_state": "healthy",
        "raw_sensor_retained": False,
        "derived_metadata": {"motion_detected": 1},
        "plain_language_summary": "Echo Guardian received a minimized safety signal.",
    }
    native.update(patch)
    with pytest.raises(SensorPolicyViolation, match=message):
        NativeCoreObservation.from_native_json(native)


def test_guarded_provider_harness_blocks_sensitive_and_emergency_payloads():
    provider = LocalOutboxDeliveryProvider()
    emergency = MinimalDisclosureAlert(
        severity="emergency",
        reason="No response",
        location_context="Home - living room",
        recommended_action="Please check on the user.",
        emergency_services_used=True,
    )
    assert provider.send({"authorized": "true"}, emergency).status == "blocked"
    sensitive = MinimalDisclosureAlert(
        severity="severe",
        reason="No response",
        location_context="Home - living room",
        recommended_action="Please check on the user.",
        sensitive_details_included=True,
    )
    assert provider.send({"authorized": "true"}, sensitive).status == "blocked"


def test_ci_has_no_soft_fail_placeholders_and_splits_native_jobs():
    ci = (ROOT / ".github/workflows/ci.yml").read_text()
    assert "|| true" not in ci
    assert "continue-on-error" not in ci
    for job in ["python-core", "ios-native", "android-native", "security", "sbom"]:
        assert job in ci
    assert "testDebugUnitTest" in ci


def test_v05_readiness_report_exists_and_matches_release():
    report = json.loads((ROOT / "docs/release/production-readiness-report-v0.5.json").read_text())
    assert report["version"] == "0.5"
    assert report["decision"] == "native_runtime_start_completed"
    assert report["claims_not_approved"]["hipaa_compliance_claims"] is False
    assert report["claims_not_approved"]["medical_device_claims"] is False


def test_accessibility_screen_flow_v05_is_plain_language():
    doc = (ROOT / "docs/accessibility/accessibility-screen-flow-prototype-v0.5.md").read_text()
    assert "What are you doing?" in doc
    assert "child" in doc.lower()
    assert "elderly" in doc.lower()
    assert "exactly what your safety contact would receive" in doc
