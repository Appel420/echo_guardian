from __future__ import annotations

from pathlib import Path
import base64

from echo_guardian_core.delivery.provider_adapter import LocalOutboxDeliveryProvider, MinimalDisclosureAlert
from echo_guardian_core.security.device_keys import PortableDeviceSigningKey, recommended_device_key_capability

ROOT = Path(__file__).resolve().parents[2]


def test_ios_swift_package_scaffold_exists():
    assert (ROOT / "native/ios/EchoGuardianKit/Package.swift").exists()
    assert (ROOT / "native/ios/EchoGuardianKit/Sources/EchoGuardianKit/Keys/DeviceSigningKey.swift").exists()
    assert (ROOT / "native/ios/EchoGuardianKit/Sources/EchoGuardianKit/Sensors/MinimizedSensorObservation.swift").exists()
    assert (ROOT / "native/ios/EchoGuardianKit/Sources/EchoGuardianKit/Status/StatusViewModel.swift").exists()


def test_android_kotlin_module_scaffold_exists():
    assert (ROOT / "native/android/settings.gradle.kts").exists()
    assert (ROOT / "native/android/echo-guardian-core/build.gradle.kts").exists()
    assert (ROOT / "native/android/echo-guardian-core/src/main/java/org/echoguardian/keys/DeviceSigningKeyManager.kt").exists()
    assert (ROOT / "native/android/echo-guardian-core/src/main/java/org/echoguardian/sensors/MinimizedSensorObservation.kt").exists()


def test_device_key_capabilities_do_not_overclaim_secure_enclave():
    ios = recommended_device_key_capability("ios")
    assert ios.protection == "keychain"
    assert "Use Secure Enclave only" in ios.notes
    android = recommended_device_key_capability("android")
    assert android.protection == "android_keystore"
    assert "do not claim hardware protection" in android.notes


def test_portable_proof_of_possession_signs_real_challenge():
    key = PortableDeviceSigningKey()
    proof = key.sign_challenge(b"echo-guardian-v0.4")
    assert proof.algorithm == "ed25519_portable_development"
    assert proof.protection == "software_protected"
    assert base64.b64decode(proof.signature_b64)
    assert base64.b64decode(proof.challenge_b64) == b"echo-guardian-v0.4"


def test_delivery_provider_blocks_unauthorized_contact():
    provider = LocalOutboxDeliveryProvider()
    alert = MinimalDisclosureAlert(
        severity="severe",
        reason="No response",
        location_context="Home - living room",
        recommended_action="Please check on the user.",
    )
    result = provider.send({"authorized": "false"}, alert)
    assert result.status == "blocked"
    assert result.audit_required is True


def test_delivery_provider_blocks_emergency_services_by_default():
    provider = LocalOutboxDeliveryProvider()
    alert = MinimalDisclosureAlert(
        severity="emergency",
        reason="No response",
        location_context="Home - living room",
        recommended_action="Please check on the user.",
        emergency_services_used=True,
    )
    result = provider.send({"authorized": "true"}, alert)
    assert result.status == "blocked"
    assert "Emergency services" in result.plain_language_summary


def test_delivery_provider_allows_minimal_authorized_local_outbox():
    provider = LocalOutboxDeliveryProvider()
    alert = MinimalDisclosureAlert(
        severity="severe",
        reason="No response",
        location_context="Home - living room",
        recommended_action="Please check on the user.",
    )
    result = provider.send({"authorized": "true"}, alert)
    assert result.status == "attempted"
    assert result.audit_required is True


def test_ci_split_contains_expected_jobs():
    ci = (ROOT / ".github/workflows/ci.yml").read_text()
    for job in ["python-core", "ios-native", "android-native", "security", "sbom"]:
        assert job in ci


def test_accessibility_screen_flow_exists_and_is_plain_language():
    doc = (ROOT / "docs/accessibility/accessibility-screen-flow-prototype-v0.4.md").read_text()
    assert "What are you doing?" in doc
    assert "child" in doc.lower()
    assert "elderly" in doc.lower()
