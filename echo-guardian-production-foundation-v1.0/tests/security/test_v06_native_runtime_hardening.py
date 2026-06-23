from __future__ import annotations

from pathlib import Path

import pytest

from echo_guardian_core.audit import AuditLog
from echo_guardian_core.baseline import BaselineProfile
from echo_guardian_core.delivery.provider_adapter import DeliveryResult, MinimalDisclosureAlert
from echo_guardian_core.native.runtime_hardening import (
    NativeObservationEnvelope,
    NativeRuntimeHardeningRunner,
    NativeRuntimePolicyViolation,
    ProviderDeliveryStatusStore,
)
from echo_guardian_core.policy import DEFAULT_PRODUCTION_POLICY_V02, ProductionPolicy, PolicyViolation

ROOT = Path(__file__).resolve().parents[2]


def policy(**overrides):
    data = dict(DEFAULT_PRODUCTION_POLICY_V02)
    data.update(overrides)
    p = ProductionPolicy(data)
    p.validate()
    return p


def envelope(**overrides):
    data = {
        "platform": "ios",
        "sensor_id": "ios.core_motion.activity",
        "signal_type": "motion",
        "space_id": "living_room",
        "private_space": False,
        "permission_state": "granted",
        "availability_state": "healthy",
        "quality": "good",
        "derived_metadata": {"motion_detected": True, "confidence_scaled": 90},
    }
    data.update(overrides)
    return NativeObservationEnvelope(**data)


def runner(tmp_path, p=None):
    return NativeRuntimeHardeningRunner(
        policy=p or policy(),
        audit_log=AuditLog.open(tmp_path / "native_audit.jsonl"),
    )


def test_native_runtime_cycle_updates_baseline_classifies_and_verifies_audit(tmp_path: Path):
    baseline = BaselineProfile.create()
    result = runner(tmp_path).run(envelope=envelope(), baseline=baseline)
    assert result.schema_version == "0.6"
    assert result.platform == "ios"
    assert result.audit_verified is True
    assert result.severity in {"normal", "unusual", "concerning", "severe", "emergency"}
    assert baseline.total_observations == 1
    assert "native ios safety check" in result.plain_language_summary


def test_android_native_runtime_cycle_is_core_compatible(tmp_path: Path):
    baseline = BaselineProfile.create()
    result = runner(tmp_path).run(envelope=envelope(platform="android", sensor_id="android.sensor.accelerometer"), baseline=baseline)
    assert result.platform == "android"
    assert result.audit_verified is True
    assert baseline.total_observations == 1


def test_private_space_blocked_before_ingestion(tmp_path: Path):
    with pytest.raises(NativeRuntimePolicyViolation):
        runner(tmp_path).run(envelope=envelope(space_id="bedroom", private_space=True), baseline=BaselineProfile.create())


def test_raw_like_native_metadata_blocked(tmp_path: Path):
    with pytest.raises(NativeRuntimePolicyViolation):
        runner(tmp_path).run(envelope=envelope(derived_metadata={"raw_sample": "blocked"}), baseline=BaselineProfile.create())


def test_hidden_cloud_or_telemetry_policy_blocked(tmp_path: Path):
    with pytest.raises(PolicyViolation):
        policy(cloud_dependency_for_core_loop=True)
    with pytest.raises(PolicyViolation):
        policy(silent_telemetry_enabled=True)


def test_delivery_status_persistence_is_local_minimal_and_audited(tmp_path: Path):
    store = ProviderDeliveryStatusStore(tmp_path / "delivery_status.jsonl")
    result = runner(tmp_path).run(
        envelope=envelope(),
        baseline=BaselineProfile.create(),
        delivery_store=store,
        delivery_result=DeliveryResult(
            status="attempted",
            provider="local_outbox",
            provider_message_id="local-001",
            plain_language_summary="A guarded local contact delivery was attempted.",
        ),
        delivery_alert=MinimalDisclosureAlert(
            severity="severe",
            reason="No response",
            location_context="Home - living room",
            recommended_action="Please check on the user.",
        ),
    )
    records = store.read_all()
    assert result.delivery_status == "attempted"
    assert len(records) == 1
    assert records[0]["minimal_disclosure"] is True
    assert records[0]["sensitive_details_included"] is False
    assert records[0]["emergency_services_used"] is False


def test_delivery_status_persistence_blocks_sensitive_egress(tmp_path: Path):
    with pytest.raises(NativeRuntimePolicyViolation):
        runner(tmp_path).run(
            envelope=envelope(),
            baseline=BaselineProfile.create(),
            delivery_store=ProviderDeliveryStatusStore(tmp_path / "delivery_status.jsonl"),
            delivery_result=DeliveryResult(
                status="attempted",
                provider="local_outbox",
                provider_message_id="local-001",
                plain_language_summary="blocked",
            ),
            delivery_alert=MinimalDisclosureAlert(
                severity="severe",
                reason="No response",
                location_context="Home - living room",
                recommended_action="Please check on the user.",
                sensitive_details_included=True,
            ),
        )


def test_native_export_package_creation_requires_explicit_local_path_and_hashes_manifest(tmp_path: Path):
    result = runner(tmp_path).run(
        envelope=envelope(),
        baseline=BaselineProfile.create(),
        export_dir=tmp_path / "native_export",
    )
    assert result.export_manifest_hash is not None
    package = tmp_path / "native_export" / "package"
    assert (package / "export_manifest.json").exists()
    assert (package / "audit_chain.jsonl").exists()
    assert (package / "baseline_summary.json").exists()


def test_native_audit_tamper_is_detected(tmp_path: Path):
    r = runner(tmp_path)
    r.run(envelope=envelope(), baseline=BaselineProfile.create())
    audit_path = tmp_path / "native_audit.jsonl"
    text = audit_path.read_text(encoding="utf-8")
    audit_path.write_text(text.replace("living_room", "tampered_room", 1), encoding="utf-8")
    reopened = AuditLog.open(audit_path)
    assert reopened.verify()


def test_v06_native_artifacts_exist_and_ci_has_no_soft_fail_placeholders():
    required = [
        "native/ios/EchoGuardianKit/Sources/EchoGuardianKit/Sensors/CoreMotionPermissionStatus.swift",
        "native/android/echo-guardian-core/src/main/java/org/echoguardian/sensors/AndroidSensorPermissionStatus.kt",
        "native/ios/EchoGuardianKit/Sources/EchoGuardianKit/Runtime/NativeCoreCycleBridge.swift",
        "native/android/echo-guardian-core/src/main/java/org/echoguardian/runtime/NativeCoreCycleBridge.kt",
        "docs/native/v0.6-native-runtime-hardening.md",
        "docs/release/production-readiness-report-v0.6.json",
        "tools/check_v06_release_artifacts.py",
    ]
    for rel in required:
        assert (ROOT / rel).exists(), rel
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    banned = ["continue-on-error: true", "|| true", "soft-fail", "allow-failure"]
    for text in banned:
        assert text not in ci
    assert "check_v06_release_artifacts.py" in ci
