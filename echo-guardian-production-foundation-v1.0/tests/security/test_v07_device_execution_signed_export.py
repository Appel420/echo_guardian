from __future__ import annotations

import json
from pathlib import Path

import pytest

from echo_guardian_core.audit import AuditEntryInput, AuditLog
from echo_guardian_core.delivery.provider_adapter import DeliveryResult, MinimalDisclosureAlert
from echo_guardian_core.export import ExportPackageBuilder, ExportRequest
from echo_guardian_core.native.device_execution import (
    ArtifactAttestationBuilder,
    DeviceExecutionViolation,
    NativeAuditCheckpointSigner,
    PersistedDeviceSigningKeyStore,
    PhysicalDeviceChecklistBuilder,
    ProviderSandboxReceiptVerifier,
    SignedNativeExportBuilder,
    audit_device_execution_event,
    write_json,
)
from echo_guardian_core.policy import DEFAULT_PRODUCTION_POLICY_V02, ProductionPolicy

ROOT = Path(__file__).resolve().parents[2]


def policy() -> ProductionPolicy:
    data = dict(DEFAULT_PRODUCTION_POLICY_V02)
    data["monitoring_enabled"] = True
    data["export_permissions"] = {"user_export": True, "automatic_export": False}
    p = ProductionPolicy(data)
    p.validate()
    return p


def audit(path: Path, p: ProductionPolicy | None = None) -> AuditLog:
    log = AuditLog.open(path)
    pol = p or policy()
    log.append(
        AuditEntryInput(
            event_type="v07_test_started",
            severity="normal",
            authority_context="system_internal",
            policy_id=pol.policy_id,
            policy_version=pol.policy_version,
            public_context={
                "space_id": "native_device_execution",
                "private_space": False,
                "signal_types": [],
                "plain_language": "Echo Guardian started v0.7 device execution verification.",
                "raw_sensor_retained": False,
                "cloud_dependency": False,
            },
        )
    )
    return log


def make_export(tmp_path: Path, p: ProductionPolicy, log: AuditLog) -> dict:
    policy_path = tmp_path / "policy.json"
    baseline_path = tmp_path / "baseline.json"
    status_path = tmp_path / "status.json"
    write_json(policy_path, p.data)
    write_json(baseline_path, {"schema_version": "0.2", "baseline_id": "baseline-test", "status": "learning"})
    write_json(status_path, {"schema_version": "0.2", "status_id": "status-test", "monitoring_on": True})
    return ExportPackageBuilder(policy=p, audit_log=log).create_export(
        request=ExportRequest(export_type="full_export", user_confirmed=True, redactions_applied=True),
        export_dir=tmp_path / "export_package",
        audit_chain_path=log.path,
        policy_path=policy_path,
        baseline_path=baseline_path,
        status_path=status_path,
    )


def full_evidence(**overrides):
    data = {
        "physical_device_named": True,
        "permissions_visible": True,
        "private_space_blocked": True,
        "raw_data_blocked": True,
        "audit_append_enabled": True,
        "key_persisted": True,
        "export_user_confirmed": True,
        "provider_sandbox_only": True,
        "accessibility_flow_tested": True,
    }
    data.update(overrides)
    return data


def test_physical_device_execution_checklist_passes_only_with_all_required_evidence():
    report = PhysicalDeviceChecklistBuilder().build(platform="ios", evidence=full_evidence())
    assert report.schema_version == "0.7"
    assert report.approved_for_device_execution is True
    assert "HIPAA" in report.plain_language_summary

    failed = PhysicalDeviceChecklistBuilder().build(platform="android", evidence=full_evidence(raw_data_blocked=False))
    assert failed.approved_for_device_execution is False
    assert any(item.item_id == "raw_data_blocked" and item.passed is False for item in failed.items)


@pytest.mark.parametrize("platform", ["ios", "android"])
def test_persisted_key_proof_survives_reload_and_verifies(tmp_path: Path, platform: str):
    store = PersistedDeviceSigningKeyStore(root=tmp_path / "keys", platform=platform, key_alias="echo_guardian_device_signing")
    first = store.prove_possession(challenge=b"echo-guardian-v07-device-proof")
    second = PersistedDeviceSigningKeyStore(root=tmp_path / "keys", platform=platform, key_alias="echo_guardian_device_signing").prove_possession(
        challenge=b"echo-guardian-v07-second-proof"
    )
    assert first.public_key_hex == second.public_key_hex
    assert first.key_persisted is True
    assert platform in first.native_protection_label
    assert PersistedDeviceSigningKeyStore.verify_proof(first)
    assert PersistedDeviceSigningKeyStore.verify_proof(second)


def test_signed_native_export_manifest_requires_confirmation_and_verifies(tmp_path: Path):
    p = policy()
    log = audit(tmp_path / "audit.jsonl", p)
    manifest = make_export(tmp_path, p, log)
    signer = SignedNativeExportBuilder(
        key_store=PersistedDeviceSigningKeyStore(root=tmp_path / "keys", platform="ios", key_alias="export_signing")
    )
    signed = signer.sign_manifest(manifest=manifest)
    assert signed.schema_version == "0.7"
    assert signed.user_confirmed is True
    assert signed.automatic_export is False
    assert signer.verify_signed_manifest(manifest=manifest, signed=signed)

    tampered = dict(manifest)
    tampered["automatic_export"] = True
    assert signer.verify_signed_manifest(manifest=tampered, signed=signed) is False
    with pytest.raises(DeviceExecutionViolation):
        signer.sign_manifest(manifest={**manifest, "user_confirmed": False})


def test_native_audit_checkpoint_is_signed_only_after_chain_verification(tmp_path: Path):
    p = policy()
    log = audit(tmp_path / "audit.jsonl", p)
    audit_device_execution_event(
        audit_log=log,
        policy=p,
        event_type="native_accessibility_ui_tested",
        platform="ios",
        plain_language="Echo Guardian tested the native accessibility flow.",
    )
    signed = NativeAuditCheckpointSigner(
        key_store=PersistedDeviceSigningKeyStore(root=tmp_path / "keys", platform="ios", key_alias="checkpoint_signing")
    ).sign_checkpoint(audit_log=log)
    assert signed.audit_verified is True
    assert signed.checkpoint["signature_algorithm"] == "ed25519"
    assert AuditLog.verify_checkpoint(signed.checkpoint) == []

    lines = log.path.read_text(encoding="utf-8").splitlines()
    obj = json.loads(lines[0])
    obj["event_type"] = "tampered"
    log.path.write_text(json.dumps(obj) + "\n" + "\n".join(lines[1:]) + "\n", encoding="utf-8")
    tampered_log = AuditLog.open(log.path)
    with pytest.raises(DeviceExecutionViolation):
        NativeAuditCheckpointSigner(
            key_store=PersistedDeviceSigningKeyStore(root=tmp_path / "keys", platform="ios", key_alias="checkpoint_signing")
        ).sign_checkpoint(audit_log=tampered_log)


def test_provider_sandbox_delivery_receipt_verification_blocks_live_or_mismatched_receipts():
    result = DeliveryResult(status="attempted", provider="local_outbox", provider_message_id="sandbox-001", plain_language_summary="sandbox attempted")
    alert = MinimalDisclosureAlert(
        severity="severe",
        reason="No response",
        location_context="Home - living room",
        recommended_action="Please check on the user.",
    )
    receipt = ProviderSandboxReceiptVerifier().verify(
        result=result,
        alert=alert,
        provider_response={"sandbox": True, "provider": "local_outbox", "provider_message_id": "sandbox-001"},
    )
    assert receipt.schema_version == "0.7"
    assert receipt.sandbox_verified is True
    assert receipt.sensitive_details_included is False
    assert receipt.emergency_services_used is False

    with pytest.raises(DeviceExecutionViolation):
        ProviderSandboxReceiptVerifier().verify(result=result, alert=alert, provider_response={"sandbox": False, "provider": "local_outbox", "provider_message_id": "sandbox-001"})
    with pytest.raises(DeviceExecutionViolation):
        ProviderSandboxReceiptVerifier().verify(result=result, alert=alert, provider_response={"sandbox": True, "provider": "wrong", "provider_message_id": "sandbox-001"})


def test_artifact_attestation_hashes_release_files(tmp_path: Path):
    (tmp_path / "a.txt").write_text("alpha", encoding="utf-8")
    (tmp_path / "b.txt").write_text("beta", encoding="utf-8")
    statement = ArtifactAttestationBuilder().build(root=tmp_path, artifact_paths=["b.txt", "a.txt"])
    assert statement["schema_version"] == "0.7"
    assert statement["artifact_count"] == 2
    assert statement["attestation_hash"]
    with pytest.raises(DeviceExecutionViolation):
        ArtifactAttestationBuilder().build(root=tmp_path, artifact_paths=["missing.txt"])


def test_v07_required_files_and_ci_do_not_soft_fail():
    required = [
        "docs/native/v0.7-device-execution-signed-native-export.md",
        "docs/secure-keys/v0.7-persisted-signing-proof-tests.md",
        "docs/delivery/v0.7-provider-sandbox-delivery-receipt-verification.md",
        "docs/accessibility/v0.7-native-accessibility-ui-tests.md",
        "docs/release/production-readiness-report-v0.7.json",
        "docs/sbom/sbom-v0.7.json",
        "native/ios/EchoGuardianKit/Sources/EchoGuardianKit/Export/SignedNativeExportManifest.swift",
        "native/android/echo-guardian-core/src/main/java/org/echoguardian/export/SignedNativeExportManifest.kt",
        "tools/check_v07_release_artifacts.py",
    ]
    for rel in required:
        assert (ROOT / rel).exists(), rel
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    blocked_tokens = ["continue-on-error: true", "|| true", "soft-fail", "allow_failure"]
    assert not any(token in ci for token in blocked_tokens)
    assert "check_v07_release_artifacts.py" in ci
    assert ":echo-guardian-core:testDebugUnitTest" in ci
    assert "swift test" in ci
