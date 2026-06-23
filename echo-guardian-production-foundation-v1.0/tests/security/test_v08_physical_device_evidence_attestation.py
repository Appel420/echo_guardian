from __future__ import annotations

import json
from pathlib import Path

import pytest

from echo_guardian_core.audit import AuditEntryInput, AuditLog
from echo_guardian_core.delivery.provider_adapter import DeliveryResult, MinimalDisclosureAlert
from echo_guardian_core.export import ExportPackageBuilder, ExportRequest
from echo_guardian_core.native.device_execution import (
    DeviceExecutionViolation,
    NativeAuditCheckpointSigner,
    PersistedDeviceSigningKeyStore,
    ProviderSandboxReceiptVerifier,
    SignedNativeExportBuilder,
    write_json,
)
from echo_guardian_core.native.physical_evidence import (
    AccessibilityEvidenceBuilder,
    CIReleaseAttestationBundleBuilder,
    DeviceRunEvidenceBuilder,
    ProviderTranscriptRedactionVerifier,
    SignedDeviceEvidenceBundleBuilder,
    audit_physical_evidence_event,
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
            event_type="v08_test_started",
            severity="normal",
            authority_context="system_internal",
            policy_id=pol.policy_id,
            policy_version=pol.policy_version,
            public_context={
                "space_id": "physical_device_evidence",
                "private_space": False,
                "signal_types": [],
                "plain_language": "Echo Guardian started v0.8 physical device evidence verification.",
                "raw_sensor_retained": False,
                "cloud_dependency": False,
                "automatic_export": False,
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


def signed_primitives(tmp_path: Path):
    p = policy()
    log = audit(tmp_path / "audit.jsonl", p)
    audit_physical_evidence_event(
        audit_log=log,
        policy=p,
        event_type="physical_device_evidence_collected",
        platform="ios",
        plain_language="Echo Guardian collected physical device evidence.",
    )
    checkpoint = NativeAuditCheckpointSigner(
        key_store=PersistedDeviceSigningKeyStore(root=tmp_path / "keys", platform="ios", key_alias="checkpoint")
    ).sign_checkpoint(audit_log=log)
    manifest = make_export(tmp_path, p, log)
    signed_manifest = SignedNativeExportBuilder(
        key_store=PersistedDeviceSigningKeyStore(root=tmp_path / "keys", platform="ios", key_alias="export")
    ).sign_manifest(manifest=manifest)
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
    redaction = ProviderTranscriptRedactionVerifier().verify(
        receipt=receipt,
        redacted_transcript="Minimal disclosure sandbox transcript: [REDACTED]. Please check on the user.",
    )
    accessibility = AccessibilityEvidenceBuilder().build(
        platform="ios",
        screen_name="Local Status",
        spoken_or_visible_text=[
            "What are you doing?",
            "Echo Guardian is checking the living room for safety signals.",
            "No emergency services are contacted by default.",
        ],
    )
    device = DeviceRunEvidenceBuilder().build(
        platform="ios",
        device_model="iPhone physical test device",
        os_version="iOS 18 physical-device evidence format",
        app_build="0.8.0-test",
        physical_device=True,
        simulator_or_emulator=False,
        permissions_visible=True,
        private_space_blocked=True,
        raw_data_blocked=True,
        audit_checkpoint_hash=checkpoint.checkpoint["merkle_root"],
        signed_export_manifest_hash=signed_manifest.export_manifest_hash,
        provider_sandbox_receipt_hash=receipt.receipt_hash,
        accessibility_capture_hash=accessibility.capture_hash,
    )
    bundle = SignedDeviceEvidenceBundleBuilder(
        key_store=PersistedDeviceSigningKeyStore(root=tmp_path / "keys", platform="ios", key_alias="evidence")
    ).build(
        device_evidence=[device],
        signed_checkpoint=checkpoint,
        signed_export_manifest=signed_manifest,
        redaction_proof=redaction,
        accessibility_capture=accessibility,
    )
    return device, checkpoint, signed_manifest, receipt, redaction, accessibility, bundle


@pytest.mark.parametrize("platform", ["ios", "android"])
def test_real_device_evidence_rejects_simulator_and_requires_safety_flags(platform: str):
    ok = DeviceRunEvidenceBuilder().build(
        platform=platform,
        device_model="physical device",
        os_version="native OS",
        app_build="0.8.0",
        physical_device=True,
        simulator_or_emulator=False,
        permissions_visible=True,
        private_space_blocked=True,
        raw_data_blocked=True,
        audit_checkpoint_hash="a" * 64,
    )
    assert ok.schema_version == "0.8"
    assert ok.physical_device is True
    assert ok.raw_data_blocked is True
    with pytest.raises(DeviceExecutionViolation):
        DeviceRunEvidenceBuilder().build(
            platform=platform,
            device_model="simulator",
            os_version="native OS",
            app_build="0.8.0",
            physical_device=False,
            simulator_or_emulator=True,
            permissions_visible=True,
            private_space_blocked=True,
            raw_data_blocked=True,
            audit_checkpoint_hash="a" * 64,
        )
    with pytest.raises(DeviceExecutionViolation):
        DeviceRunEvidenceBuilder().build(
            platform=platform,
            device_model="physical device",
            os_version="native OS",
            app_build="0.8.0",
            physical_device=True,
            simulator_or_emulator=False,
            permissions_visible=True,
            private_space_blocked=False,
            raw_data_blocked=True,
            audit_checkpoint_hash="a" * 64,
        )


def test_accessibility_evidence_requires_what_are_you_doing_and_blocks_claims():
    capture = AccessibilityEvidenceBuilder().build(
        platform="android",
        screen_name="Status",
        spoken_or_visible_text=["What are you doing?", "I am checking safety signals and can explain if help is needed."],
    )
    assert capture.what_are_you_doing_available is True
    assert capture.child_elderly_understandable is True
    with pytest.raises(DeviceExecutionViolation):
        AccessibilityEvidenceBuilder().build(platform="ios", screen_name="Status", spoken_or_visible_text=["HIPAA compliant medical device"])


def test_provider_sandbox_transcript_redaction_proof_blocks_raw_transcripts(tmp_path: Path):
    _, _, _, receipt, _, _, _ = signed_primitives(tmp_path)
    proof = ProviderTranscriptRedactionVerifier().verify(
        receipt=receipt,
        redacted_transcript="Minimal disclosure provider sandbox transcript. [REDACTED] exact details.",
    )
    assert proof.schema_version == "0.8"
    assert proof.sensitive_markers_found == []
    with pytest.raises(DeviceExecutionViolation):
        ProviderTranscriptRedactionVerifier().verify(receipt=receipt, redacted_transcript="Raw transcript with exact address and password")


def test_signed_device_evidence_bundle_verifies_and_rejects_tamper(tmp_path: Path):
    _, _, _, _, _, _, bundle = signed_primitives(tmp_path)
    assert SignedDeviceEvidenceBundleBuilder.verify(bundle)
    tampered = bundle.to_dict()
    tampered["evidence_hashes"] = ["0" * 64]
    assert SignedDeviceEvidenceBundleBuilder.verify(tampered) is False


def test_ci_release_attestation_requires_gradle_wrapper_and_verified_bundle(tmp_path: Path):
    _, _, _, _, _, _, bundle = signed_primitives(tmp_path)
    root = tmp_path / "root"
    (root / "native/android").mkdir(parents=True)
    (root / "native/android/gradlew").write_text("#!/usr/bin/env sh\nexit 0\n", encoding="utf-8")
    (root / "artifact.txt").write_text("artifact", encoding="utf-8")
    attestation = CIReleaseAttestationBundleBuilder().build(root=root, artifact_paths=["artifact.txt"], evidence_bundle=bundle)
    assert attestation["schema_version"] == "0.8"
    assert attestation["android_gradle_wrapper_included"] is True
    assert attestation["release_blocking_android_native_tests"] is True

    (root / "native/android/gradlew").unlink()
    with pytest.raises(DeviceExecutionViolation):
        CIReleaseAttestationBundleBuilder().build(root=root, artifact_paths=["artifact.txt"], evidence_bundle=bundle)


def test_v08_required_files_and_ci_android_wrapper_are_present():
    required = [
        "docs/native/v0.8-physical-device-evidence-release-attestation.md",
        "docs/native/v0.8-ios-device-execution-evidence-format.md",
        "docs/native/v0.8-android-device-execution-evidence-format.md",
        "docs/delivery/v0.8-provider-sandbox-transcript-redaction-proof.md",
        "docs/accessibility/v0.8-accessibility-test-evidence-capture.md",
        "docs/release/production-readiness-report-v0.8.json",
        "docs/sbom/sbom-v0.8.json",
        "native/android/gradlew",
        "native/android/gradle/wrapper/gradle-wrapper.properties",
        "tools/check_v08_release_artifacts.py",
    ]
    for rel in required:
        assert (ROOT / rel).exists(), rel
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    blocked_tokens = ["continue-on-error: true", "|| true", "soft-fail", "allow_failure"]
    assert not any(token in ci for token in blocked_tokens)
    assert "check_v08_release_artifacts.py" in ci
    assert "./gradlew :echo-guardian-core:testDebugUnitTest" in ci
    assert "swift test" in ci
