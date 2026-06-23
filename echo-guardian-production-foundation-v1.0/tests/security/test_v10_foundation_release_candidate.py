from pathlib import Path
import json

import pytest

from echo_guardian_core.native.device_execution import DeviceExecutionViolation, PersistedDeviceSigningKeyStore
from echo_guardian_core.release.foundation_rc import (
    TrustedGradleWrapperEvidenceBuilder,
    PhysicalDeviceExecutionEvidenceBuilder,
    SignedSBOMVerificationBuilder,
    ReviewCompletionRecordBuilder,
    V10FoundationReadinessGateBuilder,
    ClaimBlockingReleaseTextReview,
    write_json,
)
from echo_guardian_core.release.external_review import SignedSBOMAttestationBuilder

ROOT = Path(__file__).resolve().parents[2]


def test_trusted_gradle_wrapper_evidence_blocks_missing_jar_but_requires_pinned_properties():
    evidence = TrustedGradleWrapperEvidenceBuilder().build(android_root=ROOT / "native/android")
    assert evidence.schema_version == "1.0-rc"
    assert evidence.release_blocking is True
    assert evidence.distribution_url.endswith("gradle-8.7-bin.zip")
    assert evidence.gradle_wrapper_jar_present is False
    assert evidence.evidence_state == "missing"
    assert "Do not fabricate" in evidence.plain_language_summary


def test_physical_device_evidence_rejects_simulator_or_emulator():
    with pytest.raises(DeviceExecutionViolation):
        PhysicalDeviceExecutionEvidenceBuilder().build(
            platform="ios",
            device_model="iPhone",
            os_version="18.x",
            app_build_id="local",
            tests_passed=True,
            private_space_blocking_verified=True,
            raw_data_blocking_verified=True,
            audit_checkpoint_verified=True,
            accessibility_evidence_captured=True,
            execution_log="simulator run",
            simulator_or_emulator_used=True,
        )


def test_physical_device_evidence_collected_only_when_all_required_items_pass():
    missing = PhysicalDeviceExecutionEvidenceBuilder().build(
        platform="android",
        device_model=None,
        os_version=None,
        app_build_id=None,
        tests_passed=False,
        private_space_blocking_verified=False,
        raw_data_blocking_verified=False,
        audit_checkpoint_verified=False,
        accessibility_evidence_captured=False,
        execution_log=None,
    )
    assert missing.evidence_state == "missing"
    collected = PhysicalDeviceExecutionEvidenceBuilder().build(
        platform="android",
        device_model="Pixel test device",
        os_version="Android test",
        app_build_id="v1-rc-local",
        tests_passed=True,
        private_space_blocking_verified=True,
        raw_data_blocking_verified=True,
        audit_checkpoint_verified=True,
        accessibility_evidence_captured=True,
        execution_log="release blocking local/native test log",
    )
    assert collected.evidence_state == "collected"
    assert collected.execution_log_hash is not None


def test_signed_sbom_verification_accepts_valid_attestation_and_rejects_tamper(tmp_path: Path):
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps({"schema_version": "1.0-rc", "components": [{"name": "echo_guardian_core"}]}), encoding="utf-8")
    key_store = PersistedDeviceSigningKeyStore(root=tmp_path / "keys", platform="portable", key_alias="sbom")
    attestation = SignedSBOMAttestationBuilder(key_store=key_store).build(sbom_path=sbom)
    attestation_path = tmp_path / "attestation.json"
    write_json(attestation_path, attestation.to_dict())
    verified = SignedSBOMVerificationBuilder().verify(sbom_path=sbom, attestation_path=attestation_path)
    assert verified.signature_valid is True
    assert verified.evidence_state == "collected"
    sbom.write_text(json.dumps({"schema_version": "1.0-rc", "components": [{"name": "tampered"}]}), encoding="utf-8")
    rejected = SignedSBOMVerificationBuilder().verify(sbom_path=sbom, attestation_path=attestation_path)
    assert rejected.signature_valid is False
    assert rejected.evidence_state == "rejected"


def test_review_completion_requires_human_completion_and_no_blockers():
    builder = ReviewCompletionRecordBuilder()
    blocked = builder.build(
        review_type="external_security",
        package_path="docs/review/external-security-review-package-v1.0.md",
        completed_by=None,
        completed_at=None,
        passed=True,
        findings_count=0,
        unresolved_blockers=[],
    )
    assert blocked.passed is False
    complete = builder.build(
        review_type="privacy",
        package_path="docs/review/privacy-review-package-v1.0.md",
        completed_by="reviewer@example.invalid",
        completed_at="2026-06-23T10:00:00Z",
        passed=True,
        findings_count=0,
        unresolved_blockers=[],
    )
    assert complete.passed is True


def test_claim_blocking_release_text_review_blocks_forbidden_terms(tmp_path: Path):
    good = tmp_path / "good.md"
    bad = tmp_path / "bad.md"
    good.write_text("Echo Guardian is a local-first production foundation.", encoding="utf-8")
    bad.write_text("This is HIPAA compliant and medical device approved.", encoding="utf-8")
    review = ClaimBlockingReleaseTextReview().review_files(files=[good])
    assert review["passed"] is True
    blocked = ClaimBlockingReleaseTextReview().review_files(files=[bad])
    assert blocked["passed"] is False
    assert any("hipaa compliant" in item["blocked_terms_found"] for item in blocked["results"])


def test_v1_foundation_gate_blocks_until_all_release_evidence_passes():
    blocked = V10FoundationReadinessGateBuilder().build(evidence={"no_hipaa_or_gdpr_claims": True})
    assert blocked.decision == "blocked"
    all_evidence = {item: True for item in V10FoundationReadinessGateBuilder.REQUIRED}
    approved = V10FoundationReadinessGateBuilder().build(evidence=all_evidence, release_notes_text="release notes")
    assert approved.decision == "approved_for_foundation_release"
    assert approved.release_notes_hash is not None


def test_v1_required_artifacts_are_present_and_gate_is_evidence_bound():
    required = [
        "src/echo_guardian_core/release/foundation_rc.py",
        "docs/native/v1.0-trusted-gradle-wrapper-evidence.md",
        "docs/native/v1.0-ios-physical-device-evidence.md",
        "docs/native/v1.0-android-local-native-test-evidence.md",
        "docs/sbom/signed-sbom-attestation-v1.0.md",
        "docs/review/external-security-review-package-v1.0.md",
        "docs/review/privacy-review-package-v1.0.md",
        "docs/review/clinical-legal-claim-blocking-review-v1.0.md",
        "docs/release/v1.0-foundation-readiness-gate.md",
        "docs/release/production-readiness-report-v1.0.json",
        "examples/local-live-personal/v10_foundation_release_candidate/v1_foundation_readiness_gate_result.json",
        "examples/local-live-personal/v10_foundation_release_candidate/signed_sbom_verification.json",
        "RELEASE_NOTES_v1.0.md",
    ]
    for rel in required:
        assert (ROOT / rel).exists(), rel
    gate = json.loads((ROOT / "examples/local-live-personal/v10_foundation_release_candidate/v1_foundation_readiness_gate_result.json").read_text())
    assert gate["schema_version"] == "1.0-rc"
    assert gate["decision"] == "blocked"
    assert "HIPAA compliance claims" in gate["blocked_claims"]
