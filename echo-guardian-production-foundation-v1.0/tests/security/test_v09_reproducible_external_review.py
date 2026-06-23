from __future__ import annotations

import json
from pathlib import Path

import pytest

from echo_guardian_core.native.device_execution import DeviceExecutionViolation, PersistedDeviceSigningKeyStore
from echo_guardian_core.release.external_review import (
    AndroidLocalTestEvidenceBuilder,
    ClaimBlockingChecklistBuilder,
    DependencyLicenseReportBuilder,
    ExternalReviewPackageBuilder,
    IOSPhysicalDeviceChecklistRefinementBuilder,
    SignedSBOMAttestationBuilder,
    TrustedGradleWrapperInstructionBuilder,
    V10FoundationReleaseCandidateGateBuilder,
)

ROOT = Path(__file__).resolve().parents[2]


def test_trusted_gradle_wrapper_instructions_are_release_blocking():
    instructions = TrustedGradleWrapperInstructionBuilder().build(gradle_version="8.7")
    assert instructions.schema_version == "0.9"
    assert instructions.release_blocking is True
    assert "gradle wrapper --gradle-version 8.7 --distribution-type bin" in instructions.required_commands
    assert "./gradlew :echo-guardian-core:testDebugUnitTest" in instructions.required_commands
    assert "Do not hand-edit or invent gradle-wrapper.jar" in instructions.wrapper_jar_policy


def test_android_local_test_evidence_requires_wrapper_pass_and_no_soft_fail():
    evidence = AndroidLocalTestEvidenceBuilder().build(
        command="./gradlew :echo-guardian-core:testDebugUnitTest",
        gradle_wrapper_present=True,
        gradle_wrapper_jar_sha256="a" * 64,
        tests_passed=True,
        soft_fail_used=False,
        execution_log="BUILD SUCCESSFUL in release-blocking local Android native tests",
    )
    assert evidence.schema_version == "0.9"
    assert evidence.release_blocking is True
    assert evidence.soft_fail_used is False
    with pytest.raises(DeviceExecutionViolation):
        AndroidLocalTestEvidenceBuilder().build(
            command="./gradlew :echo-guardian-core:testDebugUnitTest || true",
            gradle_wrapper_present=True,
            gradle_wrapper_jar_sha256="a" * 64,
            tests_passed=True,
            soft_fail_used=True,
            execution_log="soft failed",
        )


def test_ios_physical_device_checklist_rejects_simulator_evidence_for_release():
    checklist = IOSPhysicalDeviceChecklistRefinementBuilder().build()
    assert checklist.schema_version == "0.9"
    assert checklist.simulator_evidence_allowed is False
    assert checklist.release_blocking is True
    assert "private-space blocking evidence" in checklist.required_evidence_items


def test_signed_sbom_attestation_verifies_and_rejects_tamper(tmp_path: Path):
    sbom = tmp_path / "sbom-v0.9.json"
    sbom.write_text(json.dumps({"schema_version": "0.9", "components": [{"name": "echo_guardian_core"}]}), encoding="utf-8")
    builder = SignedSBOMAttestationBuilder(
        key_store=PersistedDeviceSigningKeyStore(root=tmp_path / "keys", platform="portable", key_alias="sbom")
    )
    attestation = builder.build(sbom_path=sbom)
    assert SignedSBOMAttestationBuilder.verify(sbom_path=sbom, attestation=attestation)
    sbom.write_text(json.dumps({"schema_version": "0.9", "components": [{"name": "tampered"}]}), encoding="utf-8")
    assert SignedSBOMAttestationBuilder.verify(sbom_path=sbom, attestation=attestation) is False


def test_dependency_license_report_marks_review_required_dependencies():
    report = DependencyLicenseReportBuilder().build_from_requirements(requirements_path=ROOT / "requirements.txt")
    assert report.schema_version == "0.9"
    assert report.dependency_count >= 1
    assert report.unknown_license_count >= 1
    assert report.release_blocking_unknowns is True


def test_external_review_packages_are_ready_with_blocked_claims():
    security = ExternalReviewPackageBuilder().build(root=ROOT, review_type="security")
    privacy = ExternalReviewPackageBuilder().build(root=ROOT, review_type="privacy")
    assert security.ready_for_external_review is True
    assert privacy.ready_for_external_review is True
    assert "HIPAA compliance claims" in security.blocked_claims
    assert "silent enterprise/MDM control" in privacy.blocked_claims


def test_claim_blocking_checklist_blocks_clinical_and_compliance_claims():
    ok = ClaimBlockingChecklistBuilder().build(text="Echo Guardian is a local-first production foundation for internal validation.")
    assert ok.passed is True
    bad = ClaimBlockingChecklistBuilder().build(text="Echo Guardian is HIPAA compliant and a medical device approved product.")
    assert bad.passed is False
    assert "hipaa compliant" in bad.blocked_terms_found
    assert "medical device approved" in bad.blocked_terms_found


def test_v10_foundation_gate_requires_all_evidence():
    gate = V10FoundationReleaseCandidateGateBuilder().build(
        evidence={
            "python_core_tests_passed": True,
            "ios_native_tests_passed": True,
            "android_native_tests_passed": True,
            "signed_sbom_attestation_verified": True,
            "external_security_review_package_ready": True,
            "privacy_review_package_ready": True,
            "claim_blocking_review_passed": True,
            "no_silent_mdm_control": True,
            "no_clinical_or_compliance_claims": True,
        }
    )
    assert gate.approved_for_v1_foundation_readiness is True
    blocked = V10FoundationReleaseCandidateGateBuilder().build(evidence={"python_core_tests_passed": True})
    assert blocked.approved_for_v1_foundation_readiness is False


def test_v09_required_files_and_ci_are_present():
    required = [
        "src/echo_guardian_core/release/external_review.py",
        "docs/native/v0.9-reproducible-native-build-external-review-prep.md",
        "docs/native/v0.9-trusted-gradle-wrapper-generation.md",
        "docs/native/v0.9-android-local-test-evidence-format.md",
        "docs/native/v0.9-ios-physical-device-test-checklist.md",
        "docs/sbom/signed-sbom-attestation-v0.9.md",
        "docs/review/dependency-license-report-v0.9.md",
        "docs/review/external-security-review-package-v0.9.md",
        "docs/review/privacy-review-package-v0.9.md",
        "docs/review/clinical-legal-claim-blocking-review-checklist-v0.9.md",
        "docs/release/v1.0-foundation-release-candidate-gate-v0.9.md",
        "docs/release/production-readiness-report-v0.9.json",
        "docs/sbom/sbom-v0.9.json",
        "tools/check_v09_release_artifacts.py",
        "RELEASE_NOTES_v0.9.md",
    ]
    for rel in required:
        assert (ROOT / rel).exists(), rel
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    for blocked in ["continue-on-error: true", "|| true", "soft-fail", "allow_failure"]:
        assert blocked not in ci
    assert "check_v09_release_artifacts.py" in ci
    assert "./gradlew :echo-guardian-core:testDebugUnitTest" in ci
