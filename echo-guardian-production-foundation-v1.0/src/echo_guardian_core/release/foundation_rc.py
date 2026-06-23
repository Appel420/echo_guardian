"""v1.0 foundation release-candidate evidence and readiness gate.

This layer records the evidence required for a foundation release candidate. It
is intentionally strict: real device evidence, trusted Gradle wrapper evidence,
SBOM attestation, security/privacy review packages, and claim-blocking review are
release-blocking. The module does not certify HIPAA, GDPR, medical-device,
emergency-system, clinical deployment, or silent MDM approval.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4
import json

from echo_guardian_core.audit import utc_now_iso
from echo_guardian_core.crypto import blake3_hex
from echo_guardian_core.native.device_execution import DeviceExecutionViolation, PersistedDeviceSigningKeyStore
from echo_guardian_core.release.external_review import BLOCKED_CLAIMS, BLOCKED_CLAIM_TERMS, ClaimBlockingChecklistBuilder
from echo_guardian_core.signing import verify_ed25519_signature

Platform = Literal["ios", "android"]
EvidenceState = Literal["collected", "missing", "rejected", "not_applicable"]


@dataclass(frozen=True)
class TrustedGradleWrapperEvidence:
    schema_version: str
    evidence_id: str
    created_at: str
    gradle_version: str
    distribution_url: str
    gradle_wrapper_properties_path: str
    gradle_wrapper_jar_present: bool
    gradle_wrapper_jar_sha256: str | None
    generated_by_command: str
    verified_by_command: str
    release_blocking: bool
    evidence_state: EvidenceState
    plain_language_summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class TrustedGradleWrapperEvidenceBuilder:
    REQUIRED_COMMAND = "gradle wrapper --gradle-version 8.7 --distribution-type bin"
    VERIFY_COMMAND = "./gradlew --version && ./gradlew :echo-guardian-core:testDebugUnitTest"

    def build(self, *, android_root: str | Path, gradle_version: str = "8.7") -> TrustedGradleWrapperEvidence:
        root = Path(android_root)
        properties = root / "gradle" / "wrapper" / "gradle-wrapper.properties"
        jar = root / "gradle" / "wrapper" / "gradle-wrapper.jar"
        distribution_url = f"https://services.gradle.org/distributions/gradle-{gradle_version}-bin.zip"
        if not properties.exists():
            raise DeviceExecutionViolation("Gradle wrapper properties are required for trusted wrapper evidence")
        properties_text = properties.read_text(encoding="utf-8")
        if distribution_url not in properties_text and distribution_url.replace("://", "\\://") not in properties_text:
            raise DeviceExecutionViolation("Gradle wrapper properties must pin the expected Gradle distribution URL")
        jar_hash = blake3_hex(jar.read_bytes()) if jar.exists() else None
        state: EvidenceState = "collected" if jar.exists() else "missing"
        summary = (
            "Trusted Gradle wrapper evidence is collected and ready for Android local reproducibility."
            if state == "collected"
            else "Trusted Gradle wrapper evidence is incomplete because gradle-wrapper.jar is not present. Do not fabricate this file; generate it from the pinned Gradle version."
        )
        return TrustedGradleWrapperEvidence(
            schema_version="1.0-rc",
            evidence_id=str(uuid4()),
            created_at=utc_now_iso(),
            gradle_version=gradle_version,
            distribution_url=distribution_url,
            gradle_wrapper_properties_path=str(properties),
            gradle_wrapper_jar_present=jar.exists(),
            gradle_wrapper_jar_sha256=jar_hash,
            generated_by_command=self.REQUIRED_COMMAND,
            verified_by_command=self.VERIFY_COMMAND,
            release_blocking=True,
            evidence_state=state,
            plain_language_summary=summary,
        )


@dataclass(frozen=True)
class PhysicalDeviceExecutionEvidence:
    schema_version: str
    evidence_id: str
    created_at: str
    platform: Platform
    physical_device_required: bool
    simulator_or_emulator_allowed: bool
    device_model: str | None
    os_version: str | None
    app_build_id: str | None
    tests_passed: bool
    private_space_blocking_verified: bool
    raw_data_blocking_verified: bool
    audit_checkpoint_verified: bool
    accessibility_evidence_captured: bool
    execution_log_hash: str | None
    evidence_state: EvidenceState
    release_blocking: bool
    plain_language_summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PhysicalDeviceExecutionEvidenceBuilder:
    def build(
        self,
        *,
        platform: Platform,
        device_model: str | None,
        os_version: str | None,
        app_build_id: str | None,
        tests_passed: bool,
        private_space_blocking_verified: bool,
        raw_data_blocking_verified: bool,
        audit_checkpoint_verified: bool,
        accessibility_evidence_captured: bool,
        execution_log: str | None,
        simulator_or_emulator_used: bool = False,
    ) -> PhysicalDeviceExecutionEvidence:
        if simulator_or_emulator_used:
            raise DeviceExecutionViolation("v1.0 foundation device evidence cannot use simulator or emulator execution")
        required_values_present = all([device_model, os_version, app_build_id, execution_log])
        all_checks = all([
            required_values_present,
            tests_passed,
            private_space_blocking_verified,
            raw_data_blocking_verified,
            audit_checkpoint_verified,
            accessibility_evidence_captured,
        ])
        state: EvidenceState = "collected" if all_checks else "missing"
        return PhysicalDeviceExecutionEvidence(
            schema_version="1.0-rc",
            evidence_id=str(uuid4()),
            created_at=utc_now_iso(),
            platform=platform,
            physical_device_required=True,
            simulator_or_emulator_allowed=False,
            device_model=device_model,
            os_version=os_version,
            app_build_id=app_build_id,
            tests_passed=tests_passed,
            private_space_blocking_verified=private_space_blocking_verified,
            raw_data_blocking_verified=raw_data_blocking_verified,
            audit_checkpoint_verified=audit_checkpoint_verified,
            accessibility_evidence_captured=accessibility_evidence_captured,
            execution_log_hash=blake3_hex(execution_log.encode("utf-8")) if execution_log else None,
            evidence_state=state,
            release_blocking=True,
            plain_language_summary=(
                f"{platform} physical-device evidence is collected and passes the v1.0 foundation gate."
                if state == "collected"
                else f"{platform} physical-device evidence is incomplete and blocks v1.0 foundation readiness."
            ),
        )


@dataclass(frozen=True)
class SignedSBOMVerificationResult:
    schema_version: str
    verification_id: str
    created_at: str
    sbom_path: str
    attestation_path: str
    sbom_hash: str | None
    signature_valid: bool
    evidence_state: EvidenceState
    release_blocking: bool
    plain_language_summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SignedSBOMVerificationBuilder:
    def verify(self, *, sbom_path: str | Path, attestation_path: str | Path) -> SignedSBOMVerificationResult:
        sbom = Path(sbom_path)
        attestation = Path(attestation_path)
        if not sbom.exists() or not attestation.exists():
            return SignedSBOMVerificationResult(
                schema_version="1.0-rc",
                verification_id=str(uuid4()),
                created_at=utc_now_iso(),
                sbom_path=str(sbom),
                attestation_path=str(attestation),
                sbom_hash=None,
                signature_valid=False,
                evidence_state="missing",
                release_blocking=True,
                plain_language_summary="Signed SBOM attestation is missing and blocks v1.0 foundation readiness.",
            )
        data = json.loads(attestation.read_text(encoding="utf-8"))
        material = sbom.read_bytes()
        sbom_hash = blake3_hex(material)
        signature_valid = sbom_hash == data.get("sbom_hash") and verify_ed25519_signature(
            data.get("public_key_hex", ""), data.get("signature_hex", ""), material
        )
        return SignedSBOMVerificationResult(
            schema_version="1.0-rc",
            verification_id=str(uuid4()),
            created_at=utc_now_iso(),
            sbom_path=str(sbom),
            attestation_path=str(attestation),
            sbom_hash=sbom_hash,
            signature_valid=signature_valid,
            evidence_state="collected" if signature_valid else "rejected",
            release_blocking=True,
            plain_language_summary="Signed SBOM attestation verified." if signature_valid else "Signed SBOM attestation failed verification.",
        )


@dataclass(frozen=True)
class ReviewCompletionRecord:
    schema_version: str
    review_id: str
    created_at: str
    review_type: Literal["external_security", "privacy", "clinical_legal_claim_blocking"]
    package_path: str
    completed_by: str | None
    completed_at: str | None
    passed: bool
    findings_count: int
    unresolved_blockers: list[str]
    blocked_claims: list[str]
    release_blocking: bool
    plain_language_summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ReviewCompletionRecordBuilder:
    def build(
        self,
        *,
        review_type: Literal["external_security", "privacy", "clinical_legal_claim_blocking"],
        package_path: str | Path,
        completed_by: str | None,
        completed_at: str | None,
        passed: bool,
        findings_count: int,
        unresolved_blockers: list[str],
    ) -> ReviewCompletionRecord:
        if findings_count < 0:
            raise DeviceExecutionViolation("findings_count cannot be negative")
        final_passed = passed and completed_by is not None and completed_at is not None and not unresolved_blockers
        return ReviewCompletionRecord(
            schema_version="1.0-rc",
            review_id=str(uuid4()),
            created_at=utc_now_iso(),
            review_type=review_type,
            package_path=str(package_path),
            completed_by=completed_by,
            completed_at=completed_at,
            passed=final_passed,
            findings_count=findings_count,
            unresolved_blockers=unresolved_blockers,
            blocked_claims=BLOCKED_CLAIMS,
            release_blocking=True,
            plain_language_summary=(
                f"{review_type} review is complete and passed."
                if final_passed else f"{review_type} review is incomplete or has unresolved blockers."
            ),
        )


@dataclass(frozen=True)
class V10FoundationReadinessGateResult:
    schema_version: str
    gate_id: str
    created_at: str
    decision: Literal["approved_for_foundation_release", "blocked"]
    criteria: list[dict[str, Any]]
    blocked_claims: list[str]
    release_notes_hash: str | None
    plain_language_summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class V10FoundationReadinessGateBuilder:
    REQUIRED = [
        "trusted_gradle_wrapper_evidence_collected",
        "ios_physical_device_evidence_collected",
        "android_physical_device_evidence_collected",
        "signed_sbom_attestation_verified",
        "external_security_review_completed",
        "privacy_review_completed",
        "clinical_legal_claim_blocking_review_passed",
        "no_hipaa_or_gdpr_claims",
        "no_medical_device_claims",
        "no_emergency_system_claims",
        "no_clinical_deployment_claims",
        "no_silent_enterprise_mdm_control",
    ]

    def build(self, *, evidence: dict[str, bool], release_notes_text: str | None = None) -> V10FoundationReadinessGateResult:
        criteria = [{"criterion": item, "required": True, "passed": bool(evidence.get(item, False))} for item in self.REQUIRED]
        approved = all(item["passed"] for item in criteria)
        return V10FoundationReadinessGateResult(
            schema_version="1.0-rc",
            gate_id=str(uuid4()),
            created_at=utc_now_iso(),
            decision="approved_for_foundation_release" if approved else "blocked",
            criteria=criteria,
            blocked_claims=BLOCKED_CLAIMS,
            release_notes_hash=blake3_hex(release_notes_text.encode("utf-8")) if release_notes_text else None,
            plain_language_summary=(
                "Echo Guardian v1.0 foundation release candidate is approved for foundation release. Blocked clinical, compliance, medical-device, emergency-system, and silent MDM claims remain blocked."
                if approved else
                "Echo Guardian v1.0 foundation readiness is blocked until all release-blocking evidence and reviews are complete. Blocked clinical, compliance, medical-device, emergency-system, and silent MDM claims remain blocked."
            ),
        )


class ClaimBlockingReleaseTextReview:
    def review_files(self, *, files: list[str | Path]) -> dict[str, Any]:
        results: list[dict[str, Any]] = []
        builder = ClaimBlockingChecklistBuilder()
        all_passed = True
        for file in files:
            path = Path(file)
            text = path.read_text(encoding="utf-8")
            result = builder.build(text=text)
            results.append({"path": str(path), **result.to_dict()})
            all_passed = all_passed and result.passed
        return {
            "schema_version": "1.0-rc",
            "review_id": str(uuid4()),
            "created_at": utc_now_iso(),
            "files_checked": len(results),
            "blocked_claim_terms": BLOCKED_CLAIM_TERMS,
            "passed": all_passed,
            "results": results,
        }


def write_json(path: str | Path, data: dict[str, Any]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
