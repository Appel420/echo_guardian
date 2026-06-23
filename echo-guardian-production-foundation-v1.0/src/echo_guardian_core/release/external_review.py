"""v0.9 reproducible native build and external review preparation.

This module creates deterministic, local review artifacts for reproducible native
build evidence, SBOM attestation, dependency-license review, security/privacy
review packs, and claim-blocking release gates. It does not create legal,
clinical, HIPAA, GDPR, medical-device, emergency-system, or silent MDM approval.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4
import json

from echo_guardian_core.audit import utc_now_iso
from echo_guardian_core.canonical import canonical_json_bytes
from echo_guardian_core.crypto import blake3_hex
from echo_guardian_core.native.device_execution import DeviceExecutionViolation, PersistedDeviceSigningKeyStore
from echo_guardian_core.signing import verify_ed25519_signature

Platform = Literal["ios", "android"]

BLOCKED_CLAIMS = [
    "HIPAA compliance claims",
    "GDPR/global-compliance claims",
    "medical-device claims",
    "emergency-system certification claims",
    "clinical deployment",
    "silent enterprise/MDM control",
]

BLOCKED_CLAIM_TERMS = [
    "hipaa compliant",
    "gdpr compliant",
    "medical device approved",
    "emergency-system certified",
    "clinical deployment approved",
    "silent mdm",
]


@dataclass(frozen=True)
class TrustedGradleWrapperInstructions:
    schema_version: str
    instruction_id: str
    created_at: str
    gradle_version: str
    distribution_url: str
    wrapper_jar_policy: str
    required_commands: list[str]
    verification_steps: list[str]
    release_blocking: bool
    plain_language_summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class TrustedGradleWrapperInstructionBuilder:
    def build(self, *, gradle_version: str = "8.7") -> TrustedGradleWrapperInstructions:
        if not gradle_version.strip():
            raise DeviceExecutionViolation("Gradle version is required for trusted wrapper instructions")
        distribution_url = f"https://services.gradle.org/distributions/gradle-{gradle_version}-bin.zip"
        return TrustedGradleWrapperInstructions(
            schema_version="0.9",
            instruction_id=str(uuid4()),
            created_at=utc_now_iso(),
            gradle_version=gradle_version,
            distribution_url=distribution_url,
            wrapper_jar_policy="Do not hand-edit or invent gradle-wrapper.jar. Generate it from a trusted local Gradle installation, pin the distribution URL, record checksums, and commit the generated wrapper only after review.",
            required_commands=[
                f"gradle wrapper --gradle-version {gradle_version} --distribution-type bin",
                "./gradlew --version",
                "./gradlew :echo-guardian-core:testDebugUnitTest",
            ],
            verification_steps=[
                "Verify gradle/wrapper/gradle-wrapper.properties uses the pinned distribution URL.",
                "Record SHA-256 for gradle-wrapper.jar after generation.",
                "Run Android native tests locally through ./gradlew without soft-fail behavior.",
                "Attach Android local test execution evidence to release review.",
            ],
            release_blocking=True,
            plain_language_summary="Echo Guardian v0.9 requires a trusted Gradle wrapper generated from a pinned Gradle version before local Android reproducibility can be accepted.",
        )


@dataclass(frozen=True)
class AndroidLocalTestEvidence:
    schema_version: str
    evidence_id: str
    created_at: str
    command: str
    gradle_wrapper_present: bool
    gradle_wrapper_jar_sha256: str | None
    tests_passed: bool
    soft_fail_used: bool
    log_hash: str
    release_blocking: bool
    plain_language_summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AndroidLocalTestEvidenceBuilder:
    def build(
        self,
        *,
        command: str,
        gradle_wrapper_present: bool,
        gradle_wrapper_jar_sha256: str | None,
        tests_passed: bool,
        soft_fail_used: bool,
        execution_log: str,
    ) -> AndroidLocalTestEvidence:
        if command.strip() != "./gradlew :echo-guardian-core:testDebugUnitTest":
            raise DeviceExecutionViolation("Android local test evidence must use the release-blocking Gradle wrapper command")
        if not gradle_wrapper_present:
            raise DeviceExecutionViolation("Android local test evidence requires the Gradle wrapper")
        if soft_fail_used:
            raise DeviceExecutionViolation("Android local test evidence cannot use soft-fail behavior")
        if not tests_passed:
            raise DeviceExecutionViolation("Android local native tests must pass for release evidence")
        if not execution_log.strip():
            raise DeviceExecutionViolation("Android local test evidence requires an execution log")
        return AndroidLocalTestEvidence(
            schema_version="0.9",
            evidence_id=str(uuid4()),
            created_at=utc_now_iso(),
            command=command,
            gradle_wrapper_present=True,
            gradle_wrapper_jar_sha256=gradle_wrapper_jar_sha256,
            tests_passed=True,
            soft_fail_used=False,
            log_hash=blake3_hex(execution_log.encode("utf-8")),
            release_blocking=True,
            plain_language_summary="Android native tests passed locally through the release-blocking Gradle wrapper command.",
        )


@dataclass(frozen=True)
class IOSPhysicalDeviceChecklistRefinement:
    schema_version: str
    checklist_id: str
    created_at: str
    required_evidence_items: list[str]
    simulator_evidence_allowed: bool
    release_blocking: bool
    plain_language_summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class IOSPhysicalDeviceChecklistRefinementBuilder:
    def build(self) -> IOSPhysicalDeviceChecklistRefinement:
        return IOSPhysicalDeviceChecklistRefinement(
            schema_version="0.9",
            checklist_id=str(uuid4()),
            created_at=utc_now_iso(),
            required_evidence_items=[
                "physical device model and OS version",
                "app build identifier",
                "permission/status screen capture or transcript",
                "private-space blocking evidence",
                "raw-data blocking evidence",
                "signed audit checkpoint reference",
                "accessibility status and confirmation evidence",
            ],
            simulator_evidence_allowed=False,
            release_blocking=True,
            plain_language_summary="iOS v0.9 release evidence must come from a real device, not a simulator.",
        )


@dataclass(frozen=True)
class SignedSBOMAttestation:
    schema_version: str
    attestation_id: str
    created_at: str
    sbom_path: str
    sbom_hash: str
    signature_hex: str
    public_key_hex: str
    signature_algorithm: str
    release_blocking: bool
    plain_language_summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SignedSBOMAttestationBuilder:
    def __init__(self, *, key_store: PersistedDeviceSigningKeyStore):
        self.key_store = key_store

    def build(self, *, sbom_path: str | Path) -> SignedSBOMAttestation:
        path = Path(sbom_path)
        if not path.exists():
            raise DeviceExecutionViolation(f"SBOM file missing: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("schema_version") not in {"0.8", "0.9"} and "components" not in data:
            raise DeviceExecutionViolation("SBOM attestation requires an SBOM-like JSON document")
        material = path.read_bytes()
        sbom_hash = blake3_hex(material)
        key = self.key_store.load_or_create()
        return SignedSBOMAttestation(
            schema_version="0.9",
            attestation_id=str(uuid4()),
            created_at=utc_now_iso(),
            sbom_path=str(path),
            sbom_hash=sbom_hash,
            signature_hex=key.sign_hex(material),
            public_key_hex=key.public_key_hex(),
            signature_algorithm="ed25519_persisted_contract",
            release_blocking=True,
            plain_language_summary="Echo Guardian signed the SBOM for v0.9 release review. This is artifact integrity evidence, not legal compliance approval.",
        )

    @staticmethod
    def verify(*, sbom_path: str | Path, attestation: SignedSBOMAttestation | dict[str, Any]) -> bool:
        data = attestation.to_dict() if isinstance(attestation, SignedSBOMAttestation) else attestation
        material = Path(sbom_path).read_bytes()
        if blake3_hex(material) != data.get("sbom_hash"):
            return False
        return verify_ed25519_signature(data["public_key_hex"], data["signature_hex"], material)


@dataclass(frozen=True)
class DependencyLicenseReport:
    schema_version: str
    report_id: str
    created_at: str
    dependency_count: int
    dependencies: list[dict[str, Any]]
    unknown_license_count: int
    release_blocking_unknowns: bool
    plain_language_summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DependencyLicenseReportBuilder:
    def build_from_requirements(self, *, requirements_path: str | Path) -> DependencyLicenseReport:
        path = Path(requirements_path)
        if not path.exists():
            raise DeviceExecutionViolation("requirements file is required for dependency license report")
        dependencies: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            clean = line.strip()
            if not clean or clean.startswith("#"):
                continue
            name = clean.split("==")[0].split(">=")[0].split("~=")[0].strip()
            dependencies.append({"name": name, "specifier": clean, "license_status": "review_required", "source": "requirements.txt"})
        unknowns = sum(1 for dep in dependencies if dep["license_status"] == "review_required")
        return DependencyLicenseReport(
            schema_version="0.9",
            report_id=str(uuid4()),
            created_at=utc_now_iso(),
            dependency_count=len(dependencies),
            dependencies=dependencies,
            unknown_license_count=unknowns,
            release_blocking_unknowns=unknowns > 0,
            plain_language_summary="Echo Guardian generated a dependency license report. Review-required entries must be cleared before v1.0 foundation readiness.",
        )


@dataclass(frozen=True)
class ExternalReviewPackage:
    schema_version: str
    package_id: str
    created_at: str
    review_type: Literal["security", "privacy"]
    required_materials: list[str]
    blocked_claims: list[str]
    ready_for_external_review: bool
    plain_language_summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ExternalReviewPackageBuilder:
    SECURITY_MATERIALS = [
        "SECURITY.md",
        "docs/security/cryptographic-design-note.md",
        "docs/security/dependency-scanning-plan-v0.3.md",
        "docs/release/production-readiness-report-v0.9.json",
        "tests/security/test_v08_physical_device_evidence_attestation.py",
    ]
    PRIVACY_MATERIALS = [
        "PRIVACY.md",
        "docs/release/open-risks-v0.2.md",
        "docs/release/known-limitations-v0.2.md",
        "docs/release/production-readiness-report-v0.9.json",
        "docs/review/clinical-legal-claim-blocking-review-checklist-v0.9.md",
    ]

    def build(self, *, root: str | Path, review_type: Literal["security", "privacy"]) -> ExternalReviewPackage:
        base = Path(root)
        materials = self.SECURITY_MATERIALS if review_type == "security" else self.PRIVACY_MATERIALS
        missing = [rel for rel in materials if not (base / rel).exists()]
        if missing:
            raise DeviceExecutionViolation(f"external {review_type} review package is missing materials: {missing}")
        return ExternalReviewPackage(
            schema_version="0.9",
            package_id=str(uuid4()),
            created_at=utc_now_iso(),
            review_type=review_type,
            required_materials=materials,
            blocked_claims=BLOCKED_CLAIMS,
            ready_for_external_review=True,
            plain_language_summary=f"Echo Guardian v0.9 {review_type} review package is ready for external review, with compliance and clinical claims still blocked.",
        )


@dataclass(frozen=True)
class ClaimBlockingChecklist:
    schema_version: str
    checklist_id: str
    created_at: str
    blocked_claims: list[str]
    checked_text_hash: str
    blocked_terms_found: list[str]
    passed: bool
    plain_language_summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ClaimBlockingChecklistBuilder:
    def build(self, *, text: str) -> ClaimBlockingChecklist:
        lowered = text.lower()
        found = [term for term in BLOCKED_CLAIM_TERMS if term in lowered]
        return ClaimBlockingChecklist(
            schema_version="0.9",
            checklist_id=str(uuid4()),
            created_at=utc_now_iso(),
            blocked_claims=BLOCKED_CLAIMS,
            checked_text_hash=blake3_hex(text.encode("utf-8")),
            blocked_terms_found=found,
            passed=len(found) == 0,
            plain_language_summary="Echo Guardian claim-blocking review passed." if not found else "Echo Guardian claim-blocking review failed because blocked claims were found.",
        )


@dataclass(frozen=True)
class V10FoundationReleaseCandidateGate:
    schema_version: str
    gate_id: str
    created_at: str
    criteria: list[dict[str, Any]]
    approved_for_v1_foundation_readiness: bool
    blocked_claims: list[str]
    plain_language_summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class V10FoundationReleaseCandidateGateBuilder:
    REQUIRED = [
        "python_core_tests_passed",
        "ios_native_tests_passed",
        "android_native_tests_passed",
        "signed_sbom_attestation_verified",
        "external_security_review_package_ready",
        "privacy_review_package_ready",
        "claim_blocking_review_passed",
        "no_silent_mdm_control",
        "no_clinical_or_compliance_claims",
    ]

    def build(self, *, evidence: dict[str, bool]) -> V10FoundationReleaseCandidateGate:
        criteria = [{"criterion": item, "required": True, "passed": bool(evidence.get(item, False))} for item in self.REQUIRED]
        approved = all(item["passed"] for item in criteria)
        return V10FoundationReleaseCandidateGate(
            schema_version="0.9",
            gate_id=str(uuid4()),
            created_at=utc_now_iso(),
            criteria=criteria,
            approved_for_v1_foundation_readiness=approved,
            blocked_claims=BLOCKED_CLAIMS,
            plain_language_summary="Echo Guardian v1.0 foundation readiness gate passed." if approved else "Echo Guardian v1.0 foundation readiness gate is blocked until all required evidence passes.",
        )


def write_json(path: str | Path, data: dict[str, Any]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
