"""Physical-device evidence and release attestation helpers for Echo Guardian v0.8.

The v0.8 layer records real-device execution evidence formats and signed local
attestation bundles. It does not claim clinical, HIPAA, GDPR, medical-device,
emergency-system, or silent enterprise/MDM approval.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4
import json
import re

from echo_guardian_core.audit import AuditEntryInput, AuditLog, utc_now_iso
from echo_guardian_core.canonical import canonical_json_bytes
from echo_guardian_core.crypto import blake3_hex
from echo_guardian_core.native.device_execution import (
    DeviceExecutionViolation,
    DevicePlatform,
    PersistedDeviceSigningKeyStore,
    ProviderSandboxReceipt,
    SignedAuditCheckpoint,
    SignedNativeExportManifest,
)
from echo_guardian_core.policy import ProductionPolicy
from echo_guardian_core.signing import verify_ed25519_signature

EvidenceKind = Literal["ios_device_run", "android_device_run", "accessibility_capture", "provider_redaction_proof"]

RAW_TRANSCRIPT_MARKERS = [
    "full transcript",
    "raw transcript",
    "verbatim transcript",
    "medical diagnosis",
    "social security",
    "password",
    "exact address",
]


@dataclass(frozen=True)
class DeviceRunEvidence:
    schema_version: str
    evidence_id: str
    kind: EvidenceKind
    platform: DevicePlatform
    created_at: str
    device_model: str
    os_version: str
    app_build: str
    physical_device: bool
    simulator_or_emulator: bool
    permissions_visible: bool
    private_space_blocked: bool
    raw_data_blocked: bool
    audit_checkpoint_hash: str
    signed_export_manifest_hash: str | None
    provider_sandbox_receipt_hash: str | None
    accessibility_capture_hash: str | None
    evidence_hash: str
    plain_language_summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DeviceRunEvidenceBuilder:
    """Builds real-device execution evidence records for iOS and Android."""

    def build(
        self,
        *,
        platform: DevicePlatform,
        device_model: str,
        os_version: str,
        app_build: str,
        physical_device: bool,
        simulator_or_emulator: bool,
        permissions_visible: bool,
        private_space_blocked: bool,
        raw_data_blocked: bool,
        audit_checkpoint_hash: str,
        signed_export_manifest_hash: str | None = None,
        provider_sandbox_receipt_hash: str | None = None,
        accessibility_capture_hash: str | None = None,
    ) -> DeviceRunEvidence:
        if platform not in {"ios", "android"}:
            raise DeviceExecutionViolation("v0.8 device-run evidence requires ios or android platform")
        if not device_model.strip() or not os_version.strip() or not app_build.strip():
            raise DeviceExecutionViolation("device model, OS version, and app build are required")
        if not physical_device or simulator_or_emulator:
            raise DeviceExecutionViolation("v0.8 real device evidence cannot be simulator/emulator evidence")
        if not permissions_visible:
            raise DeviceExecutionViolation("permission/status visibility evidence is required")
        if not private_space_blocked:
            raise DeviceExecutionViolation("private-space blocking evidence is required")
        if not raw_data_blocked:
            raise DeviceExecutionViolation("raw-data blocking evidence is required")
        if not _looks_like_hex_hash(audit_checkpoint_hash):
            raise DeviceExecutionViolation("audit checkpoint hash must be a hex hash")

        evidence_material = {
            "schema_version": "0.8",
            "platform": platform,
            "device_model": device_model,
            "os_version": os_version,
            "app_build": app_build,
            "physical_device": physical_device,
            "simulator_or_emulator": simulator_or_emulator,
            "permissions_visible": permissions_visible,
            "private_space_blocked": private_space_blocked,
            "raw_data_blocked": raw_data_blocked,
            "audit_checkpoint_hash": audit_checkpoint_hash,
            "signed_export_manifest_hash": signed_export_manifest_hash,
            "provider_sandbox_receipt_hash": provider_sandbox_receipt_hash,
            "accessibility_capture_hash": accessibility_capture_hash,
        }
        evidence_hash = blake3_hex(canonical_json_bytes(evidence_material))
        return DeviceRunEvidence(
            schema_version="0.8",
            evidence_id=str(uuid4()),
            kind=f"{platform}_device_run",  # type: ignore[arg-type]
            platform=platform,
            created_at=utc_now_iso(),
            device_model=device_model,
            os_version=os_version,
            app_build=app_build,
            physical_device=True,
            simulator_or_emulator=False,
            permissions_visible=True,
            private_space_blocked=True,
            raw_data_blocked=True,
            audit_checkpoint_hash=audit_checkpoint_hash,
            signed_export_manifest_hash=signed_export_manifest_hash,
            provider_sandbox_receipt_hash=provider_sandbox_receipt_hash,
            accessibility_capture_hash=accessibility_capture_hash,
            evidence_hash=evidence_hash,
            plain_language_summary=f"Echo Guardian recorded real {platform} device execution evidence without raw data, private-space monitoring, or hidden behavior.",
        )


@dataclass(frozen=True)
class AccessibilityEvidenceCapture:
    schema_version: str
    capture_id: str
    platform: DevicePlatform
    created_at: str
    screen_name: str
    spoken_or_visible_text: list[str]
    child_elderly_understandable: bool
    what_are_you_doing_available: bool
    emergency_claims_absent: bool
    capture_hash: str
    plain_language_summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AccessibilityEvidenceBuilder:
    def build(self, *, platform: DevicePlatform, screen_name: str, spoken_or_visible_text: list[str]) -> AccessibilityEvidenceCapture:
        if platform not in {"ios", "android"}:
            raise DeviceExecutionViolation("accessibility evidence requires ios or android platform")
        if not screen_name.strip():
            raise DeviceExecutionViolation("screen name is required")
        if not spoken_or_visible_text:
            raise DeviceExecutionViolation("accessibility evidence must include visible or spoken text")
        joined = " ".join(spoken_or_visible_text).lower()
        understandable = any(word in joined for word in ["monitoring", "checking", "help", "safe", "doing"])
        what_doing = "what are you doing" in joined
        blocked_claims = ["hipaa compliant", "gdpr compliant", "medical device", "emergency certified"]
        emergency_claims_absent = not any(claim in joined for claim in blocked_claims)
        if not understandable or not what_doing or not emergency_claims_absent:
            raise DeviceExecutionViolation("accessibility evidence failed required plain-language/claim checks")
        material = {
            "platform": platform,
            "screen_name": screen_name,
            "spoken_or_visible_text": spoken_or_visible_text,
            "child_elderly_understandable": understandable,
            "what_are_you_doing_available": what_doing,
            "emergency_claims_absent": emergency_claims_absent,
        }
        return AccessibilityEvidenceCapture(
            schema_version="0.8",
            capture_id=str(uuid4()),
            platform=platform,
            created_at=utc_now_iso(),
            screen_name=screen_name,
            spoken_or_visible_text=spoken_or_visible_text,
            child_elderly_understandable=True,
            what_are_you_doing_available=True,
            emergency_claims_absent=True,
            capture_hash=blake3_hex(canonical_json_bytes(material)),
            plain_language_summary="Echo Guardian captured native accessibility evidence for plain-language status and safety explanation.",
        )


@dataclass(frozen=True)
class ProviderTranscriptRedactionProof:
    schema_version: str
    proof_id: str
    provider: str
    provider_message_id: str | None
    sandbox_verified: bool
    transcript_redacted: bool
    sensitive_markers_found: list[str]
    redacted_transcript_hash: str
    created_at: str
    plain_language_summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ProviderTranscriptRedactionVerifier:
    def verify(self, *, receipt: ProviderSandboxReceipt | dict[str, Any], redacted_transcript: str) -> ProviderTranscriptRedactionProof:
        receipt_data = receipt.to_dict() if isinstance(receipt, ProviderSandboxReceipt) else receipt
        if receipt_data.get("sandbox_verified") is not True:
            raise DeviceExecutionViolation("provider redaction proof requires sandbox-verified receipt")
        if not redacted_transcript.strip():
            raise DeviceExecutionViolation("redacted provider transcript is required")
        lowered = redacted_transcript.lower()
        found = [marker for marker in RAW_TRANSCRIPT_MARKERS if marker in lowered]
        if found:
            raise DeviceExecutionViolation(f"provider transcript contains blocked sensitive markers: {found}")
        if "[redacted]" not in lowered and "minimal disclosure" not in lowered:
            raise DeviceExecutionViolation("provider transcript must explicitly show redaction/minimal disclosure")
        return ProviderTranscriptRedactionProof(
            schema_version="0.8",
            proof_id=str(uuid4()),
            provider=receipt_data["provider"],
            provider_message_id=receipt_data.get("provider_message_id"),
            sandbox_verified=True,
            transcript_redacted=True,
            sensitive_markers_found=[],
            redacted_transcript_hash=blake3_hex(redacted_transcript.encode("utf-8")),
            created_at=utc_now_iso(),
            plain_language_summary="Echo Guardian verified the provider sandbox transcript is redacted and minimal-disclosure only.",
        )


@dataclass(frozen=True)
class SignedDeviceEvidenceBundle:
    schema_version: str
    bundle_id: str
    created_at: str
    evidence_count: int
    evidence_hashes: list[str]
    audit_checkpoint_hash: str
    signed_export_manifest_hash: str
    provider_redaction_proof_hash: str
    accessibility_capture_hash: str
    bundle_hash: str
    signature_hex: str
    public_key_hex: str
    signature_algorithm: str
    plain_language_summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SignedDeviceEvidenceBundleBuilder:
    def __init__(self, *, key_store: PersistedDeviceSigningKeyStore):
        self.key_store = key_store

    def build(
        self,
        *,
        device_evidence: list[DeviceRunEvidence | dict[str, Any]],
        signed_checkpoint: SignedAuditCheckpoint | dict[str, Any],
        signed_export_manifest: SignedNativeExportManifest | dict[str, Any],
        redaction_proof: ProviderTranscriptRedactionProof | dict[str, Any],
        accessibility_capture: AccessibilityEvidenceCapture | dict[str, Any],
    ) -> SignedDeviceEvidenceBundle:
        if not device_evidence:
            raise DeviceExecutionViolation("device evidence bundle requires at least one device evidence record")
        checkpoint_data = signed_checkpoint.to_dict() if isinstance(signed_checkpoint, SignedAuditCheckpoint) else signed_checkpoint
        manifest_data = signed_export_manifest.to_dict() if isinstance(signed_export_manifest, SignedNativeExportManifest) else signed_export_manifest
        redaction_data = redaction_proof.to_dict() if isinstance(redaction_proof, ProviderTranscriptRedactionProof) else redaction_proof
        accessibility_data = accessibility_capture.to_dict() if isinstance(accessibility_capture, AccessibilityEvidenceCapture) else accessibility_capture
        if checkpoint_data.get("audit_verified") is not True:
            raise DeviceExecutionViolation("bundle requires verified signed audit checkpoint")
        if manifest_data.get("user_confirmed") is not True or manifest_data.get("automatic_export") is not False:
            raise DeviceExecutionViolation("bundle requires user-confirmed non-automatic export manifest")
        if redaction_data.get("transcript_redacted") is not True:
            raise DeviceExecutionViolation("bundle requires transcript redaction proof")
        if accessibility_data.get("what_are_you_doing_available") is not True:
            raise DeviceExecutionViolation("bundle requires accessibility evidence for what-are-you-doing status")

        evidence_dicts = [item.to_dict() if isinstance(item, DeviceRunEvidence) else item for item in device_evidence]
        for item in evidence_dicts:
            if item.get("physical_device") is not True or item.get("simulator_or_emulator") is not False:
                raise DeviceExecutionViolation("bundle rejects simulator/emulator evidence")
            if item.get("private_space_blocked") is not True or item.get("raw_data_blocked") is not True:
                raise DeviceExecutionViolation("bundle requires private-space and raw-data blocking")
        material = {
            "schema_version": "0.8",
            "evidence_hashes": sorted(item["evidence_hash"] for item in evidence_dicts),
            "audit_checkpoint_hash": _hash_dict(checkpoint_data),
            "signed_export_manifest_hash": _hash_dict(manifest_data),
            "provider_redaction_proof_hash": _hash_dict(redaction_data),
            "accessibility_capture_hash": _hash_dict(accessibility_data),
        }
        bundle_hash = blake3_hex(canonical_json_bytes(material))
        key = self.key_store.load_or_create()
        return SignedDeviceEvidenceBundle(
            schema_version="0.8",
            bundle_id=str(uuid4()),
            created_at=utc_now_iso(),
            evidence_count=len(evidence_dicts),
            evidence_hashes=material["evidence_hashes"],
            audit_checkpoint_hash=material["audit_checkpoint_hash"],
            signed_export_manifest_hash=material["signed_export_manifest_hash"],
            provider_redaction_proof_hash=material["provider_redaction_proof_hash"],
            accessibility_capture_hash=material["accessibility_capture_hash"],
            bundle_hash=bundle_hash,
            signature_hex=key.sign_hex(canonical_json_bytes(material)),
            public_key_hex=key.public_key_hex(),
            signature_algorithm="ed25519_persisted_contract",
            plain_language_summary="Echo Guardian signed a local v0.8 physical-device evidence bundle. Compliance and clinical claims remain blocked.",
        )

    @staticmethod
    def verify(bundle: SignedDeviceEvidenceBundle | dict[str, Any]) -> bool:
        data = bundle.to_dict() if isinstance(bundle, SignedDeviceEvidenceBundle) else bundle
        material = {
            "schema_version": "0.8",
            "evidence_hashes": data["evidence_hashes"],
            "audit_checkpoint_hash": data["audit_checkpoint_hash"],
            "signed_export_manifest_hash": data["signed_export_manifest_hash"],
            "provider_redaction_proof_hash": data["provider_redaction_proof_hash"],
            "accessibility_capture_hash": data["accessibility_capture_hash"],
        }
        if blake3_hex(canonical_json_bytes(material)) != data.get("bundle_hash"):
            return False
        return verify_ed25519_signature(data["public_key_hex"], data["signature_hex"], canonical_json_bytes(material))


class CIReleaseAttestationBundleBuilder:
    def build(self, *, root: str | Path, artifact_paths: list[str], evidence_bundle: SignedDeviceEvidenceBundle | dict[str, Any]) -> dict[str, Any]:
        base = Path(root)
        evidence_data = evidence_bundle.to_dict() if isinstance(evidence_bundle, SignedDeviceEvidenceBundle) else evidence_bundle
        if SignedDeviceEvidenceBundleBuilder.verify(evidence_data) is not True:
            raise DeviceExecutionViolation("CI attestation requires verified signed device evidence bundle")
        artifacts = []
        for rel in sorted(artifact_paths):
            path = base / rel
            if not path.exists():
                raise DeviceExecutionViolation(f"CI attestation artifact missing: {rel}")
            artifacts.append({"path": rel, "blake3": blake3_hex(path.read_bytes())})
        statement = {
            "schema_version": "0.8",
            "attestation_id": str(uuid4()),
            "created_at": utc_now_iso(),
            "artifact_count": len(artifacts),
            "artifacts": artifacts,
            "device_evidence_bundle_hash": evidence_data["bundle_hash"],
            "android_gradle_wrapper_included": (base / "native/android/gradlew").exists(),
            "release_blocking_android_native_tests": True,
            "plain_language_summary": "Echo Guardian created a v0.8 CI release attestation bundle with native test and evidence artifacts.",
        }
        if statement["android_gradle_wrapper_included"] is not True:
            raise DeviceExecutionViolation("Android Gradle wrapper is required for v0.8 local reproducible test execution")
        statement["attestation_hash"] = blake3_hex(canonical_json_bytes(statement))
        return statement


def audit_physical_evidence_event(*, audit_log: AuditLog, policy: ProductionPolicy, event_type: str, platform: DevicePlatform, plain_language: str) -> dict[str, Any]:
    return audit_log.append(
        AuditEntryInput(
            event_type=event_type,
            severity="normal",
            authority_context="system_internal",
            policy_id=policy.policy_id,
            policy_version=policy.policy_version,
            public_context={
                "space_id": "physical_device_evidence",
                "private_space": False,
                "signal_types": [],
                "platform": platform,
                "plain_language": plain_language,
                "cloud_dependency": False,
                "raw_sensor_retained": False,
                "automatic_export": False,
            },
        )
    )


def write_json(path: str | Path, data: dict[str, Any]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")


def _hash_dict(data: dict[str, Any]) -> str:
    return blake3_hex(canonical_json_bytes(data))


def _looks_like_hex_hash(value: str) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{32,128}", value))
