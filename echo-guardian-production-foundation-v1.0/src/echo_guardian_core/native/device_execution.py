"""Device execution and signed native export helpers for Echo Guardian v0.7.

The v0.7 layer remains a production-foundation implementation. It creates
portable, deterministic proofs for CI and local validation while preserving the
native contracts expected from iOS Keychain and Android Keystore builds.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4
import json
import os

from echo_guardian_core.audit import AuditEntryInput, AuditLog, utc_now_iso
from echo_guardian_core.canonical import canonical_json_bytes
from echo_guardian_core.crypto import blake3_hex
from echo_guardian_core.delivery.provider_adapter import DeliveryResult, MinimalDisclosureAlert
from echo_guardian_core.policy import ProductionPolicy, PolicyViolation
from echo_guardian_core.signing import Ed25519KeyPair, verify_ed25519_signature

DevicePlatform = Literal["ios", "android", "portable"]
ReceiptStatus = Literal["accepted", "rejected"]


class DeviceExecutionViolation(PolicyViolation):
    """Raised when a v0.7 device-execution guardrail is violated."""


@dataclass(frozen=True)
class DeviceExecutionChecklistItem:
    item_id: str
    title: str
    required: bool
    passed: bool
    plain_language: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DeviceExecutionChecklist:
    schema_version: str
    checklist_id: str
    created_at: str
    platform: DevicePlatform
    items: list[DeviceExecutionChecklistItem]
    approved_for_device_execution: bool
    plain_language_summary: str

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["items"] = [item.to_dict() for item in self.items]
        return data


class PhysicalDeviceChecklistBuilder:
    """Builds a release-blocking physical-device execution checklist."""

    REQUIRED_IDS = {
        "physical_device_named",
        "permissions_visible",
        "private_space_blocked",
        "raw_data_blocked",
        "audit_append_enabled",
        "key_persisted",
        "export_user_confirmed",
        "provider_sandbox_only",
        "accessibility_flow_tested",
    }

    def build(self, *, platform: DevicePlatform, evidence: dict[str, bool]) -> DeviceExecutionChecklist:
        items = [
            self._item("physical_device_named", "Physical device target selected", evidence, "A real device target is named for execution."),
            self._item("permissions_visible", "Permission/status screen visible", evidence, "The user can see native sensor permission status."),
            self._item("private_space_blocked", "Private-space monitoring blocked", evidence, "Bathroom and bedroom monitoring remain blocked by default."),
            self._item("raw_data_blocked", "Raw sensor data blocked", evidence, "Raw sensor samples are not retained or exported."),
            self._item("audit_append_enabled", "Native audit append enabled", evidence, "Native state transitions can be written to the core audit chain."),
            self._item("key_persisted", "Device signing key persisted", evidence, "A device-bound signing key can prove possession across runs."),
            self._item("export_user_confirmed", "Export requires user confirmation", evidence, "No native export happens automatically."),
            self._item("provider_sandbox_only", "Provider sandbox only", evidence, "Provider delivery receipts are sandbox-verified before live delivery."),
            self._item("accessibility_flow_tested", "Accessibility flow tested", evidence, "The native status and confirmation screens are testable."),
        ]
        approved = all(item.passed for item in items if item.required)
        summary = (
            f"Echo Guardian v0.7 {'can' if approved else 'cannot'} run the physical-device execution checklist for {platform}. "
            "HIPAA, GDPR, medical-device, emergency-system, clinical, and silent MDM claims remain blocked."
        )
        return DeviceExecutionChecklist(
            schema_version="0.7",
            checklist_id=str(uuid4()),
            created_at=utc_now_iso(),
            platform=platform,
            items=items,
            approved_for_device_execution=approved,
            plain_language_summary=summary,
        )

    def _item(self, item_id: str, title: str, evidence: dict[str, bool], message: str) -> DeviceExecutionChecklistItem:
        return DeviceExecutionChecklistItem(
            item_id=item_id,
            title=title,
            required=True,
            passed=bool(evidence.get(item_id, False)),
            plain_language=message if evidence.get(item_id, False) else f"Needs work: {message}",
        )


@dataclass(frozen=True)
class PersistedSigningProof:
    schema_version: str
    proof_id: str
    platform: DevicePlatform
    key_alias: str
    algorithm: str
    challenge_b64: str
    signature_hex: str
    public_key_hex: str
    key_persisted: bool
    native_protection_label: str
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PersistedDeviceSigningKeyStore:
    """Portable persisted key proof used by CI and native contract tests.

    Native apps must map the same proof contract to iOS Keychain or Android
    Keystore. This portable implementation persists an Ed25519 seed in a local
    file for repeatable tests and labels the native protection boundary instead
    of overclaiming hardware protection.
    """

    def __init__(self, *, root: str | Path, platform: DevicePlatform, key_alias: str):
        self.root = Path(root)
        self.platform = platform
        self.key_alias = key_alias
        self.root.mkdir(parents=True, exist_ok=True)
        self.key_path = self.root / f"{platform}_{key_alias}.seed"

    @property
    def native_protection_label(self) -> str:
        if self.platform == "ios":
            return "ios_keychain_contract"
        if self.platform == "android":
            return "android_keystore_contract"
        return "portable_software_protected_ci"

    def load_or_create(self) -> Ed25519KeyPair:
        if self.key_path.exists():
            return Ed25519KeyPair.from_private_bytes(bytes.fromhex(self.key_path.read_text(encoding="utf-8").strip()))
        key = Ed25519KeyPair.generate()
        self.key_path.write_text(key.private_bytes_raw().hex(), encoding="utf-8")
        try:
            os.chmod(self.key_path, 0o600)
        except PermissionError:
            pass
        return key

    def prove_possession(self, *, challenge: bytes) -> PersistedSigningProof:
        if not challenge:
            raise DeviceExecutionViolation("signing challenge must not be empty")
        key = self.load_or_create()
        return PersistedSigningProof(
            schema_version="0.7",
            proof_id=str(uuid4()),
            platform=self.platform,
            key_alias=self.key_alias,
            algorithm="ed25519_persisted_contract",
            challenge_b64=__import__("base64").b64encode(challenge).decode("ascii"),
            signature_hex=key.sign_hex(challenge),
            public_key_hex=key.public_key_hex(),
            key_persisted=True,
            native_protection_label=self.native_protection_label,
            created_at=utc_now_iso(),
        )

    @staticmethod
    def verify_proof(proof: PersistedSigningProof | dict[str, Any]) -> bool:
        data = proof.to_dict() if isinstance(proof, PersistedSigningProof) else proof
        challenge = __import__("base64").b64decode(data["challenge_b64"])
        return verify_ed25519_signature(data["public_key_hex"], data["signature_hex"], challenge)


@dataclass(frozen=True)
class SignedNativeExportManifest:
    schema_version: str
    signed_manifest_id: str
    platform: DevicePlatform
    export_manifest_hash: str
    export_manifest_signature_hex: str
    public_key_hex: str
    signature_algorithm: str
    user_confirmed: bool
    automatic_export: bool
    created_at: str
    plain_language_summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SignedNativeExportBuilder:
    """Signs a native export manifest without allowing automatic export."""

    def __init__(self, *, key_store: PersistedDeviceSigningKeyStore):
        self.key_store = key_store

    def sign_manifest(self, *, manifest: dict[str, Any]) -> SignedNativeExportManifest:
        if manifest.get("user_confirmed") is not True:
            raise DeviceExecutionViolation("signed native export requires explicit user confirmation")
        if manifest.get("automatic_export") is not False:
            raise DeviceExecutionViolation("signed native export blocks automatic export")
        if manifest.get("device_signature") not in {None, ""}:
            raise DeviceExecutionViolation("manifest already contains device signature material")
        material = canonical_json_bytes(manifest)
        key = self.key_store.load_or_create()
        digest = blake3_hex(material)
        return SignedNativeExportManifest(
            schema_version="0.7",
            signed_manifest_id=str(uuid4()),
            platform=self.key_store.platform,
            export_manifest_hash=digest,
            export_manifest_signature_hex=key.sign_hex(material),
            public_key_hex=key.public_key_hex(),
            signature_algorithm="ed25519_persisted_contract",
            user_confirmed=True,
            automatic_export=False,
            created_at=utc_now_iso(),
            plain_language_summary="Echo Guardian signed a user-confirmed local native export manifest.",
        )

    @staticmethod
    def verify_signed_manifest(*, manifest: dict[str, Any], signed: SignedNativeExportManifest | dict[str, Any]) -> bool:
        data = signed.to_dict() if isinstance(signed, SignedNativeExportManifest) else signed
        material = canonical_json_bytes(manifest)
        if data.get("export_manifest_hash") != blake3_hex(material):
            return False
        return verify_ed25519_signature(data["public_key_hex"], data["export_manifest_signature_hex"], material)


@dataclass(frozen=True)
class SignedAuditCheckpoint:
    schema_version: str
    checkpoint: dict[str, Any]
    audit_verified: bool
    plain_language_summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class NativeAuditCheckpointSigner:
    def __init__(self, *, key_store: PersistedDeviceSigningKeyStore):
        self.key_store = key_store

    def sign_checkpoint(self, *, audit_log: AuditLog) -> SignedAuditCheckpoint:
        errors = audit_log.verify()
        if errors:
            raise DeviceExecutionViolation(f"cannot sign failed audit chain: {errors}")
        checkpoint = audit_log.create_checkpoint(self.key_store.load_or_create())
        checkpoint_errors = AuditLog.verify_checkpoint(checkpoint)
        if checkpoint_errors:
            raise DeviceExecutionViolation(f"checkpoint signature failed verification: {checkpoint_errors}")
        return SignedAuditCheckpoint(
            schema_version="0.7",
            checkpoint=checkpoint,
            audit_verified=True,
            plain_language_summary="Echo Guardian signed the latest native audit checkpoint after verifying the audit chain.",
        )


@dataclass(frozen=True)
class ProviderSandboxReceipt:
    schema_version: str
    receipt_id: str
    provider: str
    provider_message_id: str | None
    delivery_status: str
    sandbox_verified: bool
    sensitive_details_included: bool
    emergency_services_used: bool
    receipt_hash: str
    created_at: str
    plain_language_summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ProviderSandboxReceiptVerifier:
    """Verifies sandbox provider receipts before live delivery can advance."""

    def verify(
        self,
        *,
        result: DeliveryResult,
        alert: MinimalDisclosureAlert,
        provider_response: dict[str, Any],
    ) -> ProviderSandboxReceipt:
        alert.validate_minimal_disclosure()
        if provider_response.get("sandbox") is not True:
            raise DeviceExecutionViolation("provider receipt must come from sandbox mode before live delivery")
        if provider_response.get("provider") != result.provider:
            raise DeviceExecutionViolation("provider receipt does not match delivery result provider")
        if provider_response.get("provider_message_id") != result.provider_message_id:
            raise DeviceExecutionViolation("provider receipt does not match delivery message id")
        if result.status not in {"attempted", "delivered"}:
            raise DeviceExecutionViolation("only attempted or delivered sandbox results can be verified")
        receipt_material = {
            "provider": result.provider,
            "provider_message_id": result.provider_message_id,
            "status": result.status,
            "sandbox": True,
        }
        return ProviderSandboxReceipt(
            schema_version="0.7",
            receipt_id=str(uuid4()),
            provider=result.provider,
            provider_message_id=result.provider_message_id,
            delivery_status=result.status,
            sandbox_verified=True,
            sensitive_details_included=False,
            emergency_services_used=False,
            receipt_hash=blake3_hex(canonical_json_bytes(receipt_material)),
            created_at=utc_now_iso(),
            plain_language_summary="Echo Guardian verified the provider sandbox delivery receipt before live delivery use.",
        )


class ArtifactAttestationBuilder:
    """Creates deterministic hashes for release artifacts used by CI."""

    def build(self, *, root: str | Path, artifact_paths: list[str]) -> dict[str, Any]:
        base = Path(root)
        entries: list[dict[str, Any]] = []
        for rel in sorted(artifact_paths):
            path = base / rel
            if not path.exists():
                raise DeviceExecutionViolation(f"attestation artifact missing: {rel}")
            entries.append({"path": rel, "blake3": blake3_hex(path.read_bytes())})
        statement = {
            "schema_version": "0.7",
            "attestation_id": str(uuid4()),
            "created_at": utc_now_iso(),
            "artifact_count": len(entries),
            "artifacts": entries,
            "plain_language_summary": "Echo Guardian created local CI artifact hashes for v0.7 release verification.",
        }
        statement["attestation_hash"] = blake3_hex(canonical_json_bytes(statement))
        return statement


def audit_device_execution_event(*, audit_log: AuditLog, policy: ProductionPolicy, event_type: str, platform: DevicePlatform, plain_language: str) -> dict[str, Any]:
    return audit_log.append(
        AuditEntryInput(
            event_type=event_type,
            severity="normal",
            authority_context="system_internal",
            policy_id=policy.policy_id,
            policy_version=policy.policy_version,
            public_context={
                "space_id": "native_device_execution",
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
