"""Native runtime hardening helpers for Echo Guardian v0.6.

These helpers model the boundary between native iOS/Android runtimes and the
Python/core-compatible production foundation. They intentionally keep platform
facts minimized, visible, and auditable.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4
import json

from echo_guardian_core.anomaly import AnomalySeverityClassifier, SeverityClassificationRecord
from echo_guardian_core.audit import AuditEntryInput, AuditLog, utc_now_iso
from echo_guardian_core.baseline import BaselineLearningEngine, BaselineProfile
from echo_guardian_core.crypto import blake3_hex
from echo_guardian_core.delivery.provider_adapter import DeliveryResult, MinimalDisclosureAlert
from echo_guardian_core.export import ExportPackageBuilder, ExportRequest
from echo_guardian_core.policy import ProductionPolicy, PolicyViolation
from echo_guardian_core.sensor import DeviceSignalSample, SensorIngestionEngine, SensorObservationRecord, SensorPolicyViolation

NativePlatform = Literal["ios", "android"]
PermissionState = Literal["granted", "denied", "restricted", "not_determined", "unavailable"]
AvailabilityState = Literal["healthy", "degraded", "critical", "unavailable", "unknown"]

FORBIDDEN_NATIVE_KEYS = {
    "raw",
    "raw_data",
    "raw_sample",
    "samples",
    "audio_buffer",
    "video_frame",
    "transcript",
    "waveform",
    "packet_capture",
}


class NativeRuntimePolicyViolation(PolicyViolation):
    """Raised when a native runtime boundary violates production laws."""


@dataclass(frozen=True)
class NativePermissionStatus:
    platform: NativePlatform
    permission_name: str
    permission_state: PermissionState
    availability_state: AvailabilityState
    sensor_id: str
    signal_type: str
    plain_language_summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class NativeObservationEnvelope:
    platform: NativePlatform
    sensor_id: str
    signal_type: str
    space_id: str
    private_space: bool
    permission_state: PermissionState
    availability_state: AvailabilityState
    quality: str
    derived_metadata: dict[str, Any]
    created_at: str = field(default_factory=utc_now_iso)

    def validate(self) -> None:
        if self.private_space or self.space_id in {"bathroom", "bedroom"}:
            raise NativeRuntimePolicyViolation("native private-space monitoring is blocked by default")
        lowered = {key.lower() for key in self.derived_metadata}
        forbidden = sorted(lowered.intersection(FORBIDDEN_NATIVE_KEYS))
        if forbidden:
            raise NativeRuntimePolicyViolation(f"native derived metadata contains raw-like keys: {forbidden}")
        try:
            json.dumps(self.derived_metadata, sort_keys=True, separators=(",", ":"))
        except TypeError as exc:
            raise NativeRuntimePolicyViolation("native derived metadata must be JSON serializable") from exc

    def to_core_sample(self) -> DeviceSignalSample:
        self.validate()
        return DeviceSignalSample(
            sensor_id=self.sensor_id,
            signal_type=self.signal_type,  # type: ignore[arg-type]
            space_id=self.space_id,
            private_space=False,
            captured_at=self.created_at,
            quality=self.quality,  # type: ignore[arg-type]
            derived_metadata=json.loads(json.dumps(self.derived_metadata, sort_keys=True, separators=(",", ":"))),
            raw_sample=None,
            permission_state=self.permission_state,
            availability_state=self.availability_state,
        )


@dataclass(frozen=True)
class NativeCycleResult:
    schema_version: str
    cycle_id: str
    platform: NativePlatform
    observation_id: str
    baseline_id: str
    classification_id: str
    severity: str
    delivery_status: str | None
    export_manifest_hash: str | None
    audit_verified: bool
    plain_language_summary: str
    audit_refs: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class NativeAuditAppender:
    """Native audit append facade that writes to the core audit chain."""

    def __init__(self, *, audit_log: AuditLog, policy: ProductionPolicy):
        self.audit_log = audit_log
        self.policy = policy

    def append_native_event(
        self,
        *,
        event_type: str,
        severity: str,
        platform: NativePlatform,
        plain_language: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        context = dict(context or {})
        context.update(
            {
                "space_id": context.get("space_id", "native_runtime"),
                "private_space": False,
                "signal_types": context.get("signal_types", []),
                "platform": platform,
                "plain_language": plain_language,
                "raw_sensor_retained": False,
                "cloud_dependency": False,
            }
        )
        return self.audit_log.append(
            AuditEntryInput(
                event_type=event_type,
                severity=severity,  # type: ignore[arg-type]
                authority_context="system_internal",
                policy_id=self.policy.policy_id,
                policy_version=self.policy.policy_version,
                public_context=context,
            )
        )


class ProviderDeliveryStatusStore:
    """Local delivery-status persistence for guarded provider adapters."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, *, result: DeliveryResult, alert: MinimalDisclosureAlert, audit_ref: str) -> dict[str, Any]:
        if alert.sensitive_details_included or alert.emergency_services_used:
            raise NativeRuntimePolicyViolation("delivery persistence blocks sensitive details and emergency-services routing by default")
        record = {
            "schema_version": "0.6",
            "delivery_record_id": str(uuid4()),
            "created_at": utc_now_iso(),
            "status": result.status,
            "provider": result.provider,
            "provider_message_id": result.provider_message_id,
            "plain_language_summary": result.plain_language_summary,
            "minimal_disclosure": True,
            "sensitive_details_included": False,
            "emergency_services_used": False,
            "audit_ref": audit_ref,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
        return record

    def read_all(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]


class NativeRuntimeHardeningRunner:
    """One native-to-core hardening cycle.

    The runner ingests a minimized native observation, appends native audit state,
    updates baseline, classifies severity, optionally persists guarded delivery
    status, optionally creates an explicit local export, and verifies the audit
    chain before returning.
    """

    def __init__(self, *, policy: ProductionPolicy, audit_log: AuditLog):
        policy.validate()
        if policy.data.get("cloud_dependency_for_core_loop") is True:
            raise NativeRuntimePolicyViolation("native runtime hardening requires no cloud dependency for the core loop")
        if policy.data.get("silent_telemetry_enabled") is True:
            raise NativeRuntimePolicyViolation("native runtime hardening blocks hidden telemetry")
        self.policy = policy
        self.audit_log = audit_log
        self.native_audit = NativeAuditAppender(audit_log=audit_log, policy=policy)

    def run(
        self,
        *,
        envelope: NativeObservationEnvelope,
        baseline: BaselineProfile,
        delivery_store: ProviderDeliveryStatusStore | None = None,
        delivery_result: DeliveryResult | None = None,
        delivery_alert: MinimalDisclosureAlert | None = None,
        export_dir: str | Path | None = None,
    ) -> NativeCycleResult:
        envelope.validate()
        permission_entry = self.native_audit.append_native_event(
            event_type="native_permission_status_checked",
            severity="normal" if envelope.permission_state == "granted" else "unusual",
            platform=envelope.platform,
            plain_language=f"Echo Guardian checked native {envelope.signal_type} permission and availability.",
            context={"space_id": envelope.space_id, "signal_types": [envelope.signal_type], "permission_state": envelope.permission_state, "availability_state": envelope.availability_state},
        )
        ingestion = SensorIngestionEngine(policy=self.policy, audit_log=self.audit_log)
        observation = ingestion.ingest(envelope.to_core_sample())
        baseline_engine = BaselineLearningEngine(policy=self.policy, audit_log=self.audit_log, profile=baseline)
        baseline_engine.ingest_observation(observation)
        classifier = AnomalySeverityClassifier(policy=self.policy, audit_log=self.audit_log)
        classification = classifier.classify(observation=observation, baseline=baseline)

        audit_refs = [permission_entry["audit_entry_id"], observation.audit_ref, *baseline.audit_refs, *classification.audit_refs]
        delivery_status = None
        if delivery_store is not None or delivery_result is not None or delivery_alert is not None:
            if delivery_store is None or delivery_result is None or delivery_alert is None:
                raise NativeRuntimePolicyViolation("delivery status persistence requires store, result, and minimal alert")
            delivery_entry = self.native_audit.append_native_event(
                event_type="native_delivery_status_persisted",
                severity="normal" if delivery_result.status in {"attempted", "delivered"} else "unusual",
                platform=envelope.platform,
                plain_language="Echo Guardian saved the guarded delivery provider status locally.",
                context={"space_id": envelope.space_id, "signal_types": [envelope.signal_type], "delivery_status": delivery_result.status},
            )
            delivery_store.append(result=delivery_result, alert=delivery_alert, audit_ref=delivery_entry["audit_entry_id"])
            delivery_status = delivery_result.status
            audit_refs.append(delivery_entry["audit_entry_id"])

        export_manifest_hash = None
        if export_dir is not None:
            request = ExportRequest(
                requested_by_authority="user",
                user_confirmed=True,
                export_type="full_export",
                redactions_applied=True,
                encrypted=False,
                recipient=None,
            )
            baseline_path = Path(export_dir) / "baseline_summary_for_export.json"
            baseline_path.parent.mkdir(parents=True, exist_ok=True)
            baseline_path.write_text(json.dumps(baseline.to_summary(), sort_keys=True, separators=(",", ":")), encoding="utf-8")
            export_builder = ExportPackageBuilder(policy=self.policy, audit_log=self.audit_log)
            manifest = export_builder.create_export(
                request=request,
                export_dir=Path(export_dir) / "package",
                audit_chain_path=self.audit_log.path,
                baseline_path=baseline_path,
            )
            manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
            export_manifest_hash = blake3_hex(manifest_bytes)
            audit_refs.append(manifest["audit_ref"])

        audit_errors = self.audit_log.verify()
        verified = not audit_errors
        result = NativeCycleResult(
            schema_version="0.6",
            cycle_id=str(uuid4()),
            platform=envelope.platform,
            observation_id=observation.observation_id,
            baseline_id=baseline.baseline_id,
            classification_id=classification.classification_id,
            severity=classification.severity,
            delivery_status=delivery_status,
            export_manifest_hash=export_manifest_hash,
            audit_verified=verified,
            plain_language_summary=(
                f"Echo Guardian completed a native {envelope.platform} safety check for {envelope.space_id}. "
                f"Severity was {classification.severity}. Audit verification {'passed' if verified else 'failed'}."
            ),
            audit_refs=list(dict.fromkeys(audit_refs)),
        )
        if not verified:
            raise NativeRuntimePolicyViolation(f"native cycle audit verification failed: {audit_errors}")
        return result


def write_native_cycle_result(path: str | Path, result: NativeCycleResult) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(result.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
