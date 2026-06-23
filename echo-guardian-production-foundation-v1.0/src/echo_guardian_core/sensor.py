from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol
from uuid import uuid4
import json

from jsonschema import Draft202012Validator

from .audit import AuditEntryInput, AuditLog, utc_now_iso
from .policy import ProductionPolicy, PolicyViolation

SignalType = Literal[
    "motion",
    "device_presence",
    "sound_level",
    "environmental",
    "accelerometer",
    "gyroscope",
    "system",
]
HealthState = Literal["healthy", "degraded", "critical", "unavailable", "unknown"]
PermissionState = Literal["granted", "denied", "restricted", "not_determined", "unavailable"]
ObservationQuality = Literal["good", "noisy", "partial", "degraded", "unavailable"]


class SensorSchemaError(ValueError):
    """Raised when a sensor observation fails JSON Schema validation."""


class SensorPolicyViolation(PolicyViolation):
    """Raised when sensor ingestion violates production data rules."""


@dataclass(frozen=True)
class SensorCapability:
    """Current availability and permission state for one sensor/signal source."""

    sensor_id: str
    signal_type: SignalType
    display_name: str
    permission_state: PermissionState
    availability_state: HealthState
    private_space_capable: bool = False
    plain_language: str = "Sensor status is available."


@dataclass(frozen=True)
class DeviceSignalSample:
    """Ephemeral adapter output.

    This object may be created in memory by platform adapters, but raw_sample must
    never be persisted or copied into SensorObservationRecord. The ingestion layer
    converts it immediately into derived metadata and audited health state.
    """

    sensor_id: str
    signal_type: SignalType
    space_id: str
    private_space: bool
    captured_at: str
    quality: ObservationQuality
    derived_metadata: dict[str, Any]
    raw_sample: Any | None = None
    permission_state: PermissionState = "granted"
    availability_state: HealthState = "healthy"


@dataclass(frozen=True)
class SensorObservationRecord:
    schema_version: str
    observation_id: str
    created_at: str
    sensor_id: str
    signal_type: SignalType
    space_id: str
    private_space: bool
    quality: ObservationQuality
    permission_state: PermissionState
    availability_state: HealthState
    raw_sensor_retained: bool
    derived_metadata: dict[str, Any]
    plain_language_summary: str
    audit_ref: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SensorAdapter(Protocol):
    """Production sensor adapter contract.

    iOS, Android, desktop, or appliance adapters must implement this contract
    using platform-approved APIs. They may expose raw samples in memory only long
    enough to derive minimized metadata.
    """

    def capability(self) -> SensorCapability:
        ...

    def read(self) -> DeviceSignalSample:
        ...


class SensorIngestionEngine:
    """Real sensor ingestion boundary for Echo Guardian production foundation.

    The engine accepts platform adapter samples, applies policy guardrails,
    discards raw samples, stores only derived metadata, and emits audit entries
    for observations, permissions, availability, and degraded states.
    """

    FORBIDDEN_RAW_KEYS = {
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

    def __init__(self, *, policy: ProductionPolicy, audit_log: AuditLog):
        policy.validate()
        self.policy = policy
        self.audit_log = audit_log

    def record_capability(self, capability: SensorCapability) -> dict[str, Any]:
        event_type = "sensor_available"
        severity = "normal"
        if capability.permission_state != "granted":
            event_type = "sensor_permission_changed"
            severity = "unusual"
        elif capability.availability_state in {"degraded", "critical", "unavailable"}:
            event_type = "sensor_degraded"
            severity = "unusual" if capability.availability_state == "degraded" else "concerning"

        entry = self.audit_log.append(
            AuditEntryInput(
                event_type=event_type,
                severity=severity,  # type: ignore[arg-type]
                authority_context="system_internal",
                policy_id=self.policy.policy_id,
                policy_version=self.policy.policy_version,
                public_context={
                    "space_id": "sensor",
                    "private_space": False,
                    "signal_types": [capability.signal_type],
                    "plain_language": capability.plain_language,
                    "sensor_id": capability.sensor_id,
                    "permission_state": capability.permission_state,
                    "availability_state": capability.availability_state,
                },
            )
        )
        return {
            "schema_version": "0.2",
            "health_id": str(uuid4()),
            "created_at": utc_now_iso(),
            "overall_state": capability.availability_state,
            "components": [asdict(capability)],
            "plain_language_summary": capability.plain_language,
            "audit_ref": entry["audit_entry_id"],
        }

    def ingest(self, sample: DeviceSignalSample) -> SensorObservationRecord:
        self._validate_sample_policy(sample)
        derived = self._sanitize_derived_metadata(sample.derived_metadata)
        plain_language = self._plain_language_for_sample(sample)
        event_type = "sensor_observation"
        severity = "normal"
        if sample.permission_state != "granted":
            event_type = "sensor_permission_changed"
            severity = "unusual"
        elif sample.availability_state in {"degraded", "critical", "unavailable"} or sample.quality in {
            "degraded",
            "unavailable",
            "partial",
        }:
            event_type = "sensor_degraded"
            severity = "unusual" if sample.availability_state == "degraded" or sample.quality != "unavailable" else "concerning"

        entry = self.audit_log.append(
            AuditEntryInput(
                event_type=event_type,
                severity=severity,  # type: ignore[arg-type]
                authority_context="system_internal",
                policy_id=self.policy.policy_id,
                policy_version=self.policy.policy_version,
                public_context={
                    "space_id": sample.space_id,
                    "private_space": sample.private_space,
                    "signal_types": [sample.signal_type],
                    "plain_language": plain_language,
                    "sensor_id": sample.sensor_id,
                    "quality": sample.quality,
                    "permission_state": sample.permission_state,
                    "availability_state": sample.availability_state,
                    "raw_sensor_retained": False,
                    "derived_metadata_keys": sorted(derived.keys()),
                },
            )
        )
        return SensorObservationRecord(
            schema_version="0.2",
            observation_id=str(uuid4()),
            created_at=utc_now_iso(),
            sensor_id=sample.sensor_id,
            signal_type=sample.signal_type,
            space_id=sample.space_id,
            private_space=sample.private_space,
            quality=sample.quality,
            permission_state=sample.permission_state,
            availability_state=sample.availability_state,
            raw_sensor_retained=False,
            derived_metadata=derived,
            plain_language_summary=plain_language,
            audit_ref=entry["audit_entry_id"],
        )

    def ingest_from_adapter(self, adapter: SensorAdapter) -> SensorObservationRecord:
        capability = adapter.capability()
        self.record_capability(capability)
        return self.ingest(adapter.read())

    def _validate_sample_policy(self, sample: DeviceSignalSample) -> None:
        if self.policy.data.get("real_sensor_ingestion_enabled") is not True:
            raise SensorPolicyViolation("real sensor ingestion must be enabled")
        if self.policy.data.get("raw_sensor_retention") != "not_retained":
            raise SensorPolicyViolation("raw sensor retention must remain not_retained")
        if sample.raw_sample is not None:
            # Raw sample may exist only ephemerally in the adapter. It must not
            # cross the ingestion boundary into production storage.
            raise SensorPolicyViolation("raw sensor samples cannot cross the ingestion boundary")
        if sample.private_space or sample.space_id in {"bathroom", "bedroom"}:
            raise SensorPolicyViolation("private-space sensor ingestion is hard-blocked by default")

    def _sanitize_derived_metadata(self, metadata: dict[str, Any]) -> dict[str, Any]:
        lowered = {k.lower() for k in metadata}
        forbidden = lowered.intersection(self.FORBIDDEN_RAW_KEYS)
        if forbidden:
            raise SensorPolicyViolation(f"derived metadata contains forbidden raw-data keys: {sorted(forbidden)}")
        try:
            # Ensure the metadata is JSON-safe and detached from adapter internals.
            return json.loads(json.dumps(metadata, sort_keys=True, separators=(",", ":")))
        except TypeError as exc:
            raise SensorPolicyViolation("derived metadata must be JSON-serializable") from exc

    @staticmethod
    def _plain_language_for_sample(sample: DeviceSignalSample) -> str:
        if sample.permission_state != "granted":
            return f"Echo Guardian cannot use {sample.signal_type} because permission is {sample.permission_state}."
        if sample.availability_state in {"degraded", "critical", "unavailable"} or sample.quality in {"degraded", "unavailable", "partial"}:
            return f"Echo Guardian received a degraded {sample.signal_type} signal, so monitoring may be less accurate."
        return f"Echo Guardian received a {sample.signal_type} safety signal for {sample.space_id} and stored only derived metadata."


def validate_sensor_observation_schema(data: dict[str, Any], schema_path: str | Path) -> None:
    schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
    if errors:
        first = errors[0]
        path = "/".join(str(p) for p in first.path) or "<root>"
        raise SensorSchemaError(f"sensor observation schema validation failed at {path}: {first.message}")
