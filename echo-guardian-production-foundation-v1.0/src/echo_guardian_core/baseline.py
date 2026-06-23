from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4
import json

from jsonschema import Draft202012Validator

from .audit import AuditEntryInput, AuditLog, utc_now_iso
from .policy import ProductionPolicy, PolicyViolation
from .sensor import SensorObservationRecord

BaselineStatus = Literal["no_baseline", "learning", "established", "degraded", "reset", "replaced"]


class BaselineSchemaError(ValueError):
    """Raised when a baseline summary fails JSON Schema validation."""


class BaselinePolicyViolation(PolicyViolation):
    """Raised when baseline learning violates Echo Guardian production rules."""


@dataclass
class SpaceBaselineState:
    """Aggregate, non-raw baseline state for one monitored space.

    This state stores only counters, confidence, signal types, and summary fields.
    It never stores raw observations, raw samples, transcripts, waveforms, or full
    event histories.
    """

    space_id: str
    private_space: bool
    enabled: bool = True
    observation_count: int = 0
    observed_signal_types: set[str] = field(default_factory=set)
    quality_counts: dict[str, int] = field(default_factory=dict)
    motion_seen_count: int = 0
    presence_seen_count: int = 0
    confidence: float = 0.0
    last_observed_at: str | None = None

    def ingest(self, observation: SensorObservationRecord) -> None:
        if observation.private_space or observation.space_id in {"bathroom", "bedroom"}:
            raise BaselinePolicyViolation("private-space observations cannot be used for baseline learning in v0.2")
        self.observation_count += 1
        self.observed_signal_types.add(observation.signal_type)
        self.quality_counts[observation.quality] = self.quality_counts.get(observation.quality, 0) + 1
        self.last_observed_at = observation.created_at

        metadata = observation.derived_metadata
        if metadata.get("motion_detected") is True:
            self.motion_seen_count += 1
        if metadata.get("presence_detected") is True:
            self.presence_seen_count += 1

        good_count = self.quality_counts.get("good", 0)
        partial_count = self.quality_counts.get("partial", 0)
        quality_score = min(1.0, (good_count + partial_count * 0.5) / max(self.observation_count, 1))
        volume_score = min(1.0, self.observation_count / 12.0)
        signal_score = min(1.0, len(self.observed_signal_types) / 3.0)
        self.confidence = round((volume_score * 0.55) + (quality_score * 0.30) + (signal_score * 0.15), 3)

    def to_summary_dict(self) -> dict[str, Any]:
        summary_parts = [f"{self.observation_count} minimized safety observations"]
        if self.observed_signal_types:
            summary_parts.append("signals: " + ", ".join(sorted(self.observed_signal_types)))
        if self.motion_seen_count:
            summary_parts.append("movement has been seen")
        if self.presence_seen_count:
            summary_parts.append("presence has been seen")
        return {
            "space_id": self.space_id,
            "private_space": self.private_space,
            "enabled": self.enabled,
            "observation_count": self.observation_count,
            "observed_signal_types": sorted(self.observed_signal_types),
            "confidence": self.confidence,
            "last_observed_at": self.last_observed_at,
            "summary": "Echo Guardian has learned " + "; ".join(summary_parts) + ".",
        }


@dataclass
class BaselineProfile:
    schema_version: str
    baseline_id: str
    created_at: str
    updated_at: str
    status: BaselineStatus
    spaces: dict[str, SpaceBaselineState] = field(default_factory=dict)
    audit_refs: list[str] = field(default_factory=list)
    minimum_observations_for_established: int = 12
    degraded_reason: str | None = None
    replaced_from_baseline_id: str | None = None

    @classmethod
    def create(cls) -> "BaselineProfile":
        now = utc_now_iso()
        return cls(
            schema_version="0.2",
            baseline_id=str(uuid4()),
            created_at=now,
            updated_at=now,
            status="no_baseline",
        )

    @property
    def overall_confidence(self) -> float:
        if not self.spaces:
            return 0.0
        return round(sum(space.confidence for space in self.spaces.values()) / len(self.spaces), 3)

    @property
    def total_observations(self) -> int:
        return sum(space.observation_count for space in self.spaces.values())

    def to_summary(self) -> dict[str, Any]:
        plain = self._plain_language_summary()
        return {
            "schema_version": self.schema_version,
            "baseline_id": self.baseline_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "status": self.status,
            "minimum_observations_for_established": self.minimum_observations_for_established,
            "total_observations": self.total_observations,
            "spaces": [self.spaces[key].to_summary_dict() for key in sorted(self.spaces)],
            "confidence": {
                "overall": self.overall_confidence,
                "observation_volume": round(min(1.0, self.total_observations / max(self.minimum_observations_for_established, 1)), 3),
                "space_coverage": round(min(1.0, len(self.spaces) / 3.0), 3),
            },
            "plain_language_summary": plain,
            "sensitive_details_included": False,
            "degraded_reason": self.degraded_reason,
            "replaced_from_baseline_id": self.replaced_from_baseline_id,
            "audit_refs": list(dict.fromkeys(self.audit_refs)),
        }

    def _plain_language_summary(self) -> str:
        if self.status == "no_baseline":
            return "Echo Guardian has not learned a normal pattern yet."
        if self.status == "learning":
            return f"Echo Guardian is learning normal activity patterns from minimized local safety signals. Confidence is {int(self.overall_confidence * 100)}%."
        if self.status == "established":
            return f"Echo Guardian has an established local baseline from minimized safety signals. Confidence is {int(self.overall_confidence * 100)}%."
        if self.status == "degraded":
            return "Echo Guardian's baseline is degraded and should be reviewed before relying on it for high-confidence decisions."
        if self.status == "reset":
            return "Echo Guardian's baseline was reset. It needs to learn again before high-confidence decisions."
        if self.status == "replaced":
            return "Echo Guardian replaced the prior baseline and created a new learning boundary."
        return "Echo Guardian baseline status is available."

    def save(self, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_summary(), sort_keys=True, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")


class BaselineLearningEngine:
    """Local baseline engine for production foundation v0.2.

    It consumes only SensorObservationRecord objects that already crossed the
    sensor minimization boundary. It stores aggregate baseline state only, emits
    plain-language summaries, and creates audit entries for every lifecycle event.
    """

    def __init__(self, *, policy: ProductionPolicy, audit_log: AuditLog, profile: BaselineProfile | None = None):
        policy.validate()
        if policy.data.get("local_baseline_learning_enabled") is not True:
            raise BaselinePolicyViolation("local baseline learning must be enabled")
        if policy.data.get("raw_sensor_retention") != "not_retained":
            raise BaselinePolicyViolation("baseline learning requires raw_sensor_retention=not_retained")
        self.policy = policy
        self.audit_log = audit_log
        self.profile = profile or BaselineProfile.create()

    def create_baseline(self) -> dict[str, Any]:
        self.profile.status = "learning"
        self.profile.updated_at = utc_now_iso()
        entry = self.audit_log.append(
            AuditEntryInput(
                event_type="baseline_created",
                severity="normal",
                authority_context="system_internal",
                policy_id=self.policy.policy_id,
                policy_version=self.policy.policy_version,
                public_context={
                    "space_id": "baseline",
                    "private_space": False,
                    "signal_types": [],
                    "plain_language": "Echo Guardian created a local baseline profile and started learning from minimized safety signals.",
                    "baseline_id": self.profile.baseline_id,
                    "raw_history_retained": False,
                },
            )
        )
        self.profile.audit_refs.append(entry["audit_entry_id"])
        return self.profile.to_summary()

    def ingest_observation(self, observation: SensorObservationRecord) -> dict[str, Any]:
        self._validate_observation(observation)
        if self.profile.status in {"no_baseline", "reset", "replaced"}:
            self.profile.status = "learning"
        space = self.profile.spaces.get(observation.space_id)
        if space is None:
            space = SpaceBaselineState(space_id=observation.space_id, private_space=observation.private_space)
            self.profile.spaces[observation.space_id] = space
        space.ingest(observation)
        self.profile.updated_at = utc_now_iso()
        if self.profile.total_observations >= self.profile.minimum_observations_for_established and self.profile.overall_confidence >= 0.65:
            self.profile.status = "established"
        else:
            self.profile.status = "learning"

        summary = self.profile.to_summary()
        entry = self.audit_log.append(
            AuditEntryInput(
                event_type="baseline_updated",
                severity="normal",
                authority_context="system_internal",
                policy_id=self.policy.policy_id,
                policy_version=self.policy.policy_version,
                public_context={
                    "space_id": observation.space_id,
                    "private_space": False,
                    "signal_types": [observation.signal_type],
                    "plain_language": summary["plain_language_summary"],
                    "baseline_id": self.profile.baseline_id,
                    "baseline_status": self.profile.status,
                    "overall_confidence_scaled": int(self.profile.overall_confidence * 1000),
                    "raw_history_retained": False,
                },
            )
        )
        self.profile.audit_refs.append(entry["audit_entry_id"])
        return self.profile.to_summary()

    def mark_degraded(self, *, reason: str) -> dict[str, Any]:
        self.profile.status = "degraded"
        self.profile.degraded_reason = reason
        self.profile.updated_at = utc_now_iso()
        entry = self.audit_log.append(
            AuditEntryInput(
                event_type="baseline_degraded",
                severity="unusual",
                authority_context="system_internal",
                policy_id=self.policy.policy_id,
                policy_version=self.policy.policy_version,
                public_context={
                    "space_id": "baseline",
                    "private_space": False,
                    "signal_types": [],
                    "plain_language": "Echo Guardian marked the baseline as degraded: " + reason,
                    "baseline_id": self.profile.baseline_id,
                    "raw_history_retained": False,
                },
            )
        )
        self.profile.audit_refs.append(entry["audit_entry_id"])
        return self.profile.to_summary()

    def reset(self, *, reason: str) -> dict[str, Any]:
        old_id = self.profile.baseline_id
        self.profile = BaselineProfile.create()
        self.profile.status = "reset"
        self.profile.degraded_reason = reason
        entry = self.audit_log.append(
            AuditEntryInput(
                event_type="baseline_reset",
                severity="normal",
                authority_context="user_controlled",
                policy_id=self.policy.policy_id,
                policy_version=self.policy.policy_version,
                public_context={
                    "space_id": "baseline",
                    "private_space": False,
                    "signal_types": [],
                    "plain_language": "Echo Guardian reset the local baseline. It will need to learn again before high-confidence decisions.",
                    "previous_baseline_id": old_id,
                    "new_baseline_id": self.profile.baseline_id,
                    "reason": reason,
                    "raw_history_retained": False,
                },
            )
        )
        self.profile.audit_refs.append(entry["audit_entry_id"])
        return self.profile.to_summary()

    def replace(self, *, reason: str) -> dict[str, Any]:
        old_id = self.profile.baseline_id
        self.profile = BaselineProfile.create()
        self.profile.status = "replaced"
        self.profile.replaced_from_baseline_id = old_id
        entry = self.audit_log.append(
            AuditEntryInput(
                event_type="baseline_replaced",
                severity="normal",
                authority_context="user_controlled",
                policy_id=self.policy.policy_id,
                policy_version=self.policy.policy_version,
                public_context={
                    "space_id": "baseline",
                    "private_space": False,
                    "signal_types": [],
                    "plain_language": "Echo Guardian replaced the local baseline and created a visible learning boundary.",
                    "previous_baseline_id": old_id,
                    "new_baseline_id": self.profile.baseline_id,
                    "reason": reason,
                    "raw_history_retained": False,
                },
            )
        )
        self.profile.audit_refs.append(entry["audit_entry_id"])
        return self.profile.to_summary()

    def _validate_observation(self, observation: SensorObservationRecord) -> None:
        if observation.raw_sensor_retained is not False:
            raise BaselinePolicyViolation("baseline learning cannot ingest records that retained raw sensor data")
        if observation.private_space or observation.space_id in {"bathroom", "bedroom"}:
            raise BaselinePolicyViolation("private-space observations cannot be used for baseline learning in v0.2")
        forbidden = {"raw", "raw_data", "raw_sample", "samples", "audio_buffer", "video_frame", "transcript", "waveform", "packet_capture"}
        lowered = {k.lower() for k in observation.derived_metadata}
        if forbidden.intersection(lowered):
            raise BaselinePolicyViolation("baseline learning cannot ingest raw-like derived metadata keys")


def validate_baseline_summary_schema(data: dict[str, Any], schema_path: str | Path) -> None:
    schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
    if errors:
        first = errors[0]
        path = "/".join(str(p) for p in first.path) or "<root>"
        raise BaselineSchemaError(f"baseline summary schema validation failed at {path}: {first.message}")
