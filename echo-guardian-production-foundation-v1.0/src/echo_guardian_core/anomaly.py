from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4
import json

from jsonschema import Draft202012Validator

from .audit import AuditEntryInput, AuditLog, utc_now_iso
from .baseline import BaselinePolicyViolation, BaselineProfile
from .policy import ProductionPolicy, PolicyViolation
from .sensor import SensorObservationRecord

Severity = Literal["normal", "unusual", "concerning", "severe", "emergency"]
BaselineStatus = Literal["no_baseline", "learning", "established", "degraded", "reset", "replaced"]


class AnomalySchemaError(ValueError):
    """Raised when a classification record fails JSON Schema validation."""


class AnomalyPolicyViolation(PolicyViolation):
    """Raised when anomaly classification violates production safety rules."""


@dataclass(frozen=True)
class SeverityClassificationRecord:
    schema_version: str
    classification_id: str
    created_at: str
    observation_id: str
    baseline_id: str
    baseline_status: str
    space_id: str
    signal_type: str
    is_anomaly: bool
    severity: Severity
    primary_reason_code: str
    confidence: float
    baseline_confidence: float
    signal_confidence: float
    plain_language_explanation: str
    recommended_next_action: str
    raw_history_retained: bool
    sensitive_details_included: bool
    audit_refs: list[str]
    evidence: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AnomalySeverityClassifier:
    """Deterministic baseline-vs-observation classifier for production v0.2.

    This class is intentionally conservative and explainable. It does not claim
    medical certainty. It compares minimized SensorObservationRecord objects
    against aggregate BaselineProfile state and emits audit records for anomaly
    detection and severity classification.
    """

    RAW_KEYS = {
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

    def classify(self, *, observation: SensorObservationRecord, baseline: BaselineProfile) -> SeverityClassificationRecord:
        self._validate_inputs(observation, baseline)
        space_state = baseline.spaces.get(observation.space_id)
        metadata = observation.derived_metadata
        baseline_confidence = baseline.overall_confidence
        signal_confidence = self._signal_confidence(observation)
        baseline_status = baseline.status

        severity, reason, explanation, next_action, is_anomaly, confidence = self._decide(
            observation=observation,
            baseline=baseline,
            space_state=space_state,
            baseline_confidence=baseline_confidence,
            signal_confidence=signal_confidence,
            metadata=metadata,
        )

        audit_refs: list[str] = []
        if is_anomaly:
            anomaly_entry = self.audit_log.append(
                AuditEntryInput(
                    event_type="anomaly_detected",
                    severity=severity,
                    authority_context="system_internal",
                    policy_id=self.policy.policy_id,
                    policy_version=self.policy.policy_version,
                    public_context={
                        "space_id": observation.space_id,
                        "private_space": observation.private_space,
                        "signal_types": [observation.signal_type],
                        "plain_language": explanation,
                        "observation_id": observation.observation_id,
                        "baseline_id": baseline.baseline_id,
                        "baseline_status": baseline_status,
                        "reason_code": reason,
                        "raw_history_retained": False,
                    },
                )
            )
            audit_refs.append(anomaly_entry["audit_entry_id"])

        classification_entry = self.audit_log.append(
            AuditEntryInput(
                event_type="severity_classified",
                severity=severity,
                authority_context="system_internal",
                policy_id=self.policy.policy_id,
                policy_version=self.policy.policy_version,
                public_context={
                    "space_id": observation.space_id,
                    "private_space": observation.private_space,
                    "signal_types": [observation.signal_type],
                    "plain_language": explanation,
                    "observation_id": observation.observation_id,
                    "baseline_id": baseline.baseline_id,
                    "baseline_status": baseline_status,
                    "severity": severity,
                    "reason_code": reason,
                    "classification_confidence_scaled": int(confidence * 1000),
                    "baseline_confidence_scaled": int(baseline_confidence * 1000),
                    "signal_confidence_scaled": int(signal_confidence * 1000),
                    "raw_history_retained": False,
                },
            )
        )
        audit_refs.append(classification_entry["audit_entry_id"])

        record = SeverityClassificationRecord(
            schema_version="0.2",
            classification_id=str(uuid4()),
            created_at=utc_now_iso(),
            observation_id=observation.observation_id,
            baseline_id=baseline.baseline_id,
            baseline_status=baseline_status,
            space_id=observation.space_id,
            signal_type=observation.signal_type,
            is_anomaly=is_anomaly,
            severity=severity,
            primary_reason_code=reason,
            confidence=round(confidence, 3),
            baseline_confidence=round(baseline_confidence, 3),
            signal_confidence=round(signal_confidence, 3),
            plain_language_explanation=explanation,
            recommended_next_action=next_action,
            raw_history_retained=False,
            sensitive_details_included=False,
            audit_refs=audit_refs,
            evidence={
                "baseline_status": baseline_status,
                "space_known_to_baseline": space_state is not None,
                "observation_quality": observation.quality,
                "permission_state": observation.permission_state,
                "availability_state": observation.availability_state,
                "derived_metadata_keys": sorted(metadata.keys()),
            },
        )
        return record

    def _decide(
        self,
        *,
        observation: SensorObservationRecord,
        baseline: BaselineProfile,
        space_state: Any | None,
        baseline_confidence: float,
        signal_confidence: float,
        metadata: dict[str, Any],
    ) -> tuple[Severity, str, str, str, bool, float]:
        # Explicit critical flags from minimized safety metadata may elevate
        # severity, but learning/degraded baselines cap severity unless the flag
        # is an explicit emergency indicator with high signal confidence.
        explicit_emergency = metadata.get("emergency_indicator") is True or metadata.get("critical_safety_signal") is True
        fall_like = metadata.get("fall_like_event") is True or metadata.get("impact_detected") is True
        prolonged_inactivity = metadata.get("prolonged_inactivity") is True
        expected_window = metadata.get("expected_activity_window") is True
        nonresponse_indicator = metadata.get("nonresponse_indicator") is True

        if observation.permission_state != "granted":
            return (
                "concerning",
                "sensor_permission_unavailable",
                f"Echo Guardian cannot fully evaluate {observation.space_id} because {observation.signal_type} permission is {observation.permission_state}.",
                "Show degraded monitoring status and request user review.",
                True,
                min(0.7, signal_confidence),
            )
        if observation.availability_state in {"critical", "unavailable"} or observation.quality == "unavailable":
            return (
                "concerning",
                "sensor_unavailable",
                f"Echo Guardian cannot rely on the {observation.signal_type} signal in {observation.space_id} because it is unavailable.",
                "Show degraded monitoring status and use available fallback signals.",
                True,
                min(0.72, signal_confidence),
            )
        if explicit_emergency and signal_confidence >= 0.85:
            severity: Severity = "emergency" if baseline.status == "established" and baseline_confidence >= 0.65 else "severe"
            return (
                severity,
                "explicit_critical_safety_signal",
                "Echo Guardian received a high-confidence critical safety signal and is treating it as a serious safety event.",
                "Request confirmation immediately and prepare guarded escalation if unresolved.",
                True,
                min(1.0, (signal_confidence * 0.75) + (baseline_confidence * 0.25)),
            )
        if fall_like and signal_confidence >= 0.70:
            severity = "severe" if baseline.status == "established" and baseline_confidence >= 0.55 else "concerning"
            return (
                severity,
                "fall_like_pattern",
                "Echo Guardian detected a fall-like or impact-like safety pattern from minimized local signals.",
                "Ask if the user is okay and prepare escalation if there is no response.",
                True,
                min(0.95, (signal_confidence * 0.7) + (baseline_confidence * 0.3)),
            )
        if prolonged_inactivity and (expected_window or nonresponse_indicator):
            severity = "severe" if baseline.status == "established" and baseline_confidence >= 0.70 and nonresponse_indicator else "concerning"
            return (
                severity,
                "prolonged_inactivity_during_expected_window",
                "Echo Guardian noticed less activity than expected during a time when activity is normally expected.",
                "Request confirmation using available interaction modes.",
                True,
                min(0.9, (baseline_confidence * 0.55) + (signal_confidence * 0.45)),
            )
        if baseline.status in {"no_baseline", "reset", "replaced"}:
            return (
                "unusual",
                "baseline_not_ready",
                "Echo Guardian does not yet have enough local baseline information for a high-confidence decision.",
                "Continue learning and avoid high-severity action unless stronger safety signals appear.",
                True,
                min(0.45, signal_confidence),
            )
        if baseline.status == "degraded":
            return (
                "concerning",
                "baseline_degraded",
                "Echo Guardian's baseline is degraded, so this safety decision needs extra caution.",
                "Show degraded baseline status and request confirmation for meaningful deviations.",
                True,
                min(0.65, (signal_confidence + baseline_confidence) / 2),
            )
        if space_state is None:
            severity = "unusual" if baseline.status == "learning" else "concerning"
            return (
                severity,
                "space_not_in_baseline",
                f"Echo Guardian received a signal from {observation.space_id}, which is not yet part of the learned baseline.",
                "Continue learning and request confirmation if other signals also look concerning.",
                True,
                min(0.62, signal_confidence),
            )
        if observation.signal_type not in space_state.observed_signal_types:
            return (
                "unusual",
                "new_signal_type_for_space",
                f"Echo Guardian received a new type of safety signal in {observation.space_id} that is not yet well learned.",
                "Continue learning and keep monitoring visible.",
                True,
                min(0.55, signal_confidence),
            )
        if observation.quality in {"degraded", "partial", "noisy"} or observation.availability_state == "degraded":
            return (
                "unusual",
                "signal_quality_degraded",
                f"Echo Guardian received a lower-quality {observation.signal_type} signal, so monitoring may be less accurate.",
                "Show degraded monitoring status and continue using available signals.",
                True,
                min(0.6, signal_confidence),
            )

        # Baseline-vs-observation comparison for expected activity. This remains
        # conservative because the baseline stores aggregate counts, not raw history.
        if observation.signal_type == "motion" and metadata.get("motion_detected") is False and expected_window:
            motion_ratio = space_state.motion_seen_count / max(space_state.observation_count, 1)
            if baseline.status == "established" and motion_ratio >= 0.5 and baseline_confidence >= 0.65:
                return (
                    "concerning",
                    "expected_motion_absent",
                    "Echo Guardian expected movement based on the local baseline, but movement was not detected.",
                    "Ask if the user is okay.",
                    True,
                    round(min(0.85, (motion_ratio * 0.45) + (baseline_confidence * 0.35) + (signal_confidence * 0.20)), 3),
                )
            return (
                "unusual",
                "possible_expected_motion_absent",
                "Echo Guardian saw less movement than expected, but the baseline is still not strong enough for a higher-severity decision.",
                "Continue watching and ask gently if needed.",
                True,
                min(0.55, signal_confidence),
            )
        if observation.signal_type == "device_presence" and metadata.get("presence_detected") is False and expected_window:
            presence_ratio = space_state.presence_seen_count / max(space_state.observation_count, 1)
            if baseline.status == "established" and presence_ratio >= 0.5 and baseline_confidence >= 0.65:
                return (
                    "concerning",
                    "expected_presence_absent",
                    "Echo Guardian expected presence based on the local baseline, but presence was not detected.",
                    "Ask if the user is okay.",
                    True,
                    round(min(0.85, (presence_ratio * 0.45) + (baseline_confidence * 0.35) + (signal_confidence * 0.20)), 3),
                )

        if baseline.status == "learning":
            return (
                "normal",
                "matches_learning_baseline",
                "Echo Guardian received a normal minimized safety signal while it is still learning this pattern.",
                "Keep learning locally.",
                False,
                min(0.6, (signal_confidence * 0.7) + (baseline_confidence * 0.3)),
            )
        return (
            "normal",
            "matches_established_baseline",
            "Echo Guardian received a safety signal that matches the established local baseline.",
            "No action needed.",
            False,
            min(0.95, (signal_confidence * 0.55) + (baseline_confidence * 0.45)),
        )

    def _validate_inputs(self, observation: SensorObservationRecord, baseline: BaselineProfile) -> None:
        if observation.raw_sensor_retained is not False:
            raise AnomalyPolicyViolation("anomaly classification cannot ingest records that retained raw sensor data")
        if observation.private_space or observation.space_id in {"bathroom", "bedroom"}:
            raise AnomalyPolicyViolation("private-space classification is hard-blocked in v0.2")
        lowered = {k.lower() for k in observation.derived_metadata}
        if self.RAW_KEYS.intersection(lowered):
            raise AnomalyPolicyViolation("anomaly classification cannot ingest raw-like derived metadata keys")
        if baseline.to_summary().get("sensitive_details_included") is not False:
            raise BaselinePolicyViolation("baseline summary must not include sensitive details")

    @staticmethod
    def _signal_confidence(observation: SensorObservationRecord) -> float:
        metadata = observation.derived_metadata
        scaled = metadata.get("confidence_scaled")
        if isinstance(scaled, int | float):
            base = max(0.0, min(1.0, float(scaled) / 100.0 if scaled <= 100 else float(scaled) / 1000.0))
        else:
            base = {
                "good": 0.85,
                "partial": 0.60,
                "noisy": 0.45,
                "degraded": 0.40,
                "unavailable": 0.10,
            }.get(observation.quality, 0.5)
        if observation.permission_state != "granted":
            base = min(base, 0.3)
        if observation.availability_state == "degraded":
            base = min(base, 0.55)
        if observation.availability_state in {"critical", "unavailable"}:
            base = min(base, 0.2)
        return round(base, 3)


def validate_classification_schema(data: dict[str, Any], schema_path: str | Path) -> None:
    schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
    if errors:
        first = errors[0]
        path = "/".join(str(p) for p in first.path) or "<root>"
        raise AnomalySchemaError(f"severity classification schema validation failed at {path}: {first.message}")


def baseline_profile_from_summary(summary: dict[str, Any]) -> BaselineProfile:
    """Rehydrate a minimal BaselineProfile from a non-sensitive baseline summary.

    This is intended for tooling and export-review workflows. The production
    classifier should prefer an in-memory BaselineProfile when available because
    it retains aggregate counts without storing raw history.
    """
    from .baseline import SpaceBaselineState

    profile = BaselineProfile(
        schema_version=summary.get("schema_version", "0.2"),
        baseline_id=summary["baseline_id"],
        created_at=summary["created_at"],
        updated_at=summary["updated_at"],
        status=summary["status"],
        minimum_observations_for_established=int(summary.get("minimum_observations_for_established", 12)),
        degraded_reason=summary.get("degraded_reason"),
        replaced_from_baseline_id=summary.get("replaced_from_baseline_id"),
        audit_refs=list(summary.get("audit_refs", [])),
    )
    for item in summary.get("spaces", []):
        state = SpaceBaselineState(
            space_id=item["space_id"],
            private_space=bool(item["private_space"]),
            enabled=bool(item["enabled"]),
            observation_count=int(item.get("observation_count", 0)),
            observed_signal_types=set(item.get("observed_signal_types", [])),
            confidence=float(item.get("confidence", 0.0)),
            last_observed_at=item.get("last_observed_at"),
        )
        # Summary records intentionally omit detailed aggregate ratios. For tool
        # classification only, infer minimal counts from known signal coverage.
        if "motion" in state.observed_signal_types:
            state.motion_seen_count = state.observation_count
        if "device_presence" in state.observed_signal_types:
            state.presence_seen_count = state.observation_count
        profile.spaces[state.space_id] = state
    return profile
