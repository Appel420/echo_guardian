from pathlib import Path

import pytest

from echo_guardian_core.anomaly import (
    AnomalyPolicyViolation,
    AnomalySeverityClassifier,
    validate_classification_schema,
)
from echo_guardian_core.audit import AuditLog
from echo_guardian_core.baseline import BaselineLearningEngine
from echo_guardian_core.policy import DEFAULT_PRODUCTION_POLICY_V02, ProductionPolicy
from echo_guardian_core.sensor import DeviceSignalSample, SensorIngestionEngine


def policy() -> ProductionPolicy:
    return ProductionPolicy(dict(DEFAULT_PRODUCTION_POLICY_V02))


def make_observation(tmp_path: Path, *, signal_type="motion", space_id="living_room", quality="good", metadata=None):
    sensor_audit = AuditLog.open(tmp_path / f"sensor-{space_id}-{signal_type}-{len(list(tmp_path.glob('sensor-*')))}.jsonl")
    engine = SensorIngestionEngine(policy=policy(), audit_log=sensor_audit)
    return engine.ingest(
        DeviceSignalSample(
            sensor_id=f"{signal_type}.adapter",
            signal_type=signal_type,  # type: ignore[arg-type]
            space_id=space_id,
            private_space=False,
            captured_at="2026-06-22T14:15:00Z",
            quality=quality,  # type: ignore[arg-type]
            derived_metadata=metadata or {"motion_detected": True, "confidence_scaled": 90},
        )
    )


def established_baseline(tmp_path: Path):
    audit = AuditLog.open(tmp_path / "baseline.jsonl")
    engine = BaselineLearningEngine(policy=policy(), audit_log=audit)
    engine.create_baseline()
    for i in range(12):
        signal_type = "motion" if i % 2 == 0 else "device_presence"
        metadata = {"motion_detected": i % 2 == 0, "presence_detected": i % 2 == 1, "confidence_scaled": 92}
        engine.ingest_observation(make_observation(tmp_path, signal_type=signal_type, metadata=metadata))
    assert engine.profile.status == "established"
    return engine.profile


def learning_baseline(tmp_path: Path):
    audit = AuditLog.open(tmp_path / "baseline-learning.jsonl")
    engine = BaselineLearningEngine(policy=policy(), audit_log=audit)
    engine.create_baseline()
    engine.ingest_observation(make_observation(tmp_path, metadata={"motion_detected": True, "confidence_scaled": 90}))
    assert engine.profile.status == "learning"
    return engine.profile


def test_classifies_normal_against_established_baseline(tmp_path: Path):
    baseline = established_baseline(tmp_path)
    audit = AuditLog.open(tmp_path / "classification.jsonl")
    classifier = AnomalySeverityClassifier(policy=policy(), audit_log=audit)
    record = classifier.classify(
        observation=make_observation(tmp_path, metadata={"motion_detected": True, "confidence_scaled": 91}),
        baseline=baseline,
    )

    assert record.severity == "normal"
    assert record.is_anomaly is False
    assert record.primary_reason_code == "matches_established_baseline"
    assert len(record.audit_refs) == 1
    assert audit.entries[-1]["event_type"] == "severity_classified"
    assert audit.verify() == []


def test_expected_motion_absent_is_concerning_when_baseline_established(tmp_path: Path):
    baseline = established_baseline(tmp_path)
    audit = AuditLog.open(tmp_path / "classification.jsonl")
    classifier = AnomalySeverityClassifier(policy=policy(), audit_log=audit)
    record = classifier.classify(
        observation=make_observation(
            tmp_path,
            metadata={"motion_detected": False, "expected_activity_window": True, "confidence_scaled": 93},
        ),
        baseline=baseline,
    )

    assert record.severity == "concerning"
    assert record.is_anomaly is True
    assert record.primary_reason_code == "expected_motion_absent"
    assert [entry["event_type"] for entry in audit.entries] == ["anomaly_detected", "severity_classified"]
    assert "expected movement" in record.plain_language_explanation.lower()
    assert audit.verify() == []


def test_learning_baseline_caps_weak_deviation_to_unusual(tmp_path: Path):
    baseline = learning_baseline(tmp_path)
    audit = AuditLog.open(tmp_path / "classification.jsonl")
    classifier = AnomalySeverityClassifier(policy=policy(), audit_log=audit)
    record = classifier.classify(
        observation=make_observation(
            tmp_path,
            metadata={"motion_detected": False, "expected_activity_window": True, "confidence_scaled": 88},
        ),
        baseline=baseline,
    )

    assert record.severity == "unusual"
    assert record.is_anomaly is True
    assert record.primary_reason_code == "possible_expected_motion_absent"
    assert "not strong enough" in record.plain_language_explanation
    assert audit.verify() == []


def test_fall_like_pattern_is_severe_with_established_baseline(tmp_path: Path):
    baseline = established_baseline(tmp_path)
    audit = AuditLog.open(tmp_path / "classification.jsonl")
    classifier = AnomalySeverityClassifier(policy=policy(), audit_log=audit)
    record = classifier.classify(
        observation=make_observation(
            tmp_path,
            metadata={"fall_like_event": True, "confidence_scaled": 95},
        ),
        baseline=baseline,
    )

    assert record.severity == "severe"
    assert record.primary_reason_code == "fall_like_pattern"
    assert "fall-like" in record.plain_language_explanation
    assert audit.verify() == []


def test_critical_signal_can_reach_emergency_when_established(tmp_path: Path):
    baseline = established_baseline(tmp_path)
    audit = AuditLog.open(tmp_path / "classification.jsonl")
    classifier = AnomalySeverityClassifier(policy=policy(), audit_log=audit)
    record = classifier.classify(
        observation=make_observation(
            tmp_path,
            metadata={"critical_safety_signal": True, "confidence_scaled": 98},
        ),
        baseline=baseline,
    )

    assert record.severity == "emergency"
    assert record.primary_reason_code == "explicit_critical_safety_signal"
    assert record.recommended_next_action.startswith("Request confirmation")
    assert audit.verify() == []


def test_schema_accepts_classification_record(tmp_path: Path):
    baseline = established_baseline(tmp_path)
    audit = AuditLog.open(tmp_path / "classification.jsonl")
    classifier = AnomalySeverityClassifier(policy=policy(), audit_log=audit)
    record = classifier.classify(observation=make_observation(tmp_path), baseline=baseline)
    validate_classification_schema(record.to_dict(), "schemas/severity-classification.schema.json")


def test_private_space_classification_is_rejected(tmp_path: Path):
    baseline = established_baseline(tmp_path)
    observation = make_observation(tmp_path)
    bad = observation.__class__(**{**observation.to_dict(), "space_id": "bedroom", "private_space": True})
    classifier = AnomalySeverityClassifier(policy=policy(), audit_log=AuditLog.open(tmp_path / "classification.jsonl"))
    with pytest.raises(AnomalyPolicyViolation, match="private-space"):
        classifier.classify(observation=bad, baseline=baseline)


def test_raw_like_metadata_is_rejected(tmp_path: Path):
    baseline = established_baseline(tmp_path)
    observation = make_observation(tmp_path)
    bad = observation.__class__(**{**observation.to_dict(), "derived_metadata": {"samples": [1, 2, 3]}})
    classifier = AnomalySeverityClassifier(policy=policy(), audit_log=AuditLog.open(tmp_path / "classification.jsonl"))
    with pytest.raises(AnomalyPolicyViolation, match="raw-like"):
        classifier.classify(observation=bad, baseline=baseline)
