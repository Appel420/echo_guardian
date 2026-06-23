from pathlib import Path

import pytest

from echo_guardian_core.audit import AuditLog
from echo_guardian_core.baseline import BaselineLearningEngine, BaselinePolicyViolation, validate_baseline_summary_schema
from echo_guardian_core.policy import DEFAULT_PRODUCTION_POLICY_V02, ProductionPolicy
from echo_guardian_core.sensor import DeviceSignalSample, SensorIngestionEngine


def policy() -> ProductionPolicy:
    return ProductionPolicy(dict(DEFAULT_PRODUCTION_POLICY_V02))


def observation(tmp_path: Path, *, space_id="living_room", private_space=False, signal_type="motion", quality="good", metadata=None):
    audit = AuditLog.open(tmp_path / f"sensor-{space_id}-{signal_type}.jsonl")
    engine = SensorIngestionEngine(policy=policy(), audit_log=audit)
    return engine.ingest(
        DeviceSignalSample(
            sensor_id=f"{signal_type}.adapter",
            signal_type=signal_type,  # type: ignore[arg-type]
            space_id=space_id,
            private_space=private_space,
            captured_at="2026-06-22T14:15:00Z",
            quality=quality,  # type: ignore[arg-type]
            derived_metadata=metadata or {"motion_detected": True, "confidence_scaled": 91},
        )
    )


def test_create_baseline_audits_creation(tmp_path: Path):
    audit = AuditLog.open(tmp_path / "audit.jsonl")
    engine = BaselineLearningEngine(policy=policy(), audit_log=audit)
    summary = engine.create_baseline()

    assert summary["status"] == "learning"
    assert summary["sensitive_details_included"] is False
    assert summary["total_observations"] == 0
    assert audit.entries[-1]["event_type"] == "baseline_created"
    assert audit.entries[-1]["public_context"]["raw_history_retained"] is False
    assert audit.verify() == []


def test_ingest_derived_observation_updates_local_profile(tmp_path: Path):
    audit = AuditLog.open(tmp_path / "audit.jsonl")
    engine = BaselineLearningEngine(policy=policy(), audit_log=audit)
    engine.create_baseline()
    record = observation(tmp_path)
    summary = engine.ingest_observation(record)

    assert summary["status"] == "learning"
    assert summary["total_observations"] == 1
    assert summary["spaces"][0]["space_id"] == "living_room"
    assert summary["spaces"][0]["observed_signal_types"] == ["motion"]
    assert summary["sensitive_details_included"] is False
    assert "minimized" in summary["plain_language_summary"]
    assert audit.entries[-1]["event_type"] == "baseline_updated"
    assert audit.verify() == []


def test_baseline_summary_schema_accepts_summary(tmp_path: Path):
    audit = AuditLog.open(tmp_path / "audit.jsonl")
    engine = BaselineLearningEngine(policy=policy(), audit_log=audit)
    engine.create_baseline()
    summary = engine.ingest_observation(observation(tmp_path))
    validate_baseline_summary_schema(summary, "schemas/baseline-summary.schema.json")


def test_baseline_becomes_established_after_enough_good_observations(tmp_path: Path):
    audit = AuditLog.open(tmp_path / "audit.jsonl")
    engine = BaselineLearningEngine(policy=policy(), audit_log=audit)
    engine.create_baseline()
    summary = None
    for i in range(12):
        signal_type = "motion" if i % 2 == 0 else "device_presence"
        metadata = {"motion_detected": i % 2 == 0, "presence_detected": i % 2 == 1, "confidence_scaled": 90}
        summary = engine.ingest_observation(observation(tmp_path, signal_type=signal_type, metadata=metadata))

    assert summary is not None
    assert summary["status"] == "established"
    assert summary["confidence"]["overall"] >= 0.65
    assert audit.verify() == []


def test_private_space_observation_is_rejected_by_baseline(tmp_path: Path):
    audit = AuditLog.open(tmp_path / "audit.jsonl")
    engine = BaselineLearningEngine(policy=policy(), audit_log=audit)
    # Construct directly to validate baseline guard even if a future ingestion bug existed.
    record = observation(tmp_path, space_id="living_room")
    bad = record.__class__(**{**record.to_dict(), "space_id": "bedroom", "private_space": True})
    with pytest.raises(BaselinePolicyViolation, match="private-space observations"):
        engine.ingest_observation(bad)


def test_raw_retention_record_is_rejected_by_baseline(tmp_path: Path):
    audit = AuditLog.open(tmp_path / "audit.jsonl")
    engine = BaselineLearningEngine(policy=policy(), audit_log=audit)
    record = observation(tmp_path)
    bad = record.__class__(**{**record.to_dict(), "raw_sensor_retained": True})
    with pytest.raises(BaselinePolicyViolation, match="retained raw sensor data"):
        engine.ingest_observation(bad)


def test_raw_like_metadata_is_rejected_by_baseline(tmp_path: Path):
    audit = AuditLog.open(tmp_path / "audit.jsonl")
    engine = BaselineLearningEngine(policy=policy(), audit_log=audit)
    record = observation(tmp_path)
    bad = record.__class__(**{**record.to_dict(), "derived_metadata": {"samples": [1, 2, 3]}})
    with pytest.raises(BaselinePolicyViolation, match="raw-like"):
        engine.ingest_observation(bad)


def test_degrade_reset_and_replace_are_audited(tmp_path: Path):
    audit = AuditLog.open(tmp_path / "audit.jsonl")
    engine = BaselineLearningEngine(policy=policy(), audit_log=audit)
    engine.create_baseline()
    degraded = engine.mark_degraded(reason="sensor quality dropped")
    assert degraded["status"] == "degraded"
    reset = engine.reset(reason="user requested relearning")
    assert reset["status"] == "reset"
    replaced = engine.replace(reason="new home layout")
    assert replaced["status"] == "replaced"
    assert [e["event_type"] for e in audit.entries][-3:] == ["baseline_degraded", "baseline_reset", "baseline_replaced"]
    assert audit.verify() == []
