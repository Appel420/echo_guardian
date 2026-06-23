from pathlib import Path

import pytest

from echo_guardian_core.audit import AuditLog
from echo_guardian_core.policy import ProductionPolicy, DEFAULT_PRODUCTION_POLICY_V02
from echo_guardian_core.sensor import (
    DeviceSignalSample,
    SensorCapability,
    SensorIngestionEngine,
    SensorPolicyViolation,
    validate_sensor_observation_schema,
)


class RealStyleMotionAdapter:
    """Test adapter shaped like a platform sensor adapter.

    The production contract is real adapter -> derived metadata -> no raw retention.
    Tests do not use this as production monitoring; they validate the boundary.
    """

    def capability(self):
        return SensorCapability(
            sensor_id="core_motion.activity",
            signal_type="motion",
            display_name="Device Motion Activity",
            permission_state="granted",
            availability_state="healthy",
            plain_language="Device motion activity is available.",
        )

    def read(self):
        return DeviceSignalSample(
            sensor_id="core_motion.activity",
            signal_type="motion",
            space_id="living_room",
            private_space=False,
            captured_at="2026-06-22T14:15:00Z",
            quality="good",
            derived_metadata={
                "motion_detected": True,
                "activity_bucket": "walking_or_moving",
                "confidence_scaled": 91,
            },
            raw_sample=None,
            permission_state="granted",
            availability_state="healthy",
        )


def policy() -> ProductionPolicy:
    return ProductionPolicy(dict(DEFAULT_PRODUCTION_POLICY_V02))


def test_ingests_derived_metadata_and_audits_observation(tmp_path: Path):
    audit = AuditLog.open(tmp_path / "audit.jsonl")
    engine = SensorIngestionEngine(policy=policy(), audit_log=audit)
    record = engine.ingest_from_adapter(RealStyleMotionAdapter())

    assert record.raw_sensor_retained is False
    assert record.derived_metadata["motion_detected"] is True
    assert "raw_sample" not in record.to_dict()
    assert audit.verify() == []
    assert [e["event_type"] for e in audit.entries] == ["sensor_available", "sensor_observation"]


def test_sensor_observation_schema_accepts_record(tmp_path: Path):
    audit = AuditLog.open(tmp_path / "audit.jsonl")
    engine = SensorIngestionEngine(policy=policy(), audit_log=audit)
    record = engine.ingest_from_adapter(RealStyleMotionAdapter())
    validate_sensor_observation_schema(record.to_dict(), "schemas/sensor-observation.schema.json")


def test_raw_sample_crossing_boundary_is_rejected(tmp_path: Path):
    audit = AuditLog.open(tmp_path / "audit.jsonl")
    engine = SensorIngestionEngine(policy=policy(), audit_log=audit)
    sample = DeviceSignalSample(
        sensor_id="microphone.level",
        signal_type="sound_level",
        space_id="living_room",
        private_space=False,
        captured_at="2026-06-22T14:15:00Z",
        quality="good",
        derived_metadata={"sound_level_bucket": "quiet"},
        raw_sample=b"raw audio must not cross",
    )
    with pytest.raises(SensorPolicyViolation, match="raw sensor samples"):
        engine.ingest(sample)


def test_forbidden_raw_derived_metadata_key_is_rejected(tmp_path: Path):
    audit = AuditLog.open(tmp_path / "audit.jsonl")
    engine = SensorIngestionEngine(policy=policy(), audit_log=audit)
    sample = DeviceSignalSample(
        sensor_id="microphone.level",
        signal_type="sound_level",
        space_id="living_room",
        private_space=False,
        captured_at="2026-06-22T14:15:00Z",
        quality="good",
        derived_metadata={"audio_buffer": "not allowed"},
    )
    with pytest.raises(SensorPolicyViolation, match="forbidden raw-data keys"):
        engine.ingest(sample)


def test_private_space_ingestion_is_hard_blocked(tmp_path: Path):
    audit = AuditLog.open(tmp_path / "audit.jsonl")
    engine = SensorIngestionEngine(policy=policy(), audit_log=audit)
    sample = DeviceSignalSample(
        sensor_id="core_motion.activity",
        signal_type="motion",
        space_id="bedroom",
        private_space=True,
        captured_at="2026-06-22T14:15:00Z",
        quality="good",
        derived_metadata={"motion_detected": True},
    )
    with pytest.raises(SensorPolicyViolation, match="private-space sensor ingestion"):
        engine.ingest(sample)


def test_permission_denied_creates_degraded_audit_state(tmp_path: Path):
    audit = AuditLog.open(tmp_path / "audit.jsonl")
    engine = SensorIngestionEngine(policy=policy(), audit_log=audit)
    health = engine.record_capability(
        SensorCapability(
            sensor_id="microphone.level",
            signal_type="sound_level",
            display_name="Sound Level",
            permission_state="denied",
            availability_state="unavailable",
            plain_language="Sound level monitoring permission is denied.",
        )
    )
    assert health["overall_state"] == "unavailable"
    assert audit.entries[-1]["event_type"] == "sensor_permission_changed"
    assert audit.entries[-1]["public_context"]["permission_state"] == "denied"
    assert audit.verify() == []


def test_degraded_observation_is_audited(tmp_path: Path):
    audit = AuditLog.open(tmp_path / "audit.jsonl")
    engine = SensorIngestionEngine(policy=policy(), audit_log=audit)
    sample = DeviceSignalSample(
        sensor_id="ble.presence",
        signal_type="device_presence",
        space_id="living_room",
        private_space=False,
        captured_at="2026-06-22T14:15:00Z",
        quality="partial",
        derived_metadata={"presence_detected": False, "confidence_scaled": 42},
        availability_state="degraded",
    )
    record = engine.ingest(sample)
    assert record.quality == "partial"
    assert audit.entries[-1]["event_type"] == "sensor_degraded"
    assert "less accurate" in audit.entries[-1]["public_context"]["plain_language"]
