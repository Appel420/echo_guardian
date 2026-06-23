import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from echo_guardian_core.audit import AuditLog
from echo_guardian_core.policy import (
    DEFAULT_PRODUCTION_POLICY_V02,
    PolicyEngine,
    PolicySchemaError,
    PolicyViolation,
    ProductionPolicy,
)


SCHEMA_PATH = Path("schemas/policy.schema.json")


def make_engine(tmp_path, overrides=None):
    data = dict(DEFAULT_PRODUCTION_POLICY_V02)
    if overrides:
        data.update(overrides)
    policy = ProductionPolicy(data)
    policy.validate_schema(SCHEMA_PATH)
    return PolicyEngine(policy, AuditLog.open(tmp_path / "audit.jsonl"))


def test_default_policy_validates_against_schema_and_product_rules():
    p = ProductionPolicy(dict(DEFAULT_PRODUCTION_POLICY_V02))
    p.validate_schema(SCHEMA_PATH)
    p.validate()


def test_policy_loader_validates_schema_and_loads_example():
    p = ProductionPolicy.load_file("examples/local-live-personal/production_policy_v0.2.json", schema_path=SCHEMA_PATH)
    assert p.data["schema_version"] == "0.2"


def test_schema_rejects_missing_policy_id():
    p = dict(DEFAULT_PRODUCTION_POLICY_V02)
    p.pop("policy_id")
    with pytest.raises(PolicySchemaError):
        ProductionPolicy(p).validate_schema(SCHEMA_PATH)


def test_silent_telemetry_rejected():
    p = dict(DEFAULT_PRODUCTION_POLICY_V02)
    p["silent_telemetry_enabled"] = True
    with pytest.raises(PolicyViolation):
        ProductionPolicy(p).validate()


def test_cloud_dependency_rejected():
    p = dict(DEFAULT_PRODUCTION_POLICY_V02)
    p["cloud_dependency_for_core_loop"] = True
    with pytest.raises(PolicyViolation):
        ProductionPolicy(p).validate()


def test_private_space_flags_rejected():
    for key in ["private_space_monitoring_enabled", "bathroom_monitoring_enabled", "bedroom_monitoring_enabled"]:
        p = dict(DEFAULT_PRODUCTION_POLICY_V02)
        p[key] = True
        with pytest.raises(PolicyViolation):
            ProductionPolicy(p).validate()


def test_record_policy_loaded_writes_audit_entry(tmp_path):
    engine = make_engine(tmp_path)
    entry = engine.record_policy_loaded()
    assert entry["event_type"] == "policy_loaded"
    assert AuditLog.open(tmp_path / "audit.jsonl").verify() == []


def test_consent_record_creation_writes_audit_entry(tmp_path):
    engine = make_engine(tmp_path)
    record = engine.create_consent_record(scope="space", granted=True, space_id="living_room")
    assert record["schema_version"] == "0.2"
    assert record["audit_ref"]
    loaded = AuditLog.open(tmp_path / "audit.jsonl")
    assert loaded.entries[-1]["event_type"] == "consent_recorded"
    assert loaded.verify() == []


def test_private_space_consent_is_hard_blocked(tmp_path):
    engine = make_engine(tmp_path)
    with pytest.raises(PolicyViolation):
        engine.create_consent_record(scope="space", granted=True, space_id="bedroom")


def test_authorize_monitoring_non_private_space_writes_audit(tmp_path):
    engine = make_engine(tmp_path)
    decision = engine.authorize_monitoring_state(
        space_id="living_room",
        private_space=False,
        enabled=True,
        signal_types=["motion", "device_presence"],
    )
    assert decision.authorized is True
    assert decision.audit_entry_id
    assert AuditLog.open(tmp_path / "audit.jsonl").verify() == []


def test_authorize_monitoring_private_space_denied_and_audited(tmp_path):
    engine = make_engine(tmp_path)
    decision = engine.authorize_monitoring_state(
        space_id="bathroom",
        private_space=True,
        enabled=True,
        signal_types=["motion"],
    )
    assert decision.authorized is False
    assert decision.reason_code == "private_space_hard_block"
    loaded = AuditLog.open(tmp_path / "audit.jsonl")
    assert loaded.entries[-1]["event_type"] == "monitoring_authorization_denied"
    assert loaded.verify() == []


def test_live_escalation_denied_until_contacts_and_test_alert_ready(tmp_path):
    engine = make_engine(tmp_path)
    decision = engine.authorize_live_escalation(severity="severe", contact_count=1)
    assert decision.authorized is False
    assert decision.reason_code == "live_contact_gate_not_ready"
    assert AuditLog.open(tmp_path / "audit.jsonl").verify() == []


def test_live_escalation_policy_validation_requires_guarded_gates():
    p = dict(DEFAULT_PRODUCTION_POLICY_V02)
    p["real_contact_notification_enabled"] = True
    p["authorized_contacts_configured"] = True
    p["successful_test_alert_completed"] = False
    with pytest.raises(PolicyViolation):
        ProductionPolicy(p).validate()


def test_live_escalation_authorized_when_guarded_gates_complete(tmp_path):
    engine = make_engine(
        tmp_path,
        {
            "real_contact_notification_enabled": True,
            "authorized_contacts_configured": True,
            "successful_test_alert_completed": True,
        },
    )
    decision = engine.authorize_live_escalation(severity="severe", contact_count=1)
    assert decision.authorized is True
    loaded = AuditLog.open(tmp_path / "audit.jsonl")
    assert loaded.entries[-1]["event_type"] == "live_escalation_authorized"
    assert loaded.verify() == []
