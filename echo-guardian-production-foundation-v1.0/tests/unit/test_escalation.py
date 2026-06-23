import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from echo_guardian_core.audit import AuditLog, utc_now_iso
from echo_guardian_core.escalation import (
    Contact,
    ContactSchemaError,
    EscalationEngine,
    EscalationMessage,
    FileOutboxNotificationProvider,
    load_contacts,
    validate_contact_schema,
)
from echo_guardian_core.policy import DEFAULT_PRODUCTION_POLICY_V02, ProductionPolicy

CONTACT_SCHEMA = Path("schemas/contact.schema.json")
ESCALATION_SCHEMA = Path("schemas/escalation-event.schema.json")


def live_policy():
    data = dict(DEFAULT_PRODUCTION_POLICY_V02)
    data.update(
        {
            "real_contact_notification_enabled": True,
            "authorized_contacts_configured": True,
            "successful_test_alert_completed": True,
        }
    )
    policy = ProductionPolicy(data)
    policy.validate()
    return policy


def default_policy():
    policy = ProductionPolicy(dict(DEFAULT_PRODUCTION_POLICY_V02))
    policy.validate()
    return policy


def valid_contact(**overrides):
    data = {
        "schema_version": "0.2",
        "contact_id": "contact-001",
        "display_name": "Safety Contact",
        "channel": "sms",
        "address": "+15555550100",
        "authorized": True,
        "test_alert_succeeded": True,
        "created_at": utc_now_iso(),
        "authorization_audit_ref": None,
        "test_alert_audit_ref": None,
        "minimum_disclosure_only": True,
    }
    data.update(overrides)
    return Contact.from_dict(data, schema_path=CONTACT_SCHEMA)


def validate_escalation_record(record):
    schema = json.loads(ESCALATION_SCHEMA.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(record), key=lambda e: list(e.path))
    assert errors == []


class FailingProvider:
    def send(self, contact, message):
        raise RuntimeError("provider unavailable")


def test_contact_schema_accepts_valid_contact():
    contact = valid_contact()
    assert contact.authorized is True


def test_contact_schema_rejects_non_minimal_disclosure():
    data = valid_contact().to_dict()
    data["minimum_disclosure_only"] = False
    with pytest.raises(ContactSchemaError):
        validate_contact_schema(data, CONTACT_SCHEMA)


def test_load_contacts_from_file(tmp_path):
    path = tmp_path / "contacts.json"
    path.write_text(json.dumps([valid_contact().to_dict()]), encoding="utf-8")
    contacts = load_contacts(path, CONTACT_SCHEMA)
    assert len(contacts) == 1
    assert contacts[0].contact_id == "contact-001"


def test_contact_authorization_record_is_audited(tmp_path):
    audit = AuditLog.open(tmp_path / "audit.jsonl")
    engine = EscalationEngine(policy=live_policy(), audit_log=audit, provider=FileOutboxNotificationProvider(tmp_path / "outbox"))
    record = engine.create_contact_authorization_record(valid_contact())
    assert record["audit_ref"]
    loaded = AuditLog.open(tmp_path / "audit.jsonl")
    assert loaded.entries[-1]["event_type"] == "contact_authorization_recorded"
    assert loaded.verify() == []


def test_test_alert_writes_outbox_and_audit(tmp_path):
    audit = AuditLog.open(tmp_path / "audit.jsonl")
    engine = EscalationEngine(policy=live_policy(), audit_log=audit, provider=FileOutboxNotificationProvider(tmp_path / "outbox"))
    attempt = engine.send_test_alert(valid_contact())
    assert attempt.status == "delivered"
    assert list((tmp_path / "outbox").glob("*.json"))
    loaded = AuditLog.open(tmp_path / "audit.jsonl")
    assert [e["event_type"] for e in loaded.entries] == ["test_alert_attempted", "test_alert_delivered"]
    assert loaded.verify() == []


def test_live_escalation_blocked_until_policy_gates_ready_and_audited(tmp_path):
    audit = AuditLog.open(tmp_path / "audit.jsonl")
    engine = EscalationEngine(policy=default_policy(), audit_log=audit, provider=FileOutboxNotificationProvider(tmp_path / "outbox"))
    record = engine.send_guarded_live(
        contacts=[valid_contact()],
        message=EscalationMessage(
            severity="severe",
            reason="No response after safety confirmation prompt.",
            recommended_action="Please check on the user.",
            location_context="Home - living room",
        ),
    )
    assert record["delivery_status"] == "blocked"
    assert record["blocked_reason"] == "live_contact_gate_not_ready"
    validate_escalation_record(record)
    loaded = AuditLog.open(tmp_path / "audit.jsonl")
    assert loaded.entries[-1]["event_type"] == "escalation_blocked"
    assert loaded.verify() == []


def test_live_escalation_rejects_sensitive_payload_and_audits(tmp_path):
    audit = AuditLog.open(tmp_path / "audit.jsonl")
    engine = EscalationEngine(policy=live_policy(), audit_log=audit, provider=FileOutboxNotificationProvider(tmp_path / "outbox"))
    record = engine.send_guarded_live(
        contacts=[valid_contact()],
        message=EscalationMessage(
            severity="severe",
            reason="Contains sensitive details.",
            recommended_action="Please check on the user.",
            location_context="Home",
            sensitive_details_included=True,
        ),
    )
    assert record["delivery_status"] == "blocked"
    assert record["blocked_reason"] == "minimal_disclosure_required"
    loaded = AuditLog.open(tmp_path / "audit.jsonl")
    assert loaded.entries[-1]["event_type"] == "escalation_blocked"
    assert loaded.verify() == []


def test_live_escalation_delivers_minimal_payload_and_validates_schema(tmp_path):
    audit = AuditLog.open(tmp_path / "audit.jsonl")
    engine = EscalationEngine(policy=live_policy(), audit_log=audit, provider=FileOutboxNotificationProvider(tmp_path / "outbox"))
    record = engine.send_guarded_live(
        contacts=[valid_contact()],
        message=EscalationMessage(
            severity="severe",
            reason="No response after safety confirmation prompt.",
            recommended_action="Please check on the user.",
            location_context="Home - living room",
        ),
    )
    assert record["delivery_status"] == "delivered"
    assert record["emergency_services_used"] is False
    assert record["minimum_disclosure_enabled"] is True
    assert record["sensitive_details_included"] is False
    validate_escalation_record(record)
    loaded = AuditLog.open(tmp_path / "audit.jsonl")
    event_types = [e["event_type"] for e in loaded.entries]
    assert "escalation_attempted" in event_types
    assert event_types[-1] == "escalation_delivered"
    assert loaded.verify() == []


def test_delivery_failure_retries_and_audits(tmp_path):
    audit = AuditLog.open(tmp_path / "audit.jsonl")
    engine = EscalationEngine(policy=live_policy(), audit_log=audit, provider=FailingProvider(), max_retries=1)
    record = engine.send_guarded_live(
        contacts=[valid_contact()],
        message=EscalationMessage(
            severity="severe",
            reason="No response after safety confirmation prompt.",
            recommended_action="Please check on the user.",
            location_context="Home - living room",
        ),
    )
    assert record["delivery_status"] == "failed"
    loaded = AuditLog.open(tmp_path / "audit.jsonl")
    event_types = [e["event_type"] for e in loaded.entries]
    assert event_types.count("escalation_attempted") == 2
    assert "escalation_retrying" in event_types
    assert event_types[-1] == "escalation_failed"
    assert loaded.verify() == []
