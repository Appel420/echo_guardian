from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
import json

from echo_guardian_core.audit import AuditLog, utc_now_iso
from echo_guardian_core.escalation import Contact
from echo_guardian_core.integration import ProductionIntegrationRunner, IntegrationBlocked
from echo_guardian_core.policy import DEFAULT_PRODUCTION_POLICY_V02, ProductionPolicy
from echo_guardian_core.sensor import DeviceSignalSample
from echo_guardian_core.storage import LocalStoragePaths


def policy(**overrides):
    data = dict(DEFAULT_PRODUCTION_POLICY_V02)
    data.update(overrides)
    p = ProductionPolicy(data)
    p.validate()
    return p


def sample(**overrides):
    data = {
        "sensor_id": "core_motion.activity",
        "signal_type": "motion",
        "space_id": "living_room",
        "private_space": False,
        "captured_at": utc_now_iso(),
        "quality": "good",
        "derived_metadata": {"motion_detected": True, "confidence_scaled": 90},
        "raw_sample": None,
        "permission_state": "granted",
        "availability_state": "healthy",
    }
    data.update(overrides)
    return DeviceSignalSample(**data)


def contact():
    return Contact(
        schema_version="0.2",
        contact_id="contact-001",
        display_name="Safety Contact",
        channel="sms",
        address="+15555550100",
        authorized=True,
        test_alert_succeeded=True,
        created_at=utc_now_iso(),
        authorization_audit_ref=None,
        test_alert_audit_ref=None,
        minimum_disclosure_only=True,
    )


def runner(tmp_path, p=None, contacts=None):
    audit = AuditLog.open(tmp_path / "audit" / "cycle.jsonl")
    paths = LocalStoragePaths.create(tmp_path / "store")
    return ProductionIntegrationRunner(
        policy=p or policy(),
        audit_log=audit,
        storage_paths=paths,
        contacts=contacts or [],
        outbox_dir=tmp_path / "outbox",
    )


def test_production_cycle_runs_local_loop_and_verifies_audit(tmp_path: Path):
    result = runner(tmp_path).run_cycle(sample=sample(), confirmation_input="safe")
    assert result.policy_authorized is True
    assert result.readiness_passed is True
    assert result.observation["raw_sensor_retained"] is False
    assert result.classification["severity"] in {"normal", "unusual", "concerning", "severe", "emergency"}
    assert result.audit_verified is True
    assert result.no_cloud_dependency is True
    assert result.no_private_space_monitoring is True
    assert result.hidden_behavior_present is False
    assert "local safety check" in result.plain_language_summary


def test_production_cycle_schema_accepts_result(tmp_path: Path):
    result = runner(tmp_path).run_cycle(sample=sample(), confirmation_input="safe")
    schema = json.loads(Path("schemas/production-cycle-result.schema.json").read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(result.to_dict()), key=lambda e: list(e.path))
    assert errors == []


def test_private_space_blocked_before_monitoring(tmp_path: Path):
    with pytest.raises(IntegrationBlocked):
        runner(tmp_path).run_cycle(sample=sample(space_id="bedroom", private_space=True), confirmation_input="safe")


def test_unhealthy_sensor_blocks_readiness(tmp_path: Path):
    with pytest.raises(IntegrationBlocked):
        runner(tmp_path).run_cycle(sample=sample(permission_state="denied"), confirmation_input="safe")


def test_needs_help_runs_guarded_live_escalation_when_policy_ready(tmp_path: Path):
    p = policy(
        real_contact_notification_enabled=True,
        authorized_contacts_configured=True,
        successful_test_alert_completed=True,
    )
    # Explicit impact metadata makes the classifier request confirmation under the learning baseline.
    result = runner(tmp_path, p=p, contacts=[contact()]).run_cycle(
        sample=sample(derived_metadata={"impact_detected": True, "confidence_scaled": 95}),
        confirmation_input="needs_help",
    )
    assert result.confirmation is not None
    assert result.confirmation["final_result"] == "confirmed_needs_help"
    assert result.escalation is not None
    assert result.escalation["delivery_status"] == "delivered"
    assert result.audit_verified is True
    assert list((tmp_path / "outbox").glob("*.json"))


def test_timeout_blocks_escalation_when_live_contacts_not_ready_but_audits(tmp_path: Path):
    result = runner(tmp_path).run_cycle(
        sample=sample(derived_metadata={"impact_detected": True, "confidence_scaled": 95}),
        confirmation_input="timeout",
    )
    assert result.confirmation is not None
    assert result.confirmation["final_result"] == "timeout"
    assert result.escalation is not None
    assert result.escalation["delivery_status"] == "blocked"
    assert result.audit_verified is True
