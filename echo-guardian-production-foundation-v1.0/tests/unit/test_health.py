from pathlib import Path

import pytest

from echo_guardian_core.audit import AuditEntryInput, AuditLog
from echo_guardian_core.escalation import Contact
from echo_guardian_core.health import HealthMonitor, ReadinessBlocked, validate_health_schema
from echo_guardian_core.policy import DEFAULT_PRODUCTION_POLICY_V02, ProductionPolicy
from echo_guardian_core.sensor import SensorCapability
from echo_guardian_core.status import InterfaceDegradation
from echo_guardian_core.storage import LocalStoragePaths


def policy(extra=None) -> ProductionPolicy:
    data = dict(DEFAULT_PRODUCTION_POLICY_V02)
    if extra:
        data.update(extra)
    return ProductionPolicy(data)


def make_monitor(tmp_path: Path, extra=None) -> HealthMonitor:
    return HealthMonitor(policy=policy(extra), audit_log=AuditLog.open(tmp_path / "health.jsonl"))


def test_health_report_ready_when_core_components_healthy(tmp_path: Path):
    audit = AuditLog.open(tmp_path / "health.jsonl")
    monitor = HealthMonitor(policy=policy(), audit_log=audit)
    paths = LocalStoragePaths.create(tmp_path / "stores")
    sensor = SensorCapability(
        sensor_id="motion-1",
        signal_type="motion",
        display_name="living room movement",
        permission_state="granted",
        availability_state="healthy",
        plain_language="Living room movement signal is working.",
    )

    report = monitor.generate_report(
        components=[
            monitor.component_from_sensor(sensor),
            monitor.component_from_storage_paths(paths),
            monitor.component_from_audit_log(),
            monitor.component_from_policy(),
        ]
    )

    assert report.ready_for_active_monitoring is True
    assert report.overall_state == "healthy"
    assert "ready for active local monitoring" in report.plain_language_summary
    monitor.assert_ready_for_active_monitoring(report)
    validate_health_schema(report.to_dict(), "schemas/health-status.schema.json")
    assert AuditLog.open(tmp_path / "health.jsonl").verify() == []


def test_sensor_permission_denied_blocks_active_monitoring(tmp_path: Path):
    monitor = make_monitor(tmp_path)
    sensor = SensorCapability(
        sensor_id="motion-1",
        signal_type="motion",
        display_name="living room movement",
        permission_state="denied",
        availability_state="healthy",
        plain_language="Movement permission is not available.",
    )

    report = monitor.generate_report(
        components=[
            monitor.component_from_sensor(sensor),
            monitor.component_from_audit_log(),
            monitor.component_from_policy(),
        ]
    )

    assert report.ready_for_active_monitoring is False
    assert report.overall_state == "unavailable"
    assert any("movement" in reason.lower() for reason in report.blocking_reasons)
    with pytest.raises(ReadinessBlocked):
        monitor.assert_ready_for_active_monitoring(report)
    assert AuditLog.open(tmp_path / "health.jsonl").entries[-1]["event_type"] == "operational_readiness_failed"


def test_audit_health_detects_tampered_log(tmp_path: Path):
    audit_path = tmp_path / "health.jsonl"
    audit = AuditLog.open(audit_path)
    monitor = HealthMonitor(policy=policy(), audit_log=audit)
    audit.append(
        AuditEntryInput(
            event_type="test_event",
            severity="normal",
            authority_context="system_internal",
            public_context={
                "space_id": "system",
                "private_space": False,
                "signal_types": [],
                "plain_language": "Test event.",
            },
        )
    )
    text = audit_path.read_text(encoding="utf-8").replace("Test event.", "Tampered event.")
    audit_path.write_text(text, encoding="utf-8")
    tampered = AuditLog.open(audit_path)

    component = monitor.component_from_audit_log(tampered)

    assert component.state == "critical"
    assert "could not be verified" in component.plain_language


def test_nonblocking_contact_degradation_does_not_block_local_monitoring(tmp_path: Path):
    monitor = make_monitor(tmp_path)
    sensor = SensorCapability(
        sensor_id="motion-1",
        signal_type="motion",
        display_name="living room movement",
        permission_state="granted",
        availability_state="healthy",
        plain_language="Movement signal is working.",
    )
    report = monitor.generate_report(
        components=[
            monitor.component_from_sensor(sensor),
            monitor.component_from_audit_log(),
            monitor.component_from_policy(),
            monitor.component_from_contacts([]),
        ]
    )

    assert report.overall_state == "degraded"
    assert report.ready_for_active_monitoring is True
    assert "outside help will not be contacted" in report.components[-1]["plain_language"]


def test_live_contacts_ready_when_policy_and_contacts_are_ready(tmp_path: Path):
    monitor = make_monitor(
        tmp_path,
        {
            "real_contact_notification_enabled": True,
            "authorized_contacts_configured": True,
            "successful_test_alert_completed": True,
        },
    )
    contact = Contact(
        schema_version="0.2",
        contact_id="contact-1",
        display_name="Safety Contact",
        channel="sms",
        address="+15555550100",
        authorized=True,
        test_alert_succeeded=True,
        created_at="2026-06-22T14:15:00Z",
    )

    component = monitor.component_from_contacts([contact])

    assert component.state == "healthy"
    assert "configured and tested" in component.plain_language


def test_interface_critical_blocks_active_monitoring(tmp_path: Path):
    monitor = make_monitor(tmp_path)
    degradation = InterfaceDegradation(
        component="touch",
        health_state="critical",
        plain_language="Touch confirmation is not available.",
        user_action="Check screen access.",
    )
    report = monitor.generate_report(
        components=[
            monitor.component_from_audit_log(),
            monitor.component_from_policy(),
            monitor.component_from_interface_degradation(degradation),
        ]
    )

    assert report.ready_for_active_monitoring is False
    assert report.overall_state == "critical"
    assert "Touch confirmation" in report.plain_language_summary


def test_health_check_is_audited(tmp_path: Path):
    monitor = make_monitor(tmp_path)
    report = monitor.generate_report(
        components=[monitor.component_from_audit_log(), monitor.component_from_policy()]
    )

    events = [e["event_type"] for e in AuditLog.open(tmp_path / "health.jsonl").entries]
    assert events == ["operational_health_checked"]
    assert report.audit_ref
