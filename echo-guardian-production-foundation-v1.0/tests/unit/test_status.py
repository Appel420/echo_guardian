from pathlib import Path

import pytest

from echo_guardian_core.audit import AuditLog
from echo_guardian_core.policy import DEFAULT_PRODUCTION_POLICY_V02, ProductionPolicy
from echo_guardian_core.status import (
    AlertPreview,
    InterfaceDegradation,
    LocalStatusInterface,
    SpaceStatus,
    StatusPolicyViolation,
    validate_status_schema,
)


def policy() -> ProductionPolicy:
    return ProductionPolicy(dict(DEFAULT_PRODUCTION_POLICY_V02))


def make_interface(tmp_path: Path) -> LocalStatusInterface:
    return LocalStatusInterface(policy=policy(), audit_log=AuditLog.open(tmp_path / "status.jsonl"))


def test_status_explains_monitoring_off_in_plain_language(tmp_path: Path):
    interface = make_interface(tmp_path)
    report = interface.generate_status_report(
        spaces=[SpaceStatus("living_room", "living room", False, False, [])]
    )

    assert report.monitoring_enabled is False
    assert "monitoring is off" in report.monitoring_explanation.lower()
    assert "not watching" in report.monitoring_explanation.lower()
    assert "what i am doing" in report.what_are_you_doing_response.lower()
    assert AuditLog.open(tmp_path / "status.jsonl").entries[-1]["event_type"] == "status_checked"
    assert AuditLog.open(tmp_path / "status.jsonl").verify() == []


def test_status_explains_active_spaces_signals_and_authority(tmp_path: Path):
    interface = make_interface(tmp_path)
    report = interface.generate_status_report(
        spaces=[
            SpaceStatus("living_room", "living room", True, False, ["motion", "device_presence"], "user"),
            SpaceStatus("kitchen", "kitchen", False, False, []),
        ]
    )

    assert report.monitoring_enabled is True
    assert "living room" in report.active_spaces_explanation
    assert "kitchen" in report.active_spaces_explanation
    assert "movement" in report.signal_types_explanation
    assert "nearby device presence" in report.signal_types_explanation
    assert "You control this setting" in report.authority_explanation
    assert report.hidden_behavior_present is False


def test_status_schema_accepts_report(tmp_path: Path):
    interface = make_interface(tmp_path)
    report = interface.generate_status_report(
        spaces=[SpaceStatus("living_room", "living room", True, False, ["motion"], "user")]
    )
    validate_status_schema(report.to_dict(), "schemas/local-status.schema.json")


def test_private_space_enabled_is_rejected(tmp_path: Path):
    interface = make_interface(tmp_path)
    with pytest.raises(StatusPolicyViolation, match="private-space"):
        interface.generate_status_report(
            spaces=[SpaceStatus("bedroom", "bedroom", True, True, ["motion"], "user")]
        )


def test_enabled_space_without_visible_signal_type_is_rejected(tmp_path: Path):
    interface = make_interface(tmp_path)
    with pytest.raises(StatusPolicyViolation, match="signal type"):
        interface.generate_status_report(
            spaces=[SpaceStatus("living_room", "living room", True, False, [], "user")]
        )


def test_degraded_state_is_explained_and_audited(tmp_path: Path):
    interface = make_interface(tmp_path)
    degradation = InterfaceDegradation(
        component="voice",
        health_state="degraded",
        plain_language="Voice is not working right now, so Echo Guardian will use text or touch.",
        user_action="Check microphone permission when you can.",
    )
    record = interface.record_interface_degradation(degradation)
    report = interface.generate_status_report(
        spaces=[SpaceStatus("living_room", "living room", True, False, ["motion"], "user")],
        degradations=[degradation],
    )

    assert record["audit_ref"]
    assert "Voice is not working" in report.degraded_state_explanation
    events = [e["event_type"] for e in AuditLog.open(tmp_path / "status.jsonl").entries]
    assert events == ["interface_degraded", "status_checked"]
    assert AuditLog.open(tmp_path / "status.jsonl").verify() == []


def test_alert_preview_is_minimal_and_clear(tmp_path: Path):
    interface = make_interface(tmp_path)
    preview = AlertPreview(
        severity="severe",
        reason="No response after safety confirmation prompt.",
        location_context="Home - living room",
        recommended_action="Please check on the user.",
        sensitive_details_included=False,
        emergency_services_used=False,
    )
    report = interface.generate_status_report(
        spaces=[SpaceStatus("living_room", "living room", True, False, ["motion"], "user")],
        alert_preview=preview,
    )

    assert "Preview alert" in report.alert_preview_text
    assert "No sensitive details" in report.alert_preview_text
    assert "Emergency services are not contacted by default" in report.alert_preview_text


def test_what_are_you_doing_response_contains_core_visibility_items(tmp_path: Path):
    interface = make_interface(tmp_path)
    report = interface.generate_status_report(
        spaces=[SpaceStatus("living_room", "living room", True, False, ["motion"], "user")]
    )

    text = report.what_are_you_doing_response.lower()
    assert "here is what i am doing" in text
    assert "monitoring is on" in text
    assert "living room" in text
    assert "movement" in text
    assert "safety contacts" in text
