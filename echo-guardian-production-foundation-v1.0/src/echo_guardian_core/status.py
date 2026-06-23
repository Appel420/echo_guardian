from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal
import json
from uuid import uuid4

from jsonschema import Draft202012Validator

from .audit import AuditEntryInput, AuditLog, utc_now_iso
from .policy import ProductionPolicy, PolicyViolation

HealthState = Literal["healthy", "degraded", "critical", "unavailable", "unknown"]
AuthorityLabel = Literal["user", "caregiver", "mdm", "system"]


class StatusSchemaError(ValueError):
    """Raised when a local status report fails schema validation."""


class StatusPolicyViolation(PolicyViolation):
    """Raised when status inputs violate Echo Guardian transparency rules."""


@dataclass(frozen=True)
class SpaceStatus:
    """User-visible monitoring status for a physical space."""

    space_id: str
    display_name: str
    enabled: bool
    private_space: bool
    signal_types: list[str]
    authority: AuthorityLabel = "user"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class InterfaceDegradation:
    """User-visible degraded interface or safety-path state."""

    component: str
    health_state: HealthState
    plain_language: str
    user_action: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AlertPreview:
    """Plain-language preview of what a safety contact would receive."""

    severity: str
    reason: str
    location_context: str
    recommended_action: str
    sensitive_details_included: bool = False
    emergency_services_used: bool = False

    def preview_text(self) -> str:
        sensitive = "No sensitive details are included." if not self.sensitive_details_included else "This alert includes sensitive details."
        emergency = "Emergency services are not contacted by default." if not self.emergency_services_used else "Emergency services may be contacted under the configured policy."
        return (
            f"Preview alert: {self.reason} Location: {self.location_context}. "
            f"Recommended action: {self.recommended_action} {sensitive} {emergency}"
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["preview_text"] = self.preview_text()
        return data


@dataclass(frozen=True)
class LocalStatusReport:
    schema_version: str
    status_id: str
    created_at: str
    monitoring_enabled: bool
    monitoring_explanation: str
    active_spaces_explanation: str
    signal_types_explanation: str
    authority_explanation: str
    degraded_state_explanation: str
    what_are_you_doing_response: str
    alert_preview_text: str
    spaces: list[dict[str, Any]]
    degradations: list[dict[str, Any]]
    audit_ref: str
    plain_language_level: str = "child_elderly_clear"
    hidden_behavior_present: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


SIGNAL_LABELS: dict[str, str] = {
    "motion": "movement",
    "device_presence": "nearby device presence",
    "sound_level": "sound level only, not recordings",
    "environmental": "environmental safety information",
    "accelerometer": "device movement",
    "gyroscope": "device rotation",
    "system": "system health",
    "simulated": "test signal",
}

AUTHORITY_LABELS: dict[str, str] = {
    "user": "You control this setting.",
    "caregiver": "A caregiver controls this setting with permission.",
    "mdm": "An organization policy controls this setting and it must stay visible.",
    "system": "Echo Guardian controls this automatically for local safety operation.",
}


class LocalStatusInterface:
    """Plain-language local status interface.

    This module is intentionally simple on the outside and strict underneath.
    Every status check is audit-recorded. Every degraded interface condition can
    be audit-recorded. The response is designed for child/elderly comprehension:
    monitoring on/off, where it is active, what signals are used, who controls it,
    what is broken, what an alert would say, and a direct answer to: "What are you doing?"
    """

    def __init__(self, *, policy: ProductionPolicy, audit_log: AuditLog):
        policy.validate()
        self.policy = policy
        self.audit_log = audit_log

    def generate_status_report(
        self,
        *,
        spaces: list[SpaceStatus],
        degradations: list[InterfaceDegradation] | None = None,
        alert_preview: AlertPreview | None = None,
    ) -> LocalStatusReport:
        self._validate_spaces(spaces)
        degradations = degradations or []
        monitoring_enabled = any(s.enabled for s in spaces)
        monitoring_explanation = self._monitoring_explanation(spaces)
        active_spaces_explanation = self._active_spaces_explanation(spaces)
        signal_types_explanation = self._signal_types_explanation(spaces)
        authority_explanation = self._authority_explanation(spaces)
        degraded_state_explanation = self._degraded_state_explanation(degradations)
        alert_preview_text = (
            alert_preview.preview_text()
            if alert_preview is not None
            else "No live alert preview is active. Safety contacts are only notified after the configured confirmation and escalation rules are met."
        )
        what = self._what_are_you_doing_response(
            monitoring_explanation=monitoring_explanation,
            active_spaces_explanation=active_spaces_explanation,
            signal_types_explanation=signal_types_explanation,
            degraded_state_explanation=degraded_state_explanation,
            alert_preview_text=alert_preview_text,
        )

        entry = self.audit_log.append(
            AuditEntryInput(
                event_type="status_checked",
                severity="normal" if not degradations else "unusual",
                authority_context="user_controlled",
                policy_id=self.policy.policy_id,
                policy_version=self.policy.policy_version,
                public_context={
                    "space_id": "interface",
                    "private_space": False,
                    "signal_types": [],
                    "plain_language": "The user-visible Echo Guardian status screen was checked.",
                    "monitoring_enabled": monitoring_enabled,
                    "degraded": bool(degradations),
                },
            )
        )
        return LocalStatusReport(
            schema_version="0.2",
            status_id=str(uuid4()),
            created_at=utc_now_iso(),
            monitoring_enabled=monitoring_enabled,
            monitoring_explanation=monitoring_explanation,
            active_spaces_explanation=active_spaces_explanation,
            signal_types_explanation=signal_types_explanation,
            authority_explanation=authority_explanation,
            degraded_state_explanation=degraded_state_explanation,
            what_are_you_doing_response=what,
            alert_preview_text=alert_preview_text,
            spaces=[s.to_dict() for s in spaces],
            degradations=[d.to_dict() for d in degradations],
            audit_ref=entry["audit_entry_id"],
        )

    def record_interface_degradation(self, degradation: InterfaceDegradation) -> dict[str, Any]:
        entry = self.audit_log.append(
            AuditEntryInput(
                event_type="interface_degraded",
                severity="unusual" if degradation.health_state == "degraded" else "concerning",
                authority_context="system_internal",
                policy_id=self.policy.policy_id,
                policy_version=self.policy.policy_version,
                public_context={
                    "space_id": "interface",
                    "private_space": False,
                    "signal_types": [],
                    "plain_language": degradation.plain_language,
                    "component": degradation.component,
                    "health_state": degradation.health_state,
                    "user_action": degradation.user_action,
                },
            )
        )
        return {
            "schema_version": "0.2",
            "degradation_id": str(uuid4()),
            "created_at": utc_now_iso(),
            "component": degradation.component,
            "health_state": degradation.health_state,
            "plain_language": degradation.plain_language,
            "user_action": degradation.user_action,
            "audit_ref": entry["audit_entry_id"],
        }

    def _validate_spaces(self, spaces: list[SpaceStatus]) -> None:
        for space in spaces:
            if space.private_space and space.enabled:
                raise StatusPolicyViolation("private-space monitoring cannot be shown as enabled in v0.2")
            if space.space_id in {"bathroom", "bedroom"} and space.enabled:
                raise StatusPolicyViolation("bathroom and bedroom monitoring are hard-blocked in v0.2")
            if space.enabled and not space.signal_types:
                raise StatusPolicyViolation("enabled spaces must show at least one signal type")
            if space.authority not in AUTHORITY_LABELS:
                raise StatusPolicyViolation("unknown authority label")

    @staticmethod
    def _monitoring_explanation(spaces: list[SpaceStatus]) -> str:
        active = [s.display_name for s in spaces if s.enabled]
        if not active:
            return "Echo Guardian monitoring is off. It is not watching any spaces right now."
        joined = _human_join(active)
        return f"Echo Guardian monitoring is on for {joined}."

    @staticmethod
    def _active_spaces_explanation(spaces: list[SpaceStatus]) -> str:
        active = [s.display_name for s in spaces if s.enabled]
        inactive = [s.display_name for s in spaces if not s.enabled]
        if not active:
            return "No spaces are being monitored."
        text = f"Active spaces: {_human_join(active)}."
        if inactive:
            text += f" Not monitored: {_human_join(inactive)}."
        return text

    @staticmethod
    def _signal_types_explanation(spaces: list[SpaceStatus]) -> str:
        parts: list[str] = []
        for space in spaces:
            if not space.enabled:
                continue
            labels = [SIGNAL_LABELS.get(sig, sig.replace("_", " ")) for sig in space.signal_types]
            parts.append(f"{space.display_name} uses {_human_join(labels)}")
        if not parts:
            return "No signal types are active."
        return "; ".join(parts) + "."

    @staticmethod
    def _authority_explanation(spaces: list[SpaceStatus]) -> str:
        active = [s for s in spaces if s.enabled]
        if not active:
            return "No active monitoring controls need authority right now."
        parts = [f"{s.display_name}: {AUTHORITY_LABELS[s.authority]}" for s in active]
        return " ".join(parts)

    @staticmethod
    def _degraded_state_explanation(degradations: list[InterfaceDegradation]) -> str:
        if not degradations:
            return "Everything needed for this local status view is working."
        parts = []
        for d in degradations:
            action = f" {d.user_action}" if d.user_action else ""
            parts.append(f"{d.component}: {d.plain_language}{action}")
        return "Some parts need attention. " + " ".join(parts)

    @staticmethod
    def _what_are_you_doing_response(
        *,
        monitoring_explanation: str,
        active_spaces_explanation: str,
        signal_types_explanation: str,
        degraded_state_explanation: str,
        alert_preview_text: str,
    ) -> str:
        return (
            f"Here is what I am doing: {monitoring_explanation} "
            f"{active_spaces_explanation} {signal_types_explanation} "
            f"{degraded_state_explanation} {alert_preview_text}"
        )


def _human_join(items: list[str]) -> str:
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} and {items[1]}"
    return ", ".join(items[:-1]) + f", and {items[-1]}"


def validate_status_schema(data: dict[str, Any], schema_path: str | Path) -> None:
    schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
    if errors:
        first = errors[0]
        path = "/".join(str(p) for p in first.path) or "<root>"
        raise StatusSchemaError(f"local status schema validation failed at {path}: {first.message}")
