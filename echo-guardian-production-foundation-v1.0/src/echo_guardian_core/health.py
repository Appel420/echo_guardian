from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4
import json

from jsonschema import Draft202012Validator

from .audit import AuditEntryInput, AuditLog, utc_now_iso
from .escalation import Contact
from .policy import ProductionPolicy, PolicyViolation
from .sensor import SensorCapability
from .status import InterfaceDegradation
from .storage import LocalStoragePaths

HealthState = Literal["healthy", "degraded", "critical", "unavailable", "unknown"]
ComponentType = Literal[
    "sensor",
    "storage",
    "audit",
    "policy",
    "interface",
    "contact_escalation",
]


class HealthSchemaError(ValueError):
    """Raised when a health report fails JSON Schema validation."""


class ReadinessBlocked(PermissionError):
    """Raised when Echo Guardian is not ready to enter active monitoring."""


class HealthPolicyViolation(PolicyViolation):
    """Raised when health input violates product safety rules."""


@dataclass(frozen=True)
class ComponentHealth:
    component_type: ComponentType
    component_id: str
    display_name: str
    state: HealthState
    required_for_active_monitoring: bool
    plain_language: str
    user_action: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    checked_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class OperationalReadinessReport:
    schema_version: str
    health_id: str
    created_at: str
    overall_state: HealthState
    ready_for_active_monitoring: bool
    blocking_reasons: list[str]
    components: list[dict[str, Any]]
    plain_language_summary: str
    audit_ref: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


STATE_RANK: dict[str, int] = {
    "healthy": 0,
    "degraded": 1,
    "unknown": 2,
    "critical": 3,
    "unavailable": 4,
}


class HealthMonitor:
    """Operational health and readiness gate for Echo Guardian.

    The health monitor aggregates sensors, storage, audit integrity, policy state,
    interface state, and guarded escalation readiness. It gives a simple plain-
    language answer and blocks active monitoring when required safety-path
    components are critical, unavailable, unknown, or degraded beyond policy.
    """

    def __init__(self, *, policy: ProductionPolicy, audit_log: AuditLog):
        policy.validate()
        self.policy = policy
        self.audit_log = audit_log

    def component_from_sensor(self, capability: SensorCapability) -> ComponentHealth:
        state: HealthState = capability.availability_state
        if capability.permission_state != "granted":
            state = "unavailable" if capability.permission_state in {"denied", "unavailable"} else "degraded"
        return ComponentHealth(
            component_type="sensor",
            component_id=capability.sensor_id,
            display_name=capability.display_name,
            state=state,
            required_for_active_monitoring=True,
            plain_language=capability.plain_language,
            user_action=(
                "Check device permission for this signal."
                if capability.permission_state != "granted"
                else None
            ),
            details={
                "signal_type": capability.signal_type,
                "permission_state": capability.permission_state,
                "availability_state": capability.availability_state,
                "private_space_capable": capability.private_space_capable,
            },
        )

    def component_from_storage_paths(self, paths: LocalStoragePaths) -> ComponentHealth:
        try:
            paths.assert_separate()
            required_dirs = [paths.operational, paths.audit, paths.export]
            missing = [str(p) for p in required_dirs if not p.exists()]
            state: HealthState = "healthy" if not missing else "critical"
            language = (
                "Local storage is separated and available."
                if not missing
                else "One or more local storage areas are missing."
            )
            details = {
                "operational_path": str(paths.operational),
                "audit_path": str(paths.audit),
                "export_path": str(paths.export),
                "missing_paths": missing,
            }
        except Exception as exc:
            state = "critical"
            language = "Local storage paths are not safely separated."
            details = {"error": str(exc)}
        return ComponentHealth(
            component_type="storage",
            component_id="local_storage",
            display_name="local storage",
            state=state,
            required_for_active_monitoring=True,
            plain_language=language,
            user_action="Repair local storage before turning monitoring on." if state != "healthy" else None,
            details=details,
        )

    def component_from_audit_log(self, audit_log: AuditLog | None = None) -> ComponentHealth:
        log = audit_log or self.audit_log
        errors = log.verify()
        if errors:
            return ComponentHealth(
                component_type="audit",
                component_id="audit_log",
                display_name="audit log",
                state="critical",
                required_for_active_monitoring=True,
                plain_language="The safety history could not be verified.",
                user_action="Do not turn monitoring on until the audit log is reviewed.",
                details={"errors": errors, "entry_count": len(log.entries)},
            )
        return ComponentHealth(
            component_type="audit",
            component_id="audit_log",
            display_name="audit log",
            state="healthy",
            required_for_active_monitoring=True,
            plain_language="The safety history is protected and verifies correctly.",
            details={"entry_count": len(log.entries)},
        )

    def component_from_policy(self) -> ComponentHealth:
        try:
            self.policy.validate()
            return ComponentHealth(
                component_type="policy",
                component_id=str(self.policy.policy_id),
                display_name="local policy",
                state="healthy",
                required_for_active_monitoring=True,
                plain_language="The local safety policy is valid and keeps private spaces blocked by default.",
                details={
                    "policy_id": self.policy.policy_id,
                    "policy_version": self.policy.policy_version,
                    "private_space_monitoring_enabled": self.policy.data.get("private_space_monitoring_enabled"),
                    "silent_telemetry_enabled": self.policy.data.get("silent_telemetry_enabled"),
                },
            )
        except Exception as exc:
            return ComponentHealth(
                component_type="policy",
                component_id="policy_invalid",
                display_name="local policy",
                state="critical",
                required_for_active_monitoring=True,
                plain_language="The local safety policy is not valid.",
                user_action="Fix the policy before turning monitoring on.",
                details={"error": str(exc)},
            )

    def component_from_interface_degradation(self, degradation: InterfaceDegradation) -> ComponentHealth:
        return ComponentHealth(
            component_type="interface",
            component_id=degradation.component,
            display_name=degradation.component,
            state=degradation.health_state,
            required_for_active_monitoring=True,
            plain_language=degradation.plain_language,
            user_action=degradation.user_action,
            details={},
        )

    def component_from_contacts(self, contacts: list[Contact]) -> ComponentHealth:
        if self.policy.data.get("emergency_services_enabled") is True:
            return ComponentHealth(
                component_type="contact_escalation",
                component_id="emergency_services",
                display_name="emergency services",
                state="critical",
                required_for_active_monitoring=False,
                plain_language="Emergency services are enabled, but they are not allowed by default in v0.2.",
                user_action="Disable emergency services unless a reviewed deployment policy explicitly permits them.",
                details={"emergency_services_enabled": True},
            )

        if self.policy.data.get("real_contact_notification_enabled") is not True:
            return ComponentHealth(
                component_type="contact_escalation",
                component_id="live_contacts",
                display_name="safety contacts",
                state="degraded",
                required_for_active_monitoring=False,
                plain_language="Live safety contact alerts are not enabled yet. Local monitoring can still work, but outside help will not be contacted.",
                user_action="Add authorized contacts and complete a test alert before relying on live alerts.",
                details={"contact_count": len(contacts), "live_contact_ready": False},
            )

        authorized = [c for c in contacts if c.authorized and c.test_alert_succeeded]
        if not authorized or not self.policy.live_contact_ready:
            return ComponentHealth(
                component_type="contact_escalation",
                component_id="live_contacts",
                display_name="safety contacts",
                state="critical",
                required_for_active_monitoring=False,
                plain_language="Live safety contact alerts are turned on, but the contact setup is not ready.",
                user_action="Authorize contacts and complete a successful test alert.",
                details={
                    "contact_count": len(contacts),
                    "ready_contact_count": len(authorized),
                    "live_contact_ready": self.policy.live_contact_ready,
                },
            )

        return ComponentHealth(
            component_type="contact_escalation",
            component_id="live_contacts",
            display_name="safety contacts",
            state="healthy",
            required_for_active_monitoring=False,
            plain_language="Live safety contacts are configured and tested.",
            details={"contact_count": len(contacts), "ready_contact_count": len(authorized), "live_contact_ready": True},
        )

    def generate_report(self, *, components: list[ComponentHealth]) -> OperationalReadinessReport:
        if not components:
            raise HealthPolicyViolation("health report requires at least one component")
        overall_state = self._overall_state(components)
        blocking = self._blocking_reasons(components)
        ready = not blocking
        plain = self._plain_language_summary(overall_state, ready, blocking, components)
        entry = self.audit_log.append(
            AuditEntryInput(
                event_type="operational_health_checked" if ready else "operational_readiness_failed",
                severity="normal" if ready else "concerning",
                authority_context="system_internal",
                policy_id=self.policy.policy_id,
                policy_version=self.policy.policy_version,
                public_context={
                    "space_id": "system",
                    "private_space": False,
                    "signal_types": ["system"],
                    "plain_language": plain,
                    "overall_state": overall_state,
                    "ready_for_active_monitoring": ready,
                    "blocking_reasons": blocking,
                },
            )
        )
        return OperationalReadinessReport(
            schema_version="0.2",
            health_id=str(uuid4()),
            created_at=utc_now_iso(),
            overall_state=overall_state,
            ready_for_active_monitoring=ready,
            blocking_reasons=blocking,
            components=[c.to_dict() for c in components],
            plain_language_summary=plain,
            audit_ref=entry["audit_entry_id"],
        )

    def assert_ready_for_active_monitoring(self, report: OperationalReadinessReport) -> None:
        if not report.ready_for_active_monitoring:
            raise ReadinessBlocked("Active monitoring is blocked: " + "; ".join(report.blocking_reasons))

    @staticmethod
    def _overall_state(components: list[ComponentHealth]) -> HealthState:
        worst = max(components, key=lambda c: STATE_RANK[c.state]).state
        return worst

    @staticmethod
    def _blocking_reasons(components: list[ComponentHealth]) -> list[str]:
        blocking: list[str] = []
        for c in components:
            if c.required_for_active_monitoring and c.state != "healthy":
                blocking.append(f"{c.display_name}: {c.plain_language}")
        return blocking

    @staticmethod
    def _plain_language_summary(
        overall_state: HealthState,
        ready: bool,
        blocking: list[str],
        components: list[ComponentHealth],
    ) -> str:
        if ready:
            if overall_state == "healthy":
                return "Echo Guardian is ready for active local monitoring. Core safety parts are working."
            return "Echo Guardian can run local monitoring, but some non-blocking parts need attention."
        visible = "; ".join(blocking)
        return "Echo Guardian is not ready to turn monitoring on yet. " + visible


def validate_health_schema(data: dict[str, Any], schema_path: str | Path) -> None:
    schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
    if errors:
        first = errors[0]
        path = "/".join(str(p) for p in first.path) or "<root>"
        raise HealthSchemaError(f"health status schema validation failed at {path}: {first.message}")
