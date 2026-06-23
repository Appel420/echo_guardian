from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4
import json

from jsonschema import Draft202012Validator

from .audit import AuditEntryInput, AuditLog, utc_now_iso


class PolicyViolation(ValueError):
    """Raised when a policy violates Echo Guardian production safety rules."""


class PolicySchemaError(PolicyViolation):
    """Raised when a policy fails JSON Schema validation."""


class AuthorizationDenied(PermissionError):
    """Raised when a requested state change is denied by policy."""


Authority = Literal["user", "legal_representative", "managed_policy"]
ConsentScope = Literal[
    "monitoring",
    "space",
    "signal_type",
    "contact_notification",
    "export",
    "diagnostic",
]


@dataclass(frozen=True)
class AuthorizationDecision:
    authorized: bool
    reason_code: str
    plain_language: str
    audit_entry_id: str | None = None


@dataclass(frozen=True)
class ProductionPolicy:
    data: dict[str, Any]

    @classmethod
    def load_file(cls, path: str | Path, schema_path: str | Path | None = None) -> "ProductionPolicy":
        p = Path(path)
        data = json.loads(p.read_text(encoding="utf-8"))
        policy = cls(data)
        if schema_path is not None:
            policy.validate_schema(schema_path)
        policy.validate()
        return policy

    def validate_schema(self, schema_path: str | Path) -> None:
        schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        errors = sorted(validator.iter_errors(self.data), key=lambda e: list(e.path))
        if errors:
            first = errors[0]
            path = "/".join(str(p) for p in first.path) or "<root>"
            raise PolicySchemaError(f"policy schema validation failed at {path}: {first.message}")

    def validate(self) -> None:
        """Validate non-negotiable production safety defaults.

        JSON Schema validates shape. This method validates Echo Guardian product laws:
        no hidden telemetry, no cloud dependency for the core loop, no default private
        spaces, no silent exports, and no live escalation unless guarded.
        """
        if self.data.get("silent_telemetry_enabled") is not False:
            raise PolicyViolation("silent telemetry must be disabled")
        if self.data.get("cloud_dependency_for_core_loop") is not False:
            raise PolicyViolation("core safety loop must not depend on cloud")
        if self.data.get("private_space_monitoring_enabled") is not False:
            raise PolicyViolation("private-space monitoring is hard-blocked by default")
        if self.data.get("bathroom_monitoring_enabled") is not False:
            raise PolicyViolation("bathroom monitoring is hard-blocked by default")
        if self.data.get("bedroom_monitoring_enabled") is not False:
            raise PolicyViolation("bedroom monitoring is hard-blocked by default")
        if self.data.get("export_requires_explicit_confirmation") is not True:
            raise PolicyViolation("export requires explicit confirmation")
        if self.data.get("diagnostic_upload_enabled") is not False:
            raise PolicyViolation("diagnostic upload must be disabled by default")
        if self.data.get("raw_sensor_retention") != "not_retained":
            raise PolicyViolation("raw sensor retention must default to not_retained")
        if self.data.get("local_audit_logging_enabled") is not True:
            raise PolicyViolation("local audit logging must be enabled")
        if self.data.get("real_sensor_ingestion_enabled") is not True:
            raise PolicyViolation("real sensor ingestion must be enabled for production foundation")
        if self.data.get("emergency_services_enabled") is not False:
            raise PolicyViolation("emergency services must not be enabled by default")

        if self.data.get("real_contact_notification_enabled") is True:
            if self.data.get("requires_contact_test_before_live_alerts") is not True:
                raise PolicyViolation("live contact notification requires successful test-alert gate")
            if self.data.get("authorized_contacts_configured") is not True:
                raise PolicyViolation("live contact notification requires configured authorized contacts")
            if self.data.get("successful_test_alert_completed") is not True:
                raise PolicyViolation("live contact notification requires successful test alert")

    @property
    def policy_id(self) -> str | None:
        return self.data.get("policy_id") or "production-local-v0.2"

    @property
    def policy_version(self) -> str | None:
        return self.data.get("policy_version") or self.data.get("schema_version")

    @property
    def live_contact_ready(self) -> bool:
        return bool(
            self.data.get("real_contact_notification_enabled") is True
            and self.data.get("requires_contact_test_before_live_alerts") is True
            and self.data.get("authorized_contacts_configured") is True
            and self.data.get("successful_test_alert_completed") is True
        )


class PolicyEngine:
    """Production local policy and consent enforcement.

    All state-changing authorization decisions are logged to the audit log. Denied
    requests are also audit-relevant because they prove the guardrail worked.
    """

    def __init__(self, policy: ProductionPolicy, audit_log: AuditLog):
        policy.validate()
        self.policy = policy
        self.audit_log = audit_log

    @classmethod
    def from_policy_file(
        cls,
        policy_path: str | Path,
        audit_log_path: str | Path,
        schema_path: str | Path | None = None,
    ) -> "PolicyEngine":
        policy = ProductionPolicy.load_file(policy_path, schema_path=schema_path)
        return cls(policy=policy, audit_log=AuditLog.open(audit_log_path))

    def record_policy_loaded(self) -> dict[str, Any]:
        return self.audit_log.append(
            AuditEntryInput(
                event_type="policy_loaded",
                severity="normal",
                authority_context="system_internal",
                policy_id=self.policy.policy_id,
                policy_version=self.policy.policy_version,
                public_context={
                    "space_id": "system",
                    "private_space": False,
                    "signal_types": [],
                    "plain_language": "Echo Guardian loaded the local production policy and verified its safety rules.",
                },
            )
        )

    def create_consent_record(
        self,
        *,
        scope: ConsentScope,
        granted: bool,
        authority: Authority = "user",
        space_id: str | None = None,
        signal_type: str | None = None,
        plain_language_summary: str | None = None,
    ) -> dict[str, Any]:
        if scope in {"space", "signal_type"} and not space_id:
            raise PolicyViolation(f"{scope} consent requires space_id")
        if scope == "signal_type" and not signal_type:
            raise PolicyViolation("signal_type consent requires signal_type")
        if authority != "user":
            raise PolicyViolation("v0.2 production foundation only accepts direct user consent")
        if space_id in {"bathroom", "bedroom"} and granted:
            raise PolicyViolation("private-space consent is hard-blocked in v0.2 production foundation")

        summary = plain_language_summary or self._default_consent_summary(scope, granted, space_id, signal_type)
        entry = self.audit_log.append(
            AuditEntryInput(
                event_type="consent_recorded",
                severity="normal",
                authority_context="user_controlled",
                policy_id=self.policy.policy_id,
                policy_version=self.policy.policy_version,
                public_context={
                    "space_id": space_id or "system",
                    "private_space": bool(space_id in {"bathroom", "bedroom"}),
                    "signal_types": [signal_type] if signal_type else [],
                    "plain_language": summary,
                },
            )
        )
        return {
            "schema_version": "0.2",
            "consent_id": str(uuid4()),
            "created_at": utc_now_iso(),
            "authority": authority,
            "scope": scope,
            "space_id": space_id,
            "signal_type": signal_type,
            "granted": granted,
            "plain_language_summary": summary,
            "audit_ref": entry["audit_entry_id"],
        }

    def authorize_monitoring_state(
        self,
        *,
        space_id: str,
        private_space: bool,
        enabled: bool,
        signal_types: list[str],
        authority: Authority = "user",
    ) -> AuthorizationDecision:
        if authority != "user":
            return self._deny(
                event_type="monitoring_authorization_denied",
                reason_code="unsupported_authority_v0_2",
                plain_language="Only direct user-controlled monitoring changes are supported in this production foundation build.",
                space_id=space_id,
                private_space=private_space,
                signal_types=signal_types,
            )
        if private_space or space_id in {"bathroom", "bedroom"}:
            return self._deny(
                event_type="monitoring_authorization_denied",
                reason_code="private_space_hard_block",
                plain_language="Bathroom and bedroom monitoring are blocked in this build and cannot be turned on by default.",
                space_id=space_id,
                private_space=True,
                signal_types=signal_types,
            )
        if enabled and not self.policy.data.get("monitoring_enabled", False):
            # v0.2 supports explicit per-action enabling even if global monitoring starts false.
            pass
        if enabled and not signal_types:
            return self._deny(
                event_type="monitoring_authorization_denied",
                reason_code="no_signal_types_requested",
                plain_language="Monitoring cannot be enabled without at least one visible signal type.",
                space_id=space_id,
                private_space=private_space,
                signal_types=signal_types,
            )
        entry = self.audit_log.append(
            AuditEntryInput(
                event_type="monitoring_authorized" if enabled else "monitoring_disabled",
                severity="normal",
                authority_context="user_controlled",
                policy_id=self.policy.policy_id,
                policy_version=self.policy.policy_version,
                public_context={
                    "space_id": space_id,
                    "private_space": private_space,
                    "signal_types": signal_types,
                    "plain_language": (
                        f"Monitoring is authorized for {space_id} using {', '.join(signal_types)}."
                        if enabled
                        else f"Monitoring is disabled for {space_id}."
                    ),
                },
            )
        )
        return AuthorizationDecision(
            authorized=True,
            reason_code="authorized",
            plain_language=entry["public_context"]["plain_language"],
            audit_entry_id=entry["audit_entry_id"],
        )

    def authorize_live_escalation(self, *, severity: str, contact_count: int) -> AuthorizationDecision:
        signal_types: list[str] = []
        if severity not in {"concerning", "severe", "emergency"}:
            return self._deny(
                event_type="live_escalation_authorization_denied",
                reason_code="severity_too_low",
                plain_language="Live escalation is not allowed for this severity level.",
                space_id="system",
                private_space=False,
                signal_types=signal_types,
                severity="normal",
            )
        if contact_count < 1:
            return self._deny(
                event_type="live_escalation_authorization_denied",
                reason_code="no_authorized_contacts",
                plain_language="Live escalation is blocked because no authorized safety contacts are configured.",
                space_id="system",
                private_space=False,
                signal_types=signal_types,
                severity="concerning",
            )
        if not self.policy.live_contact_ready:
            return self._deny(
                event_type="live_escalation_authorization_denied",
                reason_code="live_contact_gate_not_ready",
                plain_language="Live escalation is blocked until authorized contacts are configured and a test alert succeeds.",
                space_id="system",
                private_space=False,
                signal_types=signal_types,
                severity="concerning",
            )
        entry = self.audit_log.append(
            AuditEntryInput(
                event_type="live_escalation_authorized",
                severity="concerning" if severity == "concerning" else "severe",
                authority_context="user_controlled",
                policy_id=self.policy.policy_id,
                policy_version=self.policy.policy_version,
                public_context={
                    "space_id": "system",
                    "private_space": False,
                    "signal_types": [],
                    "plain_language": "Live safety contact escalation is authorized under the configured guarded escalation policy.",
                },
            )
        )
        return AuthorizationDecision(True, "authorized", entry["public_context"]["plain_language"], entry["audit_entry_id"])

    def _deny(
        self,
        *,
        event_type: str,
        reason_code: str,
        plain_language: str,
        space_id: str,
        private_space: bool,
        signal_types: list[str],
        severity: str = "normal",
    ) -> AuthorizationDecision:
        entry = self.audit_log.append(
            AuditEntryInput(
                event_type=event_type,
                severity=severity,  # type: ignore[arg-type]
                authority_context="system_internal",
                policy_id=self.policy.policy_id,
                policy_version=self.policy.policy_version,
                public_context={
                    "space_id": space_id,
                    "private_space": private_space,
                    "signal_types": signal_types,
                    "plain_language": plain_language,
                },
            )
        )
        return AuthorizationDecision(False, reason_code, plain_language, entry["audit_entry_id"])

    @staticmethod
    def _default_consent_summary(scope: ConsentScope, granted: bool, space_id: str | None, signal_type: str | None) -> str:
        action = "granted" if granted else "revoked"
        if scope == "space":
            return f"User {action} consent for monitoring in {space_id}."
        if scope == "signal_type":
            return f"User {action} consent for {signal_type} signals in {space_id}."
        return f"User {action} consent for {scope}."


DEFAULT_PRODUCTION_POLICY_V02: dict[str, Any] = {
    "schema_version": "0.2",
    "policy_id": "production-local-v0.2",
    "policy_version": "0.2",
    "deployment_mode": "personal",
    "monitoring_enabled": False,
    "private_space_monitoring_enabled": False,
    "bathroom_monitoring_enabled": False,
    "bedroom_monitoring_enabled": False,
    "real_sensor_ingestion_enabled": True,
    "local_baseline_learning_enabled": True,
    "local_audit_logging_enabled": True,
    "real_contact_notification_enabled": False,
    "requires_contact_test_before_live_alerts": True,
    "authorized_contacts_configured": False,
    "successful_test_alert_completed": False,
    "emergency_services_enabled": False,
    "cloud_dependency_for_core_loop": False,
    "silent_telemetry_enabled": False,
    "diagnostic_upload_enabled": False,
    "raw_sensor_retention": "not_retained",
    "export_requires_explicit_confirmation": True,
}
