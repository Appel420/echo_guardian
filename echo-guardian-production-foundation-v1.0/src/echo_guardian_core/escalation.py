from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal, Protocol
from uuid import uuid4
import json

from jsonschema import Draft202012Validator

from .audit import AuditEntryInput, AuditLog, utc_now_iso
from .policy import AuthorizationDenied, ProductionPolicy

ContactChannel = Literal["sms", "phone_call", "email", "push"]
DeliveryStatus = Literal["blocked", "attempted", "delivered", "failed", "retrying", "cancelled"]
EscalationSeverity = Literal["concerning", "severe", "emergency"]


class ContactSchemaError(ValueError):
    """Raised when a contact record fails schema validation."""


class EscalationBlocked(PermissionError):
    """Raised when live escalation is blocked by product-law gates."""


@dataclass(frozen=True)
class Contact:
    """A user-authorized escalation contact.

    Authorization and test-alert success are explicit fields. The escalation
    engine refuses to contact records that are not both authorized and verified.
    """

    schema_version: str
    contact_id: str
    display_name: str
    channel: ContactChannel
    address: str
    authorized: bool
    test_alert_succeeded: bool
    created_at: str
    authorization_audit_ref: str | None = None
    test_alert_audit_ref: str | None = None
    minimum_disclosure_only: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any], schema_path: str | Path | None = None) -> "Contact":
        if schema_path is not None:
            validate_contact_schema(data, schema_path)
        return cls(**data)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EscalationMessage:
    severity: EscalationSeverity
    reason: str
    recommended_action: str
    location_context: str
    sensitive_details_included: bool = False

    def minimal_payload(self) -> dict[str, Any]:
        return {
            "schema_version": "0.2",
            "severity": self.severity,
            "reason": self.reason,
            "recommended_action": self.recommended_action,
            "location_context": self.location_context,
            "sensitive_details_included": self.sensitive_details_included,
        }


@dataclass(frozen=True)
class DeliveryAttempt:
    attempt_number: int
    contact_id: str
    channel: ContactChannel
    status: DeliveryStatus
    provider_delivery_id: str | None
    error: str | None
    created_at: str
    audit_ref: str


class NotificationProvider(Protocol):
    def send(self, contact: Contact, message: EscalationMessage) -> str:
        """Send notification and return provider delivery id."""


class FileOutboxNotificationProvider:
    """A live-provider adapter that writes outbound notifications to a local outbox.

    This is not a fake safety path. It is a deterministic local delivery adapter
    used when no carrier/SMS/phone provider is configured. Production deployments
    can replace this class with a provider-backed adapter without changing the
    escalation authorization, payload, retry, or audit behavior.
    """

    def __init__(self, outbox_dir: str | Path):
        self.outbox_dir = Path(outbox_dir)
        self.outbox_dir.mkdir(parents=True, exist_ok=True)

    def send(self, contact: Contact, message: EscalationMessage) -> str:
        delivery_id = f"local-outbox-{uuid4()}"
        payload = {
            "delivery_id": delivery_id,
            "created_at": utc_now_iso(),
            "contact": {
                "contact_id": contact.contact_id,
                "display_name": contact.display_name,
                "channel": contact.channel,
                "address": contact.address,
            },
            "message": message.minimal_payload(),
        }
        path = self.outbox_dir / f"{delivery_id}.json"
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return delivery_id


def validate_contact_schema(data: dict[str, Any], schema_path: str | Path) -> None:
    schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
    if errors:
        first = errors[0]
        path = "/".join(str(p) for p in first.path) or "<root>"
        raise ContactSchemaError(f"contact schema validation failed at {path}: {first.message}")


def load_contacts(path: str | Path, schema_path: str | Path | None = None) -> list[Contact]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ContactSchemaError("contact file must contain a list of contact records")
    return [Contact.from_dict(item, schema_path=schema_path) for item in raw]


class EscalationEngine:
    """Live guarded escalation engine.

    The engine enforces the production gates before any real notification attempt:
    user-authorized contacts, successful test alert, minimal disclosure, policy
    readiness, no emergency-services path by default, retry limits, and complete
    audit logging for blocked, attempted, delivered, failed, and retrying states.
    """

    def __init__(
        self,
        *,
        policy: ProductionPolicy,
        audit_log: AuditLog,
        provider: NotificationProvider,
        max_retries: int = 2,
    ):
        policy.validate()
        self.policy = policy
        self.audit_log = audit_log
        self.provider = provider
        self.max_retries = max_retries

    def create_contact_authorization_record(self, contact: Contact, *, plain_language: str | None = None) -> dict[str, Any]:
        entry = self.audit_log.append(
            AuditEntryInput(
                event_type="contact_authorization_recorded",
                severity="normal",
                authority_context="user_controlled",
                policy_id=self.policy.policy_id,
                policy_version=self.policy.policy_version,
                public_context={
                    "space_id": "contacts",
                    "private_space": False,
                    "signal_types": [],
                    "plain_language": plain_language
                    or f"{contact.display_name} was recorded as an authorized safety contact for {contact.channel} alerts.",
                    "contact_id": contact.contact_id,
                    "channel": contact.channel,
                    "authorized": contact.authorized,
                    "test_alert_succeeded": contact.test_alert_succeeded,
                },
            )
        )
        return {
            "schema_version": "0.2",
            "authorization_id": str(uuid4()),
            "contact_id": contact.contact_id,
            "created_at": utc_now_iso(),
            "authorized": contact.authorized,
            "test_alert_succeeded": contact.test_alert_succeeded,
            "plain_language_summary": entry["public_context"]["plain_language"],
            "audit_ref": entry["audit_entry_id"],
        }

    def send_test_alert(self, contact: Contact, message: EscalationMessage | None = None) -> DeliveryAttempt:
        msg = message or EscalationMessage(
            severity="concerning",
            reason="Echo Guardian test alert.",
            recommended_action="No action required. This confirms the contact path works.",
            location_context="Test",
            sensitive_details_included=False,
        )
        if msg.sensitive_details_included:
            return self._blocked_attempt(
                contact=contact,
                message=msg,
                reason_code="test_alert_sensitive_payload_blocked",
                plain_language="Test alerts cannot include sensitive details.",
            )
        return self._attempt_delivery(contact=contact, message=msg, attempt_number=1, event_type="test_alert_attempted")

    def send_guarded_live(
        self,
        *,
        contacts: list[Contact],
        message: EscalationMessage,
    ) -> dict[str, Any]:
        blocked_reason = self._blocked_reason(contacts, message)
        if blocked_reason is not None:
            entry = self.audit_log.append(
                AuditEntryInput(
                    event_type="escalation_blocked",
                    severity=message.severity,
                    authority_context="emergency_policy" if message.severity == "emergency" else "user_controlled",
                    policy_id=self.policy.policy_id,
                    policy_version=self.policy.policy_version,
                    public_context={
                        "space_id": "escalation",
                        "private_space": False,
                        "signal_types": [],
                        "plain_language": blocked_reason["plain_language"],
                        "reason_code": blocked_reason["reason_code"],
                        "contacts_targeted": [],
                        "emergency_services_used": False,
                    },
                )
            )
            return self._event_record(
                message=message,
                contacts_targeted=[],
                delivery_status="blocked",
                delivery_attempts=[],
                audit_ref=entry["audit_entry_id"],
                blocked_reason=blocked_reason["reason_code"],
            )

        ready_contacts = [c for c in contacts if c.authorized and c.test_alert_succeeded and c.minimum_disclosure_only]
        attempts: list[DeliveryAttempt] = []
        targeted: list[str] = []
        for contact in ready_contacts:
            targeted.append(contact.contact_id)
            attempt = self._send_with_retry(contact=contact, message=message)
            attempts.append(attempt)

        final_status: DeliveryStatus = "delivered" if all(a.status == "delivered" for a in attempts) else "failed"
        entry = self.audit_log.append(
            AuditEntryInput(
                event_type="escalation_delivered" if final_status == "delivered" else "escalation_failed",
                severity=message.severity,
                authority_context="emergency_policy" if message.severity == "emergency" else "user_controlled",
                policy_id=self.policy.policy_id,
                policy_version=self.policy.policy_version,
                public_context={
                    "space_id": "escalation",
                    "private_space": False,
                    "signal_types": [],
                    "plain_language": "Echo Guardian delivered a minimal safety alert."
                    if final_status == "delivered"
                    else "Echo Guardian attempted a safety alert but at least one delivery failed.",
                    "contacts_targeted": targeted,
                    "delivery_status": final_status,
                    "emergency_services_used": False,
                },
            )
        )
        return self._event_record(
            message=message,
            contacts_targeted=targeted,
            delivery_status=final_status,
            delivery_attempts=attempts,
            audit_ref=entry["audit_entry_id"],
            blocked_reason=None,
        )

    def _blocked_reason(self, contacts: list[Contact], message: EscalationMessage) -> dict[str, str] | None:
        if self.policy.data.get("emergency_services_enabled") is not False:
            return {
                "reason_code": "emergency_services_disabled_by_product_law",
                "plain_language": "Emergency services are not enabled by default and cannot be used in this build.",
            }
        if not self.policy.live_contact_ready:
            return {
                "reason_code": "live_contact_gate_not_ready",
                "plain_language": "Live alerts are blocked until authorized contacts are configured and a test alert succeeds.",
            }
        if message.sensitive_details_included:
            return {
                "reason_code": "minimal_disclosure_required",
                "plain_language": "Live alerts are blocked because the alert contains sensitive details.",
            }
        ready = [c for c in contacts if c.authorized and c.test_alert_succeeded and c.minimum_disclosure_only]
        if not ready:
            return {
                "reason_code": "no_authorized_verified_contacts",
                "plain_language": "Live alerts are blocked because no authorized contact has a successful test alert.",
            }
        return None

    def _blocked_attempt(
        self,
        *,
        contact: Contact,
        message: EscalationMessage,
        reason_code: str,
        plain_language: str,
    ) -> DeliveryAttempt:
        entry = self.audit_log.append(
            AuditEntryInput(
                event_type="escalation_blocked",
                severity=message.severity,
                authority_context="user_controlled",
                policy_id=self.policy.policy_id,
                policy_version=self.policy.policy_version,
                public_context={
                    "space_id": "escalation",
                    "private_space": False,
                    "signal_types": [],
                    "plain_language": plain_language,
                    "reason_code": reason_code,
                    "contact_id": contact.contact_id,
                    "emergency_services_used": False,
                },
            )
        )
        return DeliveryAttempt(
            attempt_number=1,
            contact_id=contact.contact_id,
            channel=contact.channel,
            status="blocked",
            provider_delivery_id=None,
            error=reason_code,
            created_at=utc_now_iso(),
            audit_ref=entry["audit_entry_id"],
        )

    def _send_with_retry(self, *, contact: Contact, message: EscalationMessage) -> DeliveryAttempt:
        last: DeliveryAttempt | None = None
        for attempt_number in range(1, self.max_retries + 2):
            last = self._attempt_delivery(contact=contact, message=message, attempt_number=attempt_number)
            if last.status == "delivered":
                return last
            if attempt_number <= self.max_retries:
                self.audit_log.append(
                    AuditEntryInput(
                        event_type="escalation_retrying",
                        severity=message.severity,
                        authority_context="emergency_policy" if message.severity == "emergency" else "user_controlled",
                        policy_id=self.policy.policy_id,
                        policy_version=self.policy.policy_version,
                        public_context={
                            "space_id": "escalation",
                            "private_space": False,
                            "signal_types": [],
                            "plain_language": "Echo Guardian is retrying the safety alert after a delivery failure.",
                            "contact_id": contact.contact_id,
                            "attempt_number": attempt_number + 1,
                            "emergency_services_used": False,
                        },
                    )
                )
        assert last is not None
        return last

    def _attempt_delivery(
        self,
        *,
        contact: Contact,
        message: EscalationMessage,
        attempt_number: int,
        event_type: str = "escalation_attempted",
    ) -> DeliveryAttempt:
        attempted_entry = self.audit_log.append(
            AuditEntryInput(
                event_type=event_type,
                severity=message.severity,
                authority_context="emergency_policy" if message.severity == "emergency" else "user_controlled",
                policy_id=self.policy.policy_id,
                policy_version=self.policy.policy_version,
                public_context={
                    "space_id": "escalation",
                    "private_space": False,
                    "signal_types": [],
                    "plain_language": f"Echo Guardian is sending a minimal safety alert to {contact.display_name}.",
                    "contact_id": contact.contact_id,
                    "channel": contact.channel,
                    "attempt_number": attempt_number,
                    "message": message.minimal_payload(),
                    "emergency_services_used": False,
                },
            )
        )
        try:
            provider_id = self.provider.send(contact, message)
        except Exception as exc:  # noqa: BLE001 - provider adapters must not break audit continuity
            failed_entry = self.audit_log.append(
                AuditEntryInput(
                    event_type="escalation_failed",
                    severity=message.severity,
                    authority_context="emergency_policy" if message.severity == "emergency" else "user_controlled",
                    policy_id=self.policy.policy_id,
                    policy_version=self.policy.policy_version,
                    public_context={
                        "space_id": "escalation",
                        "private_space": False,
                        "signal_types": [],
                        "plain_language": f"Echo Guardian could not deliver the safety alert to {contact.display_name}.",
                        "contact_id": contact.contact_id,
                        "channel": contact.channel,
                        "attempt_number": attempt_number,
                        "error": str(exc),
                        "attempt_audit_ref": attempted_entry["audit_entry_id"],
                        "emergency_services_used": False,
                    },
                )
            )
            return DeliveryAttempt(
                attempt_number=attempt_number,
                contact_id=contact.contact_id,
                channel=contact.channel,
                status="failed",
                provider_delivery_id=None,
                error=str(exc),
                created_at=utc_now_iso(),
                audit_ref=failed_entry["audit_entry_id"],
            )

        delivered_entry = self.audit_log.append(
            AuditEntryInput(
                event_type="escalation_delivered" if event_type != "test_alert_attempted" else "test_alert_delivered",
                severity=message.severity,
                authority_context="emergency_policy" if message.severity == "emergency" else "user_controlled",
                policy_id=self.policy.policy_id,
                policy_version=self.policy.policy_version,
                public_context={
                    "space_id": "escalation",
                    "private_space": False,
                    "signal_types": [],
                    "plain_language": f"Echo Guardian delivered a minimal safety alert to {contact.display_name}.",
                    "contact_id": contact.contact_id,
                    "channel": contact.channel,
                    "attempt_number": attempt_number,
                    "provider_delivery_id": provider_id,
                    "attempt_audit_ref": attempted_entry["audit_entry_id"],
                    "emergency_services_used": False,
                },
            )
        )
        return DeliveryAttempt(
            attempt_number=attempt_number,
            contact_id=contact.contact_id,
            channel=contact.channel,
            status="delivered",
            provider_delivery_id=provider_id,
            error=None,
            created_at=utc_now_iso(),
            audit_ref=delivered_entry["audit_entry_id"],
        )

    @staticmethod
    def _event_record(
        *,
        message: EscalationMessage,
        contacts_targeted: list[str],
        delivery_status: DeliveryStatus,
        delivery_attempts: list[DeliveryAttempt],
        audit_ref: str,
        blocked_reason: str | None,
    ) -> dict[str, Any]:
        return {
            "schema_version": "0.2",
            "escalation_id": str(uuid4()),
            "created_at": utc_now_iso(),
            "severity": message.severity,
            "reason": message.reason,
            "recommended_action": message.recommended_action,
            "location_context": message.location_context,
            "minimum_disclosure_enabled": not message.sensitive_details_included,
            "sensitive_details_included": message.sensitive_details_included,
            "contacts_targeted": contacts_targeted,
            "delivery_status": delivery_status,
            "delivery_attempts": [asdict(a) for a in delivery_attempts],
            "blocked_reason": blocked_reason,
            "emergency_services_used": False,
            "audit_ref": audit_ref,
        }
