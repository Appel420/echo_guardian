"""Provider adapter boundary for guarded live escalation v0.4."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Literal, Protocol

DeliveryStatus = Literal["blocked", "attempted", "delivered", "failed", "retrying", "cancelled"]


@dataclass(frozen=True)
class MinimalDisclosureAlert:
    severity: str
    reason: str
    location_context: str
    recommended_action: str
    sensitive_details_included: bool = False
    emergency_services_used: bool = False

    def validate_minimal_disclosure(self) -> None:
        if self.sensitive_details_included:
            raise ValueError("sensitive details are blocked in minimal-disclosure mode")
        if self.emergency_services_used:
            raise ValueError("emergency-services routing is disabled by default")


@dataclass(frozen=True)
class DeliveryResult:
    status: DeliveryStatus
    provider: str
    provider_message_id: str | None
    plain_language_summary: str
    audit_required: bool = True


class DeliveryProvider(Protocol):
    def send(self, contact: Dict[str, str], alert: MinimalDisclosureAlert) -> DeliveryResult:
        ...


class LocalOutboxDeliveryProvider:
    """Local provider for integration without external network dependency.

    This provider writes no network messages. Real SMS/email/push adapters must
    implement the same boundary and may only be called after policy gates pass.
    """

    provider_name = "local_outbox"

    def send(self, contact: Dict[str, str], alert: MinimalDisclosureAlert) -> DeliveryResult:
        if not contact.get("authorized") == "true":
            return DeliveryResult(
                status="blocked",
                provider=self.provider_name,
                provider_message_id=None,
                plain_language_summary="This contact is not authorized for live safety alerts.",
            )
        if alert.emergency_services_used:
            return DeliveryResult(
                status="blocked",
                provider=self.provider_name,
                provider_message_id=None,
                plain_language_summary="Emergency services are not contacted by default.",
            )
        if alert.sensitive_details_included:
            return DeliveryResult(
                status="blocked",
                provider=self.provider_name,
                provider_message_id=None,
                plain_language_summary="Sensitive details are blocked in minimal-disclosure mode.",
            )
        return DeliveryResult(
            status="attempted",
            provider=self.provider_name,
            provider_message_id="local-outbox-pending",
            plain_language_summary="A minimal safety alert was prepared in the local outbox.",
        )
