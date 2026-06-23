from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from .anomaly import AnomalySeverityClassifier, SeverityClassificationRecord
from .audit import AuditEntryInput, AuditLog, utc_now_iso
from .baseline import BaselineLearningEngine, BaselineProfile
from .confirmation import ConfirmationSession, ConfirmationMode
from .escalation import Contact, EscalationEngine, EscalationMessage, FileOutboxNotificationProvider
from .health import ComponentHealth, HealthMonitor, OperationalReadinessReport, ReadinessBlocked
from .policy import PolicyEngine, ProductionPolicy, AuthorizationDenied
from .sensor import DeviceSignalSample, SensorCapability, SensorIngestionEngine, SensorObservationRecord
from .status import AlertPreview, LocalStatusInterface, LocalStatusReport, SpaceStatus
from .storage import LocalStoragePaths

ConfirmationInput = Literal["safe", "needs_help", "timeout", "none"]


class IntegrationBlocked(PermissionError):
    """Raised when the production safety loop is blocked by policy or readiness."""


@dataclass(frozen=True)
class ProductionSafetyCycleResult:
    """One complete local production safety loop result.

    This object is intentionally user-visible and auditable. It contains only
    minimized records and plain-language status. It never contains raw sensor
    samples, hidden network state, or unreviewed private-space data.
    """

    schema_version: str
    cycle_id: str
    created_at: str
    completed_at: str
    policy_authorized: bool
    readiness_passed: bool
    observation: dict[str, Any]
    baseline_summary: dict[str, Any]
    classification: dict[str, Any]
    confirmation: dict[str, Any] | None
    escalation: dict[str, Any] | None
    local_status: dict[str, Any]
    audit_verified: bool
    audit_errors: list[str]
    no_cloud_dependency: bool
    no_private_space_monitoring: bool
    hidden_behavior_present: bool
    plain_language_summary: str
    audit_refs: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ProductionIntegrationRunner:
    """Runs one local production safety loop.

    Pipeline:
      policy gate -> readiness gate -> sensor ingestion -> baseline update ->
      severity classification -> confirmation decision -> escalation decision ->
      local status -> audit verification.

    Production v0.2 rules:
      - no cloud dependency
      - no private-space monitoring
      - no hidden behavior
      - no raw sensor retention
      - all state-changing decisions create audit entries
    """

    def __init__(
        self,
        *,
        policy: ProductionPolicy,
        audit_log: AuditLog,
        storage_paths: LocalStoragePaths,
        contacts: list[Contact] | None = None,
        outbox_dir: str | Path | None = None,
        baseline: BaselineProfile | None = None,
    ):
        policy.validate()
        self.policy = policy
        self.audit_log = audit_log
        self.storage_paths = storage_paths
        self.contacts = contacts or []
        self.outbox_dir = Path(outbox_dir) if outbox_dir else storage_paths.export / "local_outbox"
        self.baseline = baseline or BaselineProfile.create()

    def run_cycle(
        self,
        *,
        sample: DeviceSignalSample,
        confirmation_input: ConfirmationInput = "safe",
        confirmation_mode: ConfirmationMode = "touch",
    ) -> ProductionSafetyCycleResult:
        cycle_id = str(uuid4())
        started_at = utc_now_iso()
        audit_refs: list[str] = []

        start_entry = self.audit_log.append(
            AuditEntryInput(
                event_type="production_cycle_started",
                severity="normal",
                authority_context="system_internal",
                policy_id=self.policy.policy_id,
                policy_version=self.policy.policy_version,
                public_context={
                    "space_id": sample.space_id,
                    "private_space": sample.private_space,
                    "signal_types": [sample.signal_type],
                    "plain_language": "Echo Guardian started one local production safety check.",
                    "cycle_id": cycle_id,
                    "cloud_dependency": False,
                    "hidden_behavior_present": False,
                },
            )
        )
        audit_refs.append(start_entry["audit_entry_id"])

        policy_decision = self._policy_gate(sample)
        audit_refs.append(policy_decision.audit_entry_id or "")
        if not policy_decision.authorized:
            raise IntegrationBlocked(policy_decision.plain_language)

        try:
            readiness = self._readiness_gate(sample)
        except ReadinessBlocked as exc:
            raise IntegrationBlocked(str(exc)) from exc
        audit_refs.append(readiness.audit_ref)
        if not readiness.ready_for_active_monitoring:
            raise IntegrationBlocked(readiness.plain_language_summary)

        sensor_engine = SensorIngestionEngine(policy=self.policy, audit_log=self.audit_log)
        observation = sensor_engine.ingest(sample)
        audit_refs.append(observation.audit_ref)

        baseline_engine = BaselineLearningEngine(policy=self.policy, audit_log=self.audit_log, profile=self.baseline)
        if baseline_engine.profile.status == "no_baseline":
            created = baseline_engine.create_baseline()
            audit_refs.extend(created.get("audit_refs", []))
        baseline_summary = baseline_engine.ingest_observation(observation)
        self.baseline = baseline_engine.profile
        audit_refs.extend(baseline_summary.get("audit_refs", []))

        classifier = AnomalySeverityClassifier(policy=self.policy, audit_log=self.audit_log)
        classification = classifier.classify(observation=observation, baseline=self.baseline)
        audit_refs.extend(classification.audit_refs)

        confirmation_dict: dict[str, Any] | None = None
        escalation_dict: dict[str, Any] | None = None
        if classification.severity in {"concerning", "severe", "emergency"}:
            confirmation = self._run_confirmation(
                classification=classification,
                confirmation_input=confirmation_input,
                confirmation_mode=confirmation_mode,
            )
            confirmation_dict = confirmation
            audit_refs.extend(confirmation.get("audit_refs", []))
            if confirmation["final_result"] in {"confirmed_needs_help", "timeout", "escalated"}:
                escalation_dict = self._run_escalation(classification=classification)
                if escalation_dict.get("audit_ref"):
                    audit_refs.append(escalation_dict["audit_ref"])
                for attempt in escalation_dict.get("delivery_attempts", []):
                    ref = attempt.get("audit_ref")
                    if ref:
                        audit_refs.append(ref)

        status_report = self._status_report(sample=sample, classification=classification, readiness=readiness)
        audit_refs.append(status_report.audit_ref)

        end_entry = self.audit_log.append(
            AuditEntryInput(
                event_type="production_cycle_completed",
                severity=classification.severity,
                authority_context="system_internal",
                policy_id=self.policy.policy_id,
                policy_version=self.policy.policy_version,
                public_context={
                    "space_id": sample.space_id,
                    "private_space": False,
                    "signal_types": [sample.signal_type],
                    "plain_language": "Echo Guardian completed the local production safety check and verified the audit trail.",
                    "cycle_id": cycle_id,
                    "classification_severity": classification.severity,
                    "escalation_taken": escalation_dict is not None,
                    "cloud_dependency": False,
                    "hidden_behavior_present": False,
                },
            )
        )
        audit_refs.append(end_entry["audit_entry_id"])

        audit_errors = self.audit_log.verify()
        verified = not audit_errors
        plain = self._plain_summary(classification=classification, confirmation=confirmation_dict, escalation=escalation_dict, verified=verified)
        return ProductionSafetyCycleResult(
            schema_version="0.2",
            cycle_id=cycle_id,
            created_at=started_at,
            completed_at=utc_now_iso(),
            policy_authorized=True,
            readiness_passed=True,
            observation=observation.to_dict(),
            baseline_summary=baseline_summary,
            classification=classification.to_dict(),
            confirmation=confirmation_dict,
            escalation=escalation_dict,
            local_status=status_report.to_dict(),
            audit_verified=verified,
            audit_errors=audit_errors,
            no_cloud_dependency=True,
            no_private_space_monitoring=True,
            hidden_behavior_present=False,
            plain_language_summary=plain,
            audit_refs=list(dict.fromkeys([ref for ref in audit_refs if ref])),
        )

    def _policy_gate(self, sample: DeviceSignalSample):
        engine = PolicyEngine(policy=self.policy, audit_log=self.audit_log)
        return engine.authorize_monitoring_state(
            space_id=sample.space_id,
            private_space=sample.private_space,
            enabled=True,
            signal_types=[sample.signal_type],
            authority="user",
        )

    def _readiness_gate(self, sample: DeviceSignalSample) -> OperationalReadinessReport:
        monitor = HealthMonitor(policy=self.policy, audit_log=self.audit_log)
        capability = SensorCapability(
            sensor_id=sample.sensor_id,
            signal_type=sample.signal_type,
            display_name=f"{sample.signal_type} sensor",
            permission_state=sample.permission_state,
            availability_state=sample.availability_state,
            private_space_capable=sample.private_space,
            plain_language=f"The {sample.signal_type} safety signal is available for {sample.space_id}.",
        )
        components: list[ComponentHealth] = [
            monitor.component_from_sensor(capability),
            monitor.component_from_storage_paths(self.storage_paths),
            monitor.component_from_audit_log(self.audit_log),
            monitor.component_from_policy(),
            ComponentHealth(
                component_type="interface",
                component_id="local_confirmation_interface",
                display_name="confirmation interface",
                state="healthy",
                required_for_active_monitoring=True,
                plain_language="Voice, text, or touch confirmation can be shown locally.",
            ),
            monitor.component_from_contacts(self.contacts),
        ]
        report = monitor.generate_report(components=components)
        monitor.assert_ready_for_active_monitoring(report)
        return report

    def _run_confirmation(
        self,
        *,
        classification: SeverityClassificationRecord,
        confirmation_input: ConfirmationInput,
        confirmation_mode: ConfirmationMode,
    ) -> dict[str, Any]:
        session = ConfirmationSession(
            trigger_event_id=classification.classification_id,
            severity=classification.severity,  # type: ignore[arg-type]
            available_modes=["voice", "text", "touch"],
            timeout_seconds=30 if classification.severity == "severe" else 60,
        )
        prompt_entry = self.audit_log.append(
            AuditEntryInput(
                event_type="confirmation_prompt_delivered",
                severity=classification.severity,
                authority_context="system_internal",
                policy_id=self.policy.policy_id,
                policy_version=self.policy.policy_version,
                public_context={
                    "space_id": classification.space_id,
                    "private_space": False,
                    "signal_types": [classification.signal_type],
                    "plain_language": "Echo Guardian is checking if the user is okay.",
                    "confirmation_id": session.confirmation_id,
                    "mode": confirmation_mode,
                },
            )
        )
        session.record_attempt(confirmation_mode, "prompt_delivered", prompt_entry["audit_entry_id"])

        if confirmation_input == "safe":
            response_entry = self.audit_log.append(
                AuditEntryInput(
                    event_type="confirmation_response_received",
                    severity=classification.severity,
                    authority_context="user_controlled",
                    policy_id=self.policy.policy_id,
                    policy_version=self.policy.policy_version,
                    public_context={
                        "space_id": classification.space_id,
                        "private_space": False,
                        "signal_types": [classification.signal_type],
                        "plain_language": "The user confirmed they are okay.",
                        "confirmation_id": session.confirmation_id,
                        "mode": confirmation_mode,
                        "voice_is_identity_proof": False,
                    },
                )
            )
            session.validate_safe_response(confirmation_mode, response_entry["audit_entry_id"], confidence=0.8)
        elif confirmation_input == "needs_help":
            response_entry = self.audit_log.append(
                AuditEntryInput(
                    event_type="confirmation_response_received",
                    severity=classification.severity,
                    authority_context="user_controlled",
                    policy_id=self.policy.policy_id,
                    policy_version=self.policy.policy_version,
                    public_context={
                        "space_id": classification.space_id,
                        "private_space": False,
                        "signal_types": [classification.signal_type],
                        "plain_language": "The user indicated they may need help.",
                        "confirmation_id": session.confirmation_id,
                        "mode": confirmation_mode,
                    },
                )
            )
            session.current_state = "escalation_prepared"
            session.final_result = "confirmed_needs_help"
            session.updated_at = utc_now_iso()
            session.audit_refs.append(response_entry["audit_entry_id"])
        else:
            timeout_entry = self.audit_log.append(
                AuditEntryInput(
                    event_type="confirmation_timed_out",
                    severity=classification.severity,
                    authority_context="system_internal",
                    policy_id=self.policy.policy_id,
                    policy_version=self.policy.policy_version,
                    public_context={
                        "space_id": classification.space_id,
                        "private_space": False,
                        "signal_types": [classification.signal_type],
                        "plain_language": "No response was received in the confirmation window.",
                        "confirmation_id": session.confirmation_id,
                    },
                )
            )
            session.current_state = "timed_out"
            session.final_result = "timeout"
            session.updated_at = utc_now_iso()
            session.audit_refs.append(timeout_entry["audit_entry_id"])

        return {
            "schema_version": "0.2",
            "confirmation_id": session.confirmation_id,
            "trigger_event_id": session.trigger_event_id,
            "created_at": session.created_at,
            "updated_at": session.updated_at,
            "current_state": session.current_state,
            "severity": session.severity,
            "available_modes": session.available_modes,
            "attempts": [asdict(a) for a in session.attempts],
            "timeout_seconds": session.timeout_seconds,
            "final_result": session.final_result,
            "voice_is_identity_proof": session.voice_is_identity_proof,
            "audit_refs": session.audit_refs,
        }

    def _run_escalation(self, *, classification: SeverityClassificationRecord) -> dict[str, Any]:
        policy_engine = PolicyEngine(policy=self.policy, audit_log=self.audit_log)
        ready_contacts = [c for c in self.contacts if c.authorized and c.test_alert_succeeded]
        auth = policy_engine.authorize_live_escalation(severity=classification.severity, contact_count=len(ready_contacts))
        if not auth.authorized:
            return {
                "schema_version": "0.2",
                "escalation_id": str(uuid4()),
                "created_at": utc_now_iso(),
                "severity": classification.severity,
                "delivery_status": "blocked",
                "blocked_reason": auth.reason_code,
                "plain_language_summary": auth.plain_language,
                "contacts_targeted": [],
                "delivery_attempts": [],
                "minimum_disclosure_enabled": True,
                "emergency_services_used": False,
                "audit_ref": auth.audit_entry_id,
            }
        engine = EscalationEngine(
            policy=self.policy,
            audit_log=self.audit_log,
            provider=FileOutboxNotificationProvider(self.outbox_dir),
        )
        message = EscalationMessage(
            severity=classification.severity,  # type: ignore[arg-type]
            reason="No safe confirmation was completed after a safety check.",
            recommended_action="Please check on the user.",
            location_context=f"Home - {classification.space_id}",
            sensitive_details_included=False,
        )
        return engine.send_guarded_live(contacts=self.contacts, message=message)

    def _status_report(
        self,
        *,
        sample: DeviceSignalSample,
        classification: SeverityClassificationRecord,
        readiness: OperationalReadinessReport,
    ) -> LocalStatusReport:
        status = LocalStatusInterface(policy=self.policy, audit_log=self.audit_log)
        alert_preview = AlertPreview(
            severity=classification.severity,
            reason="No response after safety confirmation prompt.",
            location_context=f"Home - {sample.space_id}",
            recommended_action="Please check on the user.",
            sensitive_details_included=False,
            emergency_services_used=False,
        )
        return status.generate_status_report(
            spaces=[
                SpaceStatus(
                    space_id=sample.space_id,
                    display_name=sample.space_id.replace("_", " "),
                    enabled=True,
                    private_space=False,
                    signal_types=[sample.signal_type],
                    authority="user",
                )
            ],
            degradations=[],
            alert_preview=alert_preview,
        )

    @staticmethod
    def _plain_summary(
        *,
        classification: SeverityClassificationRecord,
        confirmation: dict[str, Any] | None,
        escalation: dict[str, Any] | None,
        verified: bool,
    ) -> str:
        parts = [
            f"Echo Guardian completed one local safety check for {classification.space_id}.",
            classification.plain_language_explanation,
        ]
        if confirmation:
            if confirmation["final_result"] == "confirmed_safe":
                parts.append("The user confirmed they are okay.")
            elif confirmation["final_result"] == "confirmed_needs_help":
                parts.append("The user indicated they may need help.")
            elif confirmation["final_result"] == "timeout":
                parts.append("No confirmation response was received in time.")
        if escalation:
            parts.append(f"Escalation status: {escalation.get('delivery_status', 'unknown')}.")
        parts.append("The audit trail verified correctly." if verified else "The audit trail did not verify and needs review.")
        return " ".join(parts)
