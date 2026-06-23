from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal
from uuid import uuid4
from .audit import utc_now_iso

ConfirmationState = Literal[
    "idle", "prompt_pending", "prompt_delivered", "awaiting_response",
    "response_received", "response_validated", "response_rejected", "timed_out",
    "escalation_prepared", "escalated", "resolved", "cancelled"
]
ConfirmationMode = Literal["voice", "text", "touch"]
FinalResult = Literal["pending", "confirmed_safe", "confirmed_needs_help", "timeout", "cancelled", "escalated"]


@dataclass
class ConfirmationAttempt:
    attempt_number: int
    mode: ConfirmationMode
    started_at: str
    state: str
    degraded: bool
    audit_ref: str
    completed_at: str | None = None
    response_summary: str | None = None
    confidence: float = 0.0
    degradation_reason: str | None = None


@dataclass
class ConfirmationSession:
    trigger_event_id: str
    severity: Literal["concerning", "severe", "emergency"]
    available_modes: list[ConfirmationMode]
    timeout_seconds: int
    confirmation_id: str = field(default_factory=lambda: str(uuid4()))
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    current_state: ConfirmationState = "prompt_pending"
    attempts: list[ConfirmationAttempt] = field(default_factory=list)
    final_result: FinalResult = "pending"
    voice_is_identity_proof: bool = False
    audit_refs: list[str] = field(default_factory=list)

    def record_attempt(self, mode: ConfirmationMode, state: str, audit_ref: str, degraded: bool = False, reason: str | None = None) -> None:
        self.attempts.append(ConfirmationAttempt(
            attempt_number=len(self.attempts) + 1,
            mode=mode,
            started_at=utc_now_iso(),
            state=state,
            degraded=degraded,
            degradation_reason=reason,
            audit_ref=audit_ref,
        ))
        self.current_state = "awaiting_response" if state == "prompt_delivered" else self.current_state
        self.updated_at = utc_now_iso()
        self.audit_refs.append(audit_ref)

    def validate_safe_response(self, mode: ConfirmationMode, audit_ref: str, confidence: float) -> None:
        if mode == "voice" and self.voice_is_identity_proof:
            raise ValueError("voice may not be treated as identity proof")
        self.current_state = "resolved"
        self.final_result = "confirmed_safe"
        self.updated_at = utc_now_iso()
        self.audit_refs.append(audit_ref)
