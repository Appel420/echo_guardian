# Live Guarded Escalation Engine v0.2

Status: implemented in the production foundation package.

## Implemented

- Contact schema enforcement (`schemas/contact.schema.json`)
- Contact authorization audit records
- Successful test-alert requirement before live escalation
- Minimal-disclosure escalation payloads
- Live escalation event records (`schemas/escalation-event.schema.json`)
- Delivery status model: `blocked`, `attempted`, `delivered`, `failed`, `retrying`, `cancelled`
- Retry policy with audited retry events
- Emergency-services path disabled by default
- Audit entries for every blocked, attempted, delivered, failed, and retrying escalation state
- Local file outbox provider adapter for provider-independent production integration testing

## Product Law

The production path is real and guarded. Escalation is not allowed unless:

1. Live contact notification is enabled by policy.
2. Authorized contacts are configured.
3. A successful test alert has completed.
4. The alert uses minimum disclosure.
5. Emergency-services dispatch remains disabled unless a later reviewed policy explicitly enables it.

## Files

- `src/echo_guardian_core/escalation.py`
- `schemas/contact.schema.json`
- `schemas/escalation-event.schema.json`
- `tools/send_guarded_escalation.py`
- `tests/unit/test_escalation.py`
- `examples/local-live-personal/contacts_v0.2.json`
- `examples/local-live-personal/production_policy_live_guarded_v0.2.json`
- `examples/local-live-personal/escalation_event_v0.2.json`

## Validation

```text
28 passed
AUDIT VERIFICATION PASSED: 3 entries
```
