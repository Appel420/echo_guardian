# Echo Guardian Consent + Policy Engine v0.2

Status: implemented in the production foundation scaffold.

## Purpose

The Consent + Policy Engine is the mandatory control point for monitoring, consent, export, and guarded live escalation decisions. User interface code and future sensor/escalation modules must not change safety-relevant state directly.

## Implemented Controls

- Production local policy loader.
- JSON Schema validation for `policy.schema.json`.
- Product-law validation for non-negotiables:
  - no hidden telemetry
  - no cloud dependency for the core safety path
  - no private-space monitoring by default
  - no emergency services by default
  - no diagnostic upload by default
  - no raw sensor retention by default
  - audit logging must remain enabled
- Consent record creation with audit entry linkage.
- Monitoring authorization decisions.
- Private-space hard block for bathroom and bedroom in v0.2.
- Live escalation authorization gates:
  - real contact notification enabled
  - authorized contacts configured
  - successful test alert completed
  - contact count greater than zero
- Audit entries for allowed and denied policy decisions.

## Plain-Language Rule

Every policy decision writes an audit entry with a child/elderly-readable explanation in `public_context.plain_language`.

## Important Boundary

The v0.2 engine supports production-live non-private-space monitoring and guarded live contact escalation. It does not enable MDM, caregiver delegation, private-space monitoring, passive mode, or emergency services by default.
