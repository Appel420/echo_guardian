# Health Monitor + Operational Readiness v0.2

## Purpose

The health monitor decides whether Echo Guardian is ready to enter active local monitoring. It aggregates the safety-path components that must be visible and working before monitoring begins.

## Implemented

- Sensor health aggregation
- Storage health checks
- Audit health verification
- Policy health checks
- Interface health checks
- Contact/escalation readiness checks
- `healthy`, `degraded`, `critical`, `unavailable`, and `unknown` states
- Plain-language readiness report
- Active-monitoring readiness gate
- Audit entries for health checks and readiness failures

## Readiness Rule

Active monitoring is blocked when any required component is not `healthy`.

Required components include:

- Sensor path
- Local storage separation
- Audit verification
- Local policy validity
- Interface confirmation path

Contact/escalation readiness is reported, but it is not required for local monitoring unless a deployment policy explicitly requires live external alerts. This keeps local safety monitoring available while clearly warning the user if outside help cannot be contacted.

## Plain-Language Standard

The report must be understandable to a non-technical user. Examples:

- "Echo Guardian is ready for active local monitoring. Core safety parts are working."
- "Echo Guardian is not ready to turn monitoring on yet. living room movement: Movement permission is not available."
- "Live safety contact alerts are not enabled yet. Local monitoring can still work, but outside help will not be contacted."

## Audit Behavior

The health monitor writes:

- `operational_health_checked` when readiness passes
- `operational_readiness_failed` when active monitoring must remain blocked

Every report includes the audit entry reference.
