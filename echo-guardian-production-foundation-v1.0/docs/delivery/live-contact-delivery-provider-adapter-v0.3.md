# Live Contact Delivery Provider Adapter v0.3

## Objective

Define the provider boundary for guarded live contact notification without tying the escalation engine to a single vendor.

## Provider Adapter Requirements

- Accept a minimal-disclosure alert payload.
- Return delivery status without exposing unnecessary recipient data.
- Support delivery states: blocked, attempted, delivered, failed, retrying, cancelled.
- Never contact emergency services by default.
- Never send alerts unless policy gates pass.
- Emit audit entries for every attempt and final state.

## Supported Initial Channels

- SMS provider adapter placeholder.
- Email provider adapter placeholder.
- Push notification provider placeholder.

## Provider Boundary

The provider adapter cannot decide whether escalation is allowed. It only delivers a payload already authorized by the policy and escalation engines.
