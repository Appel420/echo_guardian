# Local Status + Plain-Language Interface Layer v0.2

Status: implemented in production foundation package.

This layer makes Echo Guardian understandable without technical training. It turns internal state into child/elderly-clear explanations while preserving the production rules: nothing hidden, no private-space activation, visible authority, visible degraded states, minimal alert previews, and audit records for status checks.

## Implemented

- Plain-language monitoring on/off explanation
- Active-space explanation
- Active signal-type explanation
- Authority labels
- Degraded-state explanation
- Direct response to: "What are you doing?"
- Minimal-disclosure alert preview text
- Audit entries for status checks
- Audit entries for interface degradation

## Product-law checks

- Enabled private spaces are rejected in v0.2.
- Enabled spaces must show at least one signal type.
- Hidden behavior is represented as `hidden_behavior_present=false` and enforced by schema.
- Status checks are not silent; they create audit records.

## Normal-user standard

The interface must be simple on the outside and strong underneath. Advanced cryptographic details may be available elsewhere, but the everyday status view must explain what Echo Guardian is doing in direct human language.
