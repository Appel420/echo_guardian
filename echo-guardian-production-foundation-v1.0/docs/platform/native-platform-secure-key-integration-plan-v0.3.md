# Echo Guardian v0.3 Native Platform + Secure Key Integration Plan

Status: production-intent integration plan, not certification.

## Purpose

v0.3 moves the production foundation from portable core logic toward native platform integration. The release target is not a toy demo. It is the first native integration baseline for real iOS/Android signals, device-bound keys, guarded live delivery adapters, CI security automation, SBOM generation, dependency scanning, and accessibility screen flows.

## Production Laws Preserved

- No hidden behavior.
- No cloud dependency for the core safety loop.
- No private-space monitoring by default.
- No raw sensor retention by default.
- No export without explicit user action.
- No live contact escalation without guarded readiness.
- No emergency-services dispatch by default.
- No unsupported HIPAA, GDPR, global-compliance, clinical, or medical-device claims.

## v0.3 Deliverables

1. Native iOS sensor adapter design.
2. Native Android sensor adapter design.
3. Secure Enclave / Keychain / Android Keystore integration plan.
4. Device-bound signing key prototype interface.
5. Live contact delivery provider adapter interface.
6. CI pipeline baseline.
7. SBOM generation plan and tooling wrapper.
8. Dependency scanning plan.
9. Expanded security suite under `tests/security/`.
10. Accessibility screen-flow prototype.

## Release Gate

v0.3 is approved only when all added design artifacts exist, all existing v0.2 production-foundation tests still pass, and new security artifact tests pass.
