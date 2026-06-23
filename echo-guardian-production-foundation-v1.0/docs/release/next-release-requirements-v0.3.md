# Next Release Requirements v0.3

v0.3 should move the production foundation closer to deployable native operation.

## Required

- Native iOS and Android sensor adapter design.
- Secure Enclave / Keychain / Keystore implementation plan.
- Device-bound signing key prototype.
- Live contact delivery provider adapter interface.
- Test-alert verification workflow.
- CI pipeline for tests, schema validation, audit verification, and artifact hashing.
- SBOM generation.
- Dependency vulnerability scanning.
- Expanded `tests/security/` suite.
- Privacy-rights workflow scaffold.
- Accessibility screen-flow prototype.
- User-facing copy review for child/elderly clarity.

## Gate Criteria

v0.3 must not weaken:

- local-first operation
- no hidden behavior
- no silent export
- no raw sensor retention
- private-space block by default
- audit verification
- explicit consent
