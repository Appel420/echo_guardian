# CI Pipeline v0.3

## Required Jobs

- Unit tests
- Cryptographic tests
- Security hardening tests
- Schema validation tests
- Artifact existence tests
- Dependency scan placeholder
- SBOM generation placeholder

## Required Security Rules

- CI must fail if tests fail.
- CI must fail if security tests fail.
- CI must fail if policy defaults enable hidden telemetry, private-space monitoring, automatic export, or emergency services by default.
- CI must preserve package integrity evidence for release artifacts.
