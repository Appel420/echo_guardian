# Echo Guardian — Production Foundation v0.2

Status: production-live foundation build, not a demo.

Echo Guardian is a local-first safety monitoring foundation. The production path must use real local data, real consent state, real audit records, real confirmation state, and real guarded escalation configuration. Test harnesses may exist only as isolated validation tools.

## Non-negotiables

- No hidden telemetry.
- No stealth mode.
- No silent export.
- No private-space monitoring by default.
- No network dependency for the core safety loop.
- No fake production monitoring.
- No cryptographic fallback from BLAKE3 to weaker hashes.
- No live escalation without configured contacts and successful test alert.
- No unsupported HIPAA, GDPR, medical-device, or global-compliance claims.

## Build Target

This repository starts the production foundation:

- JSON schemas for production state boundaries.
- Canonical JSON serialization.
- Strict BLAKE3 hash requirement.
- Append-only audit chain.
- Binary Merkle root computation.
- Policy enforcement defaults.
- Confirmation state model.
- Guarded escalation model.
- Audit verification tool.

## Install

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## Verify audit log

```bash
python tools/verify_audit.py examples/local-live-personal/audit_chain.jsonl
```

## Production claim boundary

This codebase is compliance-designed and audit-ready, but not certified. Deployment-specific legal, clinical, privacy, security, and accessibility review is required before claims or regulated deployment.

## Local Audit Engine v0.2

The production foundation now includes a concrete local audit engine:

- canonical JSON serialization
- strict BLAKE3 hash chain
- Merkle root calculation
- Ed25519 signed checkpoints
- verification CLI tools
- tamper, reorder, and checkpoint tests

Run:

```bash
python -m pip install -r requirements.txt
make test
python tools/verify_audit.py examples/local-live-personal/audit_chain.jsonl
python tools/verify_checkpoint.py examples/local-live-personal/checkpoint.json
```

## Consent + Policy Engine v0.2

The production foundation now includes a local policy and consent engine:

- production policy loader
- JSON Schema validation
- product-law validation for non-negotiables
- consent record creation with audit linkage
- monitoring authorization decisions
- private-space hard block for bathroom and bedroom in v0.2
- live escalation gates requiring configured contacts and successful test alert
- audit entries for both authorized and denied policy decisions

Run:

```bash
PYTHONPATH=src python tools/validate_policy.py examples/local-live-personal/production_policy_v0.2.json
make test
```


## Live Guarded Escalation Engine v0.2

This package now includes a production-path guarded escalation engine. It supports user-authorized contacts, required test alerts, minimal-disclosure alert payloads, delivery status records, retry handling, and full audit logging for blocked, attempted, delivered, failed, and retrying escalation events. Emergency-services routing remains disabled by default.

Run tests:

```bash
PYTHONPATH=src pytest -q
```

Run a local provider-adapter escalation example:

```bash
PYTHONPATH=src python tools/send_guarded_escalation.py \
  --policy examples/local-live-personal/production_policy_live_guarded_v0.2.json \
  --contacts examples/local-live-personal/contacts_v0.2.json \
  --audit /tmp/echo_guardian_escalation_audit.jsonl \
  --outbox /tmp/echo_guardian_outbox \
  --reason "No response after safety confirmation prompt." \
  --location "Home - living room"
```


## Real Sensor Ingestion Layer v0.2

This package now includes the real sensor ingestion boundary:

- platform adapter interface
- device-signal sample model
- minimized local observation records
- permission and availability health states
- no raw sensor retention by default
- derived metadata-only pipeline
- audit entries for sensor availability, observation, degradation, and permission changes

Run tests:

```bash
PYTHONPATH=src pytest -q
```

Ingest a minimized local observation:

```bash
PYTHONPATH=src python tools/ingest_sensor_observation.py   --policy examples/local-live-personal/production_policy_v0.2.json   --audit /tmp/echo_guardian_sensor_audit.jsonl   --sensor-id core_motion.activity   --signal-type motion   --space-id living_room   --metadata-json '{"motion_detected":true,"confidence_scaled":91}'
```

## Baseline Learning Engine v0.2

This package now includes the local baseline learning engine:

- local baseline profile model
- derived-observation ingestion from minimized sensor records
- `no_baseline`, `learning`, `established`, `degraded`, `reset`, and `replaced` states
- confidence scoring without retaining raw history
- baseline update records
- plain-language baseline summaries
- audit entries for creation, update, degradation, reset, and replacement

Run tests:

```bash
PYTHONPATH=src pytest -q
```

Update a local baseline from a minimized sensor observation:

```bash
PYTHONPATH=src python tools/update_baseline.py \
  --policy examples/local-live-personal/production_policy_v0.2.json \
  --observation examples/local-live-personal/sensor_observation_v0.2.json \
  --audit-log /tmp/echo_guardian_baseline_audit.jsonl \
  --out /tmp/echo_guardian_baseline_summary.json \
  --create
```

## Anomaly + Severity Classifier v0.2

This package now includes the deterministic anomaly and severity classifier:

- baseline-vs-observation comparison
- `normal`, `unusual`, `concerning`, `severe`, and `emergency` classifications
- conservative thresholds during learning/degraded baseline states
- confidence-aware decisions
- plain-language explanation for every classification
- audit entries for anomaly detection and severity classification

Run tests:

```bash
PYTHONPATH=src pytest -q
```

Classify a minimized local observation:

```bash
PYTHONPATH=src python tools/classify_observation.py \
  --policy examples/local-live-personal/production_policy_v0.2.json \
  --observation examples/local-live-personal/sensor_observation_v0.2.json \
  --baseline examples/local-live-personal/baseline_summary_v0.2.json \
  --audit-log /tmp/echo_guardian_anomaly_audit.jsonl \
  --out /tmp/echo_guardian_severity_classification.json
```

## Local Status + Plain-Language Interface Layer v0.2

This package now includes the child/elderly-clear local status interface:

- monitoring on/off explanation
- active spaces explanation
- active signal types explanation
- authority labels
- degraded-state explanation
- direct “What are you doing?” response
- minimal-disclosure alert-preview text
- audit entries for status checks and interface degradation

Run tests:

```bash
PYTHONPATH=src pytest -q
```

Show a local status report:

```bash
PYTHONPATH=src python tools/show_local_status.py \
  --policy examples/local-live-personal/production_policy_v0.2.json \
  --audit-log /tmp/echo_guardian_status_audit.jsonl \
  --out /tmp/echo_guardian_local_status.json \
  --enabled \
  --space-id living_room \
  --display-name "living room" \
  --signal-types motion,device_presence
```

## Local Encrypted Storage + Export Package v0.2

Implemented production-foundation local storage and export controls:

- encrypted local store abstraction using AES-256-GCM
- separate operational, audit, and export storage paths
- explicit user-confirmed export request record
- export manifest generation
- audit chain export
- baseline/status/policy export
- BLAKE3 hashes for all exported files
- no automatic export
- audit entries for export request, export generation, denial, and failure

Run tests:

```bash
PYTHONPATH=src pytest -q
```

Create a local export package:

```bash
PYTHONPATH=src python tools/create_export_package.py \
  --policy examples/local-live-personal/production_policy_v0.2.json \
  --audit examples/local-live-personal/audit_chain.jsonl \
  --out examples/local-live-personal/export_package_v0.2 \
  --baseline examples/local-live-personal/baseline_summary_v0.2.json \
  --status examples/local-live-personal/local_status_report_v0.2.json \
  --confirm
```

## Health Monitor + Operational Readiness v0.2

Implemented production-foundation health and readiness controls:

- sensor health aggregation
- storage health checks
- audit health checks
- policy health checks
- interface health checks
- contact/escalation readiness
- degraded, critical, unavailable, unknown, and healthy states
- plain-language health report
- readiness gate before active monitoring
- audit entries for health checks and readiness failures

Run tests:

```bash
PYTHONPATH=src pytest -q
```

Create an operational readiness report:

```bash
PYTHONPATH=src python tools/check_operational_readiness.py \
  --policy examples/local-live-personal/production_policy_v0.2.json \
  --audit examples/local-live-personal/health_audit_chain_v0.2.jsonl \
  --storage-root examples/local-live-personal/health_store_v0.2 \
  --output examples/local-live-personal/operational_health_report_v0.2.json
```


### Production Integration Runner v0.2

The current package includes one complete local production safety loop:

```text
policy gate -> health readiness gate -> sensor ingestion -> baseline update -> severity classification -> confirmation decision -> escalation decision -> local status -> audit verification
```

Run the local production cycle:

```bash
PYTHONPATH=src python tools/run_production_cycle.py \
  --policy examples/local-live-personal/production_policy_v0.2.json \
  --audit-log examples/local-live-personal/production_cycle_audit_v0.2.jsonl \
  --storage-root examples/local-live-personal/production_cycle_store_v0.2 \
  --sample examples/local-live-personal/production_cycle_sample_v0.2.json \
  --out examples/local-live-personal/production_cycle_result_v0.2.json \
  --confirmation safe
```

Production rules enforced: no cloud dependency, no private-space monitoring, no hidden behavior, no raw sensor retention, policy/readiness gates before monitoring, and end-of-cycle audit verification.

## Production Readiness Report + v0.2 Release Gate

Release gate artifacts are included under `docs/release/`:

- `production-readiness-report-v0.2.json`
- `production-readiness-summary-v0.2.md`
- `known-limitations-v0.2.md`
- `open-risks-v0.2.md`
- `next-release-requirements-v0.3.md`
- `RELEASE_NOTES_v0.2.md` at repository root

Current release-gate test result:

```text
PYTHONPATH=src python -m pytest -q
80 passed
```

Release decision: **approved for v0.2 production-foundation baseline, with limitations**. This release is not certified for medical, clinical, HIPAA, GDPR, global-compliance, emergency-response, or enterprise institutional deployment.

## v0.3 Native Platform + Secure Key Integration Baseline

v0.3 adds the native platform and secure-key integration plan while preserving all v0.2 production laws.

Added:

- iOS sensor adapter design.
- Android sensor adapter design.
- Secure Enclave / Keychain / Android Keystore integration plan.
- Device-bound signing key prototype interface.
- Live contact delivery provider adapter boundary.
- CI pipeline baseline.
- SBOM generation wrapper.
- Dependency scanning plan.
- Expanded security suite under `tests/security/`.
- Accessibility screen-flow prototype.

This release still makes no HIPAA, GDPR/global-compliance, medical-device, clinical, or emergency-system certification claims.

## v0.5 Native Implementation Start

v0.5 starts native implementation scaffolding while preserving all production laws.

Added:

- iOS Swift package scaffold under `native/ios/EchoGuardianKit`.
- Android Kotlin module scaffold under `native/android/echo-guardian-core`.
- Keychain / Keystore proof-of-possession signing prototypes.
- Native minimized sensor observation records.
- Native plain-language status view models.
- Guarded local-outbox delivery provider boundary.
- CI job split for Python core, iOS, Android, security, and SBOM.
- SBOM baseline at `docs/sbom/sbom-v0.5.json`.
- Expanded v0.5 security tests.
- Accessibility screen-flow prototype v0.5.
- Release readiness report v0.5.

Validation:

```text
94 passed
V0.4 RELEASE ARTIFACT CHECK PASSED
```

Still not approved for:

- HIPAA compliance claims
- GDPR/global-compliance claims
- medical-device claims
- emergency-system certification claims
- clinical deployment
- silent enterprise/MDM control


## v0.5 Native Runtime Implementation Start

This package adds native runtime bridge scaffolds for iOS Swift and Android Kotlin:

- Swift sensor observation to core-compatible JSON bridge
- Kotlin sensor observation to core-compatible JSON bridge
- native audit append interfaces
- native policy/status screen models
- Keychain / Keystore proof-of-possession test scaffolds
- guarded provider adapter test harness
- native accessibility screen-flow skeleton
- CI job split with no soft-fail placeholders

Still not approved for HIPAA/GDPR/global-compliance claims, medical-device claims, emergency-system certification claims, clinical deployment, or silent enterprise/MDM control.


## v0.6 Native Runtime Hardening

Echo Guardian v0.6 adds native runtime hardening across iOS, Android, and the Python/core-compatible safety loop. It includes CoreMotion and Android sensor permission/status scaffolds, native-to-core minimized observation bridges, native audit append to the core audit chain, native baseline and severity integration, guarded provider delivery-status persistence, explicit native export package creation, CI artifact enforcement, and expanded native security tests.

Still not approved for HIPAA compliance claims, GDPR/global-compliance claims, medical-device claims, emergency-system certification claims, clinical deployment, or silent enterprise/MDM control.

## v0.7 Device Execution + Signed Native Export

v0.7 adds the first device-execution and signed-native-export foundation:

- physical-device execution checklist
- iOS Keychain persisted signing proof test scaffold
- Android Keystore persisted signing proof test scaffold
- signed native export manifest contract
- native audit checkpoint signing contract
- provider sandbox delivery receipt verification
- native accessibility UI tests
- CI artifact attestation
- release-blocking Android native test verification

Still not approved for HIPAA compliance claims, GDPR/global-compliance claims, medical-device claims, emergency-system certification claims, clinical deployment, or silent enterprise/MDM control.

## v0.8 Physical Device Evidence + Release Attestation

v0.8 adds physical-device evidence and release-attestation scaffolding:

- real iOS device execution evidence format
- real Android device execution evidence format
- signed device-run evidence bundle
- native audit checkpoint export verification
- provider sandbox transcript redaction proof
- accessibility test evidence capture
- CI release attestation bundle
- Android Gradle wrapper inclusion for local reproducible native test execution

Still not approved for HIPAA compliance claims, GDPR/global-compliance claims, medical-device claims, emergency-system certification claims, clinical deployment, or silent enterprise/MDM control.

## v1.0 Foundation Release Candidate

Echo Guardian v1.0 RC adds the final evidence-bound readiness gate for foundation release. The gate records trusted Gradle wrapper evidence, physical iOS and Android execution evidence, signed SBOM verification, external security review completion, privacy review completion, and clinical/legal claim-blocking review.

Current RC decision: **blocked until real device evidence and human review completion records are collected**. This is intentional and prevents unsupported approval claims.

Still not approved for HIPAA compliance claims, GDPR/global-compliance claims, medical-device claims, emergency-system certification claims, clinical deployment, or silent enterprise/MDM control.

