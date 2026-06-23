# Production Integration Runner v0.2

## Purpose

The Production Integration Runner executes one real local Echo Guardian safety loop:

1. Policy gate before monitoring starts
2. Health readiness gate before monitoring starts
3. Sensor ingestion from a real device-signal sample
4. Baseline update from minimized derived metadata
5. Severity classification
6. Confirmation decision when required
7. Guarded escalation decision when required
8. Plain-language local status output
9. End-of-cycle audit verification

This runner is production-intent. It is not a fake demo path. Test/replay inputs may be used by the harness, but the production path uses the same policy, audit, sensor, baseline, classification, confirmation, escalation, status, and health modules.

## Product Laws Enforced

- No cloud dependency for the core loop
- No private-space monitoring in v0.2
- No hidden behavior
- No raw sensor retention
- Policy gate must pass before monitoring
- Health readiness gate must pass before monitoring
- Every state-changing decision is audit-recorded
- Audit verification runs at the end of the cycle
- Emergency services are not contacted by default

## Primary Files

```text
src/echo_guardian_core/integration.py
tools/run_production_cycle.py
schemas/production-cycle-result.schema.json
tests/unit/test_integration.py
examples/local-live-personal/production_cycle_result_v0.2.json
examples/local-live-personal/production_cycle_audit_v0.2.jsonl
```

## Example Command

```bash
PYTHONPATH=src python tools/run_production_cycle.py \
  --policy examples/local-live-personal/production_policy_v0.2.json \
  --audit-log examples/local-live-personal/production_cycle_audit_v0.2.jsonl \
  --storage-root examples/local-live-personal/production_cycle_store_v0.2 \
  --sample examples/local-live-personal/production_cycle_sample_v0.2.json \
  --out examples/local-live-personal/production_cycle_result_v0.2.json \
  --confirmation safe
```

## Current Validation

```text
77 passed
AUDIT VERIFICATION PASSED: 9 entries
```
