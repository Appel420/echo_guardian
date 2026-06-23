# Schema catalog

This directory contains the JSON Schemas for Echo Guardian v0.2 artifacts.

## Files

- `audit-entry.schema.json`
- `baseline-summary.schema.json`
- `confirmation-state.schema.json`
- `consent-record.schema.json`
- `contact.schema.json`
- `escalation-event.schema.json`
- `event.schema.json`
- `export-manifest.schema.json`
- `health-status.schema.json`
- `local-status.schema.json`
- `policy.schema.json`
- `privacy-rights-request.schema.json`
- `production-cycle-result.schema.json`
- `retention-policy.schema.json`
- `sensor-observation.schema.json`
- `severity-classification.schema.json`

## Validation

Run the test suite from the repository root:

```bash
PYTHONPATH=src python -m pytest -q
```

The schemas are designed to stay local-first, explicit, and strict about hidden behavior, cloud dependency, and private-space monitoring.
