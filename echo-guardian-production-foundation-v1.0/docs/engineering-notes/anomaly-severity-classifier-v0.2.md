# Echo Guardian — Anomaly + Severity Classifier v0.2

Status: implemented in the production foundation package.

## Purpose

The classifier compares minimized local sensor observations against the local baseline profile and produces deterministic, confidence-aware safety severity decisions. It is production-live code, not fake demo behavior. It uses real minimized observation records, real baseline state, real audit entries, and plain-language explanations.

## Implemented

- Baseline-vs-observation comparison.
- Deterministic severity classification:
  - `normal`
  - `unusual`
  - `concerning`
  - `severe`
  - `emergency`
- Conservative thresholds during `learning`, `reset`, `replaced`, and `degraded` baseline states.
- Confidence-aware decision records.
- Plain-language explanation for every classification.
- Audit entries for:
  - `anomaly_detected`
  - `severity_classified`
- Raw-history and raw-like metadata rejection.
- Private-space hard block for classification in v0.2.

## Safety Boundaries

The classifier does not claim medical certainty. It reports safety-state classifications based on minimized local signals and baseline comparison.

During learning states, weak deviations are capped to `unusual` or `concerning` unless a high-confidence critical safety signal is present. Emergency classification requires a strong explicit critical signal plus sufficient confidence and an established baseline.

## Plain-Language Standard

Every classification produces `plain_language_explanation` and `recommended_next_action`, suitable for a child, elderly person, caregiver, or non-technical reviewer.

## Audit Rule

Every classification writes a `severity_classified` audit entry. If the decision is an anomaly, it also writes an `anomaly_detected` audit entry before the classification record.

## CLI

```bash
PYTHONPATH=src python tools/classify_observation.py \
  --policy examples/local-live-personal/production_policy_v0.2.json \
  --observation examples/local-live-personal/sensor_observation_v0.2.json \
  --baseline examples/local-live-personal/baseline_summary_v0.2.json \
  --audit-log /tmp/echo_guardian_anomaly_audit.jsonl \
  --out /tmp/echo_guardian_severity_classification.json
```

## Production Non-Negotiables

- No raw sensor history retention.
- No private-space classification in v0.2.
- No hidden decisions.
- No unaudited severity classification.
- No unsupported medical-device or emergency-service claim.
