# Baseline Learning Engine v0.2

Status: implemented in production foundation package.

## Production Rule

The baseline engine consumes only minimized `SensorObservationRecord` objects that already passed the sensor ingestion boundary. It does not store raw sensor samples, transcripts, waveforms, packet captures, or raw event history.

## Implemented

- Local baseline profile model
- Derived-observation ingestion
- `no_baseline`, `learning`, `established`, `degraded`, `reset`, and `replaced` states
- Confidence scoring from observation volume, signal coverage, and quality
- Baseline update records
- Plain-language baseline summaries
- No raw history retention
- Audit entries for baseline creation, update, degradation, reset, and replacement

## Audit Events

- `baseline_created`
- `baseline_updated`
- `baseline_degraded`
- `baseline_reset`
- `baseline_replaced`

Each event records that raw history is not retained.

## Production Boundaries

- Private-space observations are rejected in v0.2.
- Records with `raw_sensor_retained=true` are rejected.
- Raw-like metadata keys are rejected even if they appear inside derived metadata.
- Baseline summaries are plain-language and marked `sensitive_details_included=false`.
