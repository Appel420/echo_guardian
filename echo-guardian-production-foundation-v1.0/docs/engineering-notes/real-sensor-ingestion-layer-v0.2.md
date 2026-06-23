# Real Sensor Ingestion Layer v0.2

Status: implemented in the production foundation package.

## Purpose

The sensor ingestion layer is the production boundary between platform sensor adapters and Echo Guardian's local safety core. It accepts real platform-derived device signals, converts them into minimized observation records, and refuses raw sensor retention by default.

## Implemented

- `SensorAdapter` interface for platform-specific adapters.
- `DeviceSignalSample` ephemeral adapter output.
- `SensorObservationRecord` production storage record.
- `SensorIngestionEngine` policy-enforced ingestion boundary.
- Permission and availability health states.
- Derived metadata-only observation pipeline.
- Hard block for bathroom and bedroom ingestion in v0.2.
- Audit entries for:
  - `sensor_available`
  - `sensor_observation`
  - `sensor_degraded`
  - `sensor_permission_changed`
- JSON Schema for sensor observation records.
- CLI tool for ingesting a minimized local observation.

## Production Data Rule

Raw samples may exist only ephemerally inside platform adapters. They must not cross into the ingestion engine, audit log, observation records, exports, or local persistent stores.

Forbidden derived metadata keys include:

- `raw`
- `raw_data`
- `raw_sample`
- `samples`
- `audio_buffer`
- `video_frame`
- `transcript`
- `waveform`
- `packet_capture`

## Private-Space Rule

Bathroom and bedroom ingestion are hard-blocked by default in v0.2. Future builds may add private-space support only with separate explicit consent, visible state, and expanded review.
