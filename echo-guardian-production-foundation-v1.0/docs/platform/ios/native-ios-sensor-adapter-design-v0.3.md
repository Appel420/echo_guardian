# Native iOS Sensor Adapter Design v0.3

## Objective

Integrate real iOS device signals while preserving minimized local-only safety processing.

## Candidate Signal Sources

- Core Motion: accelerometer, gyroscope, device motion where permission and device state allow.
- Bluetooth / nearby device presence: only through platform-approved APIs and user-visible permission flows.
- Network reachability: used for escalation availability, not core safety dependency.
- Audio level metadata: only if explicitly authorized, and no raw audio retention.

## Adapter Contract

Native sensor adapters must emit minimized `SensorObservationRecord` objects only. Raw samples, audio buffers, transcripts, video frames, packet captures, and unminimized streams must not cross the adapter boundary.

## Required Health States

- healthy
- degraded
- critical
- unavailable
- unknown

## Permission Handling

Every permission state change must emit an audit event. If a permission is denied or revoked, the adapter must report a degraded or unavailable state instead of silently failing.

## Private-Space Rule

Bathroom and bedroom spaces remain blocked in v0.3 unless a future reviewed policy explicitly enables them. Native adapters must not bypass this block.
