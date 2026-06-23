# Native Android Sensor Adapter Design v0.3

## Objective

Integrate real Android device signals while preserving minimized local-only safety processing.

## Candidate Signal Sources

- SensorManager: accelerometer, gyroscope, significant motion where supported.
- Bluetooth / nearby device presence: platform-approved APIs only.
- Network reachability: escalation availability only, not core safety dependency.
- Audio level metadata: explicit authorization required; no raw audio retention.

## Adapter Contract

Android adapters must emit minimized `SensorObservationRecord` objects. Raw streams and raw-like keys are rejected by the shared core.

## Android Keystore Alignment

The adapter must not manage cryptographic keys directly. Device-bound signing and encryption keys are owned by the secure-key layer.

## Permission Handling

Permission denial, revocation, or sensor unavailability must be visible in the health monitor and audit log.

## Private-Space Rule

Private-space monitoring is blocked by policy in v0.3. Android adapters must not enable bathroom or bedroom ingestion by default.
