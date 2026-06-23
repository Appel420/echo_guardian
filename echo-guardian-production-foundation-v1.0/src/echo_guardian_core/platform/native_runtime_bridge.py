from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from echo_guardian_core.sensor import DeviceSignalSample, SensorPolicyViolation

FORBIDDEN_NATIVE_KEYS = {
    "raw",
    "raw_data",
    "raw_sample",
    "samples",
    "audio_buffer",
    "video_frame",
    "transcript",
    "waveform",
    "packet_capture",
}


@dataclass(frozen=True)
class NativeCoreObservation:
    """Core-compatible observation received from native iOS/Android runtime bridge."""

    schema_version: str
    observation_id: str
    created_at: str
    sensor_id: str
    signal_type: str
    space_id: str
    private_space: bool
    quality: str
    permission_state: str
    availability_state: str
    raw_sensor_retained: bool
    derived_metadata: dict[str, Any]
    plain_language_summary: str

    @classmethod
    def from_native_json(cls, data: dict[str, Any]) -> "NativeCoreObservation":
        required = {
            "schema_version",
            "observation_id",
            "created_at",
            "sensor_id",
            "signal_type",
            "space_id",
            "private_space",
            "quality",
            "permission_state",
            "availability_state",
            "raw_sensor_retained",
            "derived_metadata",
            "plain_language_summary",
        }
        missing = sorted(required - set(data))
        if missing:
            raise SensorPolicyViolation(f"native observation missing required fields: {missing}")
        obs = cls(**{k: data[k] for k in required})
        obs.validate_product_laws()
        return obs

    def validate_product_laws(self) -> None:
        if self.private_space:
            raise SensorPolicyViolation("native private-space observation blocked by default")
        if self.space_id in {"bathroom", "bedroom"}:
            raise SensorPolicyViolation("native bathroom/bedroom observation blocked by default")
        if self.raw_sensor_retained:
            raise SensorPolicyViolation("native raw sensor retention blocked")
        bad = sorted(FORBIDDEN_NATIVE_KEYS.intersection(self.derived_metadata.keys()))
        if bad:
            raise SensorPolicyViolation(f"native derived metadata contains raw-like keys: {bad}")

    def to_device_signal_sample(self) -> DeviceSignalSample:
        self.validate_product_laws()
        return DeviceSignalSample(
            sensor_id=self.sensor_id,
            signal_type=self.signal_type,  # type: ignore[arg-type]
            space_id=self.space_id,
            private_space=False,
            captured_at=self.created_at,
            quality=self.quality,  # type: ignore[arg-type]
            derived_metadata=self.derived_metadata,
            raw_sample=None,
            permission_state=self.permission_state,  # type: ignore[arg-type]
            availability_state=self.availability_state,  # type: ignore[arg-type]
        )
