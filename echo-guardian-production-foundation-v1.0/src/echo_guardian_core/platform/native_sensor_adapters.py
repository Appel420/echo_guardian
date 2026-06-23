"""Native platform sensor adapter contracts for Echo Guardian v0.3.

This module defines production-intent interfaces only. Platform-specific iOS and
Android code must preserve the minimized SensorObservationRecord boundary used by
core v0.2 logic.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Protocol


@dataclass(frozen=True)
class NativeSensorCapability:
    platform: str
    signal_type: str
    permission_name: str
    raw_retention_allowed: bool = False
    private_space_allowed_by_default: bool = False


@dataclass(frozen=True)
class NativeSensorAdapterPlan:
    platform: str
    capabilities: List[NativeSensorCapability]
    production_laws: Dict[str, bool] = field(default_factory=lambda: {
        "no_raw_sensor_retention_by_default": True,
        "no_private_space_by_default": True,
        "permission_changes_are_audited": True,
        "health_state_is_visible": True,
    })


class NativeSensorAdapter(Protocol):
    """Protocol for native adapters.

    Implementations must return minimized derived metadata records. Raw samples
    must never cross this boundary.
    """

    def read_minimized_observation(self, space_id: str) -> Dict[str, Any]:
        ...

    def health_state(self) -> str:
        ...


def ios_adapter_plan() -> NativeSensorAdapterPlan:
    return NativeSensorAdapterPlan(
        platform="ios",
        capabilities=[
            NativeSensorCapability("ios", "motion", "CoreMotion"),
            NativeSensorCapability("ios", "device_presence", "Bluetooth/LocalNetwork"),
            NativeSensorCapability("ios", "sound_level", "Microphone", raw_retention_allowed=False),
        ],
    )


def android_adapter_plan() -> NativeSensorAdapterPlan:
    return NativeSensorAdapterPlan(
        platform="android",
        capabilities=[
            NativeSensorCapability("android", "motion", "SensorManager"),
            NativeSensorCapability("android", "device_presence", "Bluetooth/NearbyDevices"),
            NativeSensorCapability("android", "sound_level", "Microphone", raw_retention_allowed=False),
        ],
    )
