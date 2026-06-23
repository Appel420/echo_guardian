#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = [
    "native/ios/EchoGuardianKit/Package.swift",
    "native/ios/EchoGuardianKit/Sources/EchoGuardianKit/Keys/DeviceSigningKey.swift",
    "native/ios/EchoGuardianKit/Sources/EchoGuardianKit/Sensors/MinimizedSensorObservation.swift",
    "native/ios/EchoGuardianKit/Sources/EchoGuardianKit/Status/StatusViewModel.swift",
    "native/ios/EchoGuardianKit/Sources/EchoGuardianKit/Escalation/GuardedDeliveryAdapter.swift",
    "native/android/settings.gradle.kts",
    "native/android/echo-guardian-core/build.gradle.kts",
    "native/android/echo-guardian-core/src/main/java/org/echoguardian/keys/DeviceSigningKeyManager.kt",
    "native/android/echo-guardian-core/src/main/java/org/echoguardian/sensors/MinimizedSensorObservation.kt",
    "native/android/echo-guardian-core/src/main/java/org/echoguardian/status/StatusViewModel.kt",
    "native/android/echo-guardian-core/src/main/java/org/echoguardian/delivery/GuardedDeliveryProvider.kt",
    "docs/native/v0.4-native-implementation-start.md",
    "docs/secure-keys/v0.4-keychain-keystore-proof-of-possession.md",
    "docs/delivery/v0.4-guarded-provider-implementation.md",
    "docs/accessibility/accessibility-screen-flow-prototype-v0.4.md",
    "docs/release/production-readiness-report-v0.4.json",
    "RELEASE_NOTES_v0.4.md",
    ".github/workflows/ci.yml",
]

missing = [p for p in REQUIRED if not (ROOT / p).exists()]
if missing:
    raise SystemExit("V0.4 RELEASE ARTIFACT CHECK FAILED: missing " + ", ".join(missing))
print("V0.4 RELEASE ARTIFACT CHECK PASSED")
