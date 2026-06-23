#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = [
    "docs/native/v0.6-native-runtime-hardening.md",
    "docs/release/production-readiness-report-v0.6.json",
    "docs/sbom/sbom-v0.6.json",
    "RELEASE_NOTES_v0.6.md",
    "src/echo_guardian_core/native/runtime_hardening.py",
    "native/ios/EchoGuardianKit/Sources/EchoGuardianKit/Sensors/CoreMotionPermissionStatus.swift",
    "native/ios/EchoGuardianKit/Sources/EchoGuardianKit/Runtime/NativeCoreCycleBridge.swift",
    "native/android/echo-guardian-core/src/main/java/org/echoguardian/sensors/AndroidSensorPermissionStatus.kt",
    "native/android/echo-guardian-core/src/main/java/org/echoguardian/runtime/NativeCoreCycleBridge.kt",
    "tests/security/test_v06_native_runtime_hardening.py",
]


def main() -> int:
    missing = [rel for rel in REQUIRED if not (ROOT / rel).exists()]
    if missing:
        print("V0.6 RELEASE ARTIFACT CHECK FAILED")
        for rel in missing:
            print(f"missing: {rel}")
        return 1
    report = json.loads((ROOT / "docs/release/production-readiness-report-v0.6.json").read_text(encoding="utf-8"))
    required_denials = {
        "HIPAA compliance claims",
        "GDPR/global-compliance claims",
        "medical-device claims",
        "emergency-system certification claims",
        "clinical deployment",
        "silent enterprise/MDM control",
    }
    if not required_denials.issubset(set(report.get("not_approved_for", []))):
        print("V0.6 RELEASE ARTIFACT CHECK FAILED: missing required denials")
        return 1
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    banned = ["continue-on-error: true", "|| true", "soft-fail", "allow-failure"]
    for token in banned:
        if token in ci:
            print(f"V0.6 RELEASE ARTIFACT CHECK FAILED: soft-fail token present: {token}")
            return 1
    print("V0.6 RELEASE ARTIFACT CHECK PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
