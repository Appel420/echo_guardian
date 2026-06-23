#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = [
    "src/echo_guardian_core/native/physical_evidence.py",
    "tests/security/test_v08_physical_device_evidence_attestation.py",
    "docs/native/v0.8-physical-device-evidence-release-attestation.md",
    "docs/native/v0.8-ios-device-execution-evidence-format.md",
    "docs/native/v0.8-android-device-execution-evidence-format.md",
    "docs/delivery/v0.8-provider-sandbox-transcript-redaction-proof.md",
    "docs/accessibility/v0.8-accessibility-test-evidence-capture.md",
    "docs/release/production-readiness-report-v0.8.json",
    "docs/sbom/sbom-v0.8.json",
    "native/ios/EchoGuardianKit/Sources/EchoGuardianKit/Evidence/DeviceEvidence.swift",
    "native/ios/EchoGuardianKit/Tests/EchoGuardianKitTests/V08EvidenceTests.swift",
    "native/android/echo-guardian-core/src/main/java/org/echoguardian/evidence/DeviceEvidence.kt",
    "native/android/echo-guardian-core/src/test/java/org/echoguardian/V08EvidenceTest.kt",
    "native/android/gradlew",
    "native/android/gradle/wrapper/gradle-wrapper.properties",
    "RELEASE_NOTES_v0.8.md",
]

BLOCKED_CI_TOKENS = ["continue-on-error: true", "|| true", "soft-fail", "allow_failure"]


def main() -> int:
    missing = [rel for rel in REQUIRED if not (ROOT / rel).exists()]
    if missing:
        for rel in missing:
            print(f"MISSING: {rel}")
        return 1
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    blocked = [token for token in BLOCKED_CI_TOKENS if token in ci]
    if blocked:
        print(f"BLOCKED CI TOKENS: {blocked}")
        return 1
    if "./gradlew :echo-guardian-core:testDebugUnitTest" not in ci:
        print("MISSING RELEASE-BLOCKING ANDROID GRADLE WRAPPER TEST COMMAND")
        return 1
    if "check_v08_release_artifacts.py" not in ci:
        print("MISSING V0.8 ARTIFACT CHECK IN CI")
        return 1
    print("V0.8 RELEASE ARTIFACT CHECK PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
