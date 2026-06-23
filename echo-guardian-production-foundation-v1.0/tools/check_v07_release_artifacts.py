#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED = [
    "docs/native/v0.7-device-execution-signed-native-export.md",
    "docs/secure-keys/v0.7-persisted-signing-proof-tests.md",
    "docs/delivery/v0.7-provider-sandbox-delivery-receipt-verification.md",
    "docs/accessibility/v0.7-native-accessibility-ui-tests.md",
    "docs/release/production-readiness-report-v0.7.json",
    "docs/sbom/sbom-v0.7.json",
    "src/echo_guardian_core/native/device_execution.py",
    "native/ios/EchoGuardianKit/Sources/EchoGuardianKit/Export/SignedNativeExportManifest.swift",
    "native/ios/EchoGuardianKit/Sources/EchoGuardianKit/Keys/PersistedSigningProof.swift",
    "native/ios/EchoGuardianKit/Sources/EchoGuardianKit/Receipts/ProviderSandboxReceipt.swift",
    "native/ios/EchoGuardianKit/Tests/EchoGuardianKitTests/V07DeviceExecutionTests.swift",
    "native/android/echo-guardian-core/src/main/java/org/echoguardian/export/SignedNativeExportManifest.kt",
    "native/android/echo-guardian-core/src/main/java/org/echoguardian/keys/PersistedSigningProof.kt",
    "native/android/echo-guardian-core/src/main/java/org/echoguardian/receipts/ProviderSandboxReceipt.kt",
    "native/android/echo-guardian-core/src/test/java/org/echoguardian/V07DeviceExecutionTest.kt",
    "tests/security/test_v07_device_execution_signed_export.py",
    "RELEASE_NOTES_v0.7.md",
]

BLOCKED_CI_TOKENS = ["continue-on-error: true", "|| true", "soft-fail", "allow_failure"]


def main() -> int:
    missing = [rel for rel in REQUIRED if not (ROOT / rel).exists()]
    if missing:
        for rel in missing:
            print(f"MISSING: {rel}")
        return 1

    report = json.loads((ROOT / "docs/release/production-readiness-report-v0.7.json").read_text(encoding="utf-8"))
    required_not_approved = {
        "HIPAA compliance claims",
        "GDPR/global-compliance claims",
        "medical-device claims",
        "emergency-system certification claims",
        "clinical deployment",
        "silent enterprise/MDM control",
    }
    if not required_not_approved.issubset(set(report.get("not_approved_for", []))):
        print("FAILED: v0.7 report is missing required non-approval statements")
        return 1

    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    for token in BLOCKED_CI_TOKENS:
        if token in ci:
            print(f"FAILED: CI contains soft-fail token: {token}")
            return 1
    for token in ["swift test", ":echo-guardian-core:testDebugUnitTest", "check_v07_release_artifacts.py"]:
        if token not in ci:
            print(f"FAILED: CI missing required release-blocking command: {token}")
            return 1

    print("V0.7 RELEASE ARTIFACT CHECK PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
