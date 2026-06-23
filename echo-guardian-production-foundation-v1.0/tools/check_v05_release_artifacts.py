#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = [
    "native/ios/EchoGuardianKit/Sources/EchoGuardianKit/Runtime/CoreJSONBridge.swift",
    "native/ios/EchoGuardianKit/Sources/EchoGuardianKit/Audit/NativeAuditAppender.swift",
    "native/ios/EchoGuardianKit/Sources/EchoGuardianKit/Policy/NativePolicyStatus.swift",
    "native/ios/EchoGuardianKit/Sources/EchoGuardianKit/Accessibility/AccessibilityFlowModel.swift",
    "native/ios/EchoGuardianKit/Tests/EchoGuardianKitTests/V05RuntimeTests.swift",
    "native/android/echo-guardian-core/src/main/java/org/echoguardian/runtime/CoreJsonBridge.kt",
    "native/android/echo-guardian-core/src/main/java/org/echoguardian/audit/NativeAuditAppender.kt",
    "native/android/echo-guardian-core/src/main/java/org/echoguardian/policy/NativePolicyStatus.kt",
    "native/android/echo-guardian-core/src/main/java/org/echoguardian/accessibility/AccessibilityFlowModel.kt",
    "native/android/echo-guardian-core/src/test/java/org/echoguardian/V05RuntimeTest.kt",
    "docs/native/v0.5-native-runtime-implementation.md",
    "docs/secure-keys/v0.5-keychain-keystore-persisted-key-tests.md",
    "docs/delivery/v0.5-guarded-provider-test-harness.md",
    "docs/accessibility/accessibility-screen-flow-prototype-v0.5.md",
    "docs/release/production-readiness-report-v0.5.json",
    "docs/sbom/sbom-v0.5.json",
    "tests/security/test_v05_native_runtime_implementation.py",
    "RELEASE_NOTES_v0.5.md",
    ".github/workflows/ci.yml",
]
missing = [p for p in REQUIRED if not (ROOT / p).exists()]
if missing:
    raise SystemExit("V0.5 RELEASE ARTIFACT CHECK FAILED: missing " + ", ".join(missing))
ci = (ROOT / ".github/workflows/ci.yml").read_text()
if "|| true" in ci or "continue-on-error" in ci:
    raise SystemExit("V0.5 RELEASE ARTIFACT CHECK FAILED: CI contains a soft-fail placeholder")
print("V0.5 RELEASE ARTIFACT CHECK PASSED")
