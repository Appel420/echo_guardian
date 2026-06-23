#!/usr/bin/env python3
from __future__ import annotations
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = [
    "src/echo_guardian_core/release/foundation_rc.py",
    "tests/security/test_v10_foundation_release_candidate.py",
    "docs/native/v1.0-trusted-gradle-wrapper-evidence.md",
    "docs/native/v1.0-ios-physical-device-evidence.md",
    "docs/native/v1.0-android-local-native-test-evidence.md",
    "docs/sbom/signed-sbom-attestation-v1.0.md",
    "docs/sbom/sbom-v1.0.json",
    "docs/review/external-security-review-package-v1.0.md",
    "docs/review/privacy-review-package-v1.0.md",
    "docs/review/clinical-legal-claim-blocking-review-v1.0.md",
    "docs/release/v1.0-foundation-readiness-gate.md",
    "docs/release/production-readiness-report-v1.0.json",
    "examples/local-live-personal/v10_foundation_release_candidate/trusted_gradle_wrapper_evidence.json",
    "examples/local-live-personal/v10_foundation_release_candidate/ios_physical_device_evidence.json",
    "examples/local-live-personal/v10_foundation_release_candidate/android_local_native_test_evidence.json",
    "examples/local-live-personal/v10_foundation_release_candidate/signed_sbom_attestation.json",
    "examples/local-live-personal/v10_foundation_release_candidate/signed_sbom_verification.json",
    "examples/local-live-personal/v10_foundation_release_candidate/external_security_review_completion.json",
    "examples/local-live-personal/v10_foundation_release_candidate/privacy_review_completion.json",
    "examples/local-live-personal/v10_foundation_release_candidate/clinical_legal_claim_blocking_review.json",
    "examples/local-live-personal/v10_foundation_release_candidate/automated_claim_blocking_review.json",
    "examples/local-live-personal/v10_foundation_release_candidate/v1_foundation_readiness_gate_result.json",
    "RELEASE_NOTES_v1.0.md",
]
BLOCKED_CI_TOKENS = ["continue-on-error: true", "|| true", "soft-fail", "allow_failure"]


def main() -> int:
    missing = [rel for rel in REQUIRED if not (ROOT / rel).exists()]
    if missing:
        for rel in missing:
            print(f"MISSING: {rel}")
        return 1
    gate = json.loads((ROOT / "examples/local-live-personal/v10_foundation_release_candidate/v1_foundation_readiness_gate_result.json").read_text(encoding="utf-8"))
    if gate.get("schema_version") != "1.0-rc":
        print("INVALID GATE SCHEMA")
        return 1
    if gate.get("decision") != "blocked":
        print("EXPECTED V1.0 RC GATE TO REMAIN BLOCKED UNTIL REAL DEVICE AND REVIEW EVIDENCE IS COLLECTED")
        return 1
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    blocked = [token for token in BLOCKED_CI_TOKENS if token in ci]
    if blocked:
        print(f"BLOCKED CI TOKENS: {blocked}")
        return 1
    for token in ["check_v09_release_artifacts.py", "check_v10_release_artifacts.py", "./gradlew :echo-guardian-core:testDebugUnitTest", "swift test"]:
        if token not in ci:
            print(f"MISSING CI TOKEN: {token}")
            return 1
    print("V1.0 RELEASE CANDIDATE ARTIFACT CHECK PASSED")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
