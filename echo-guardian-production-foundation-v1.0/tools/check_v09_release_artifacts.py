#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = [
    "src/echo_guardian_core/release/external_review.py",
    "tests/security/test_v09_reproducible_external_review.py",
    "docs/native/v0.9-reproducible-native-build-external-review-prep.md",
    "docs/native/v0.9-trusted-gradle-wrapper-generation.md",
    "docs/native/v0.9-android-local-test-evidence-format.md",
    "docs/native/v0.9-ios-physical-device-test-checklist.md",
    "docs/sbom/signed-sbom-attestation-v0.9.md",
    "docs/sbom/sbom-v0.9.json",
    "docs/review/dependency-license-report-v0.9.md",
    "docs/review/external-security-review-package-v0.9.md",
    "docs/review/privacy-review-package-v0.9.md",
    "docs/review/clinical-legal-claim-blocking-review-checklist-v0.9.md",
    "docs/release/v1.0-foundation-release-candidate-gate-v0.9.md",
    "docs/release/production-readiness-report-v0.9.json",
    "examples/local-live-personal/v09_reproducible_external_review/signed_sbom_attestation.json",
    "examples/local-live-personal/v09_reproducible_external_review/dependency_license_report.json",
    "examples/local-live-personal/v09_reproducible_external_review/claim_blocking_checklist.json",
    "examples/local-live-personal/v09_reproducible_external_review/v1_foundation_release_candidate_gate.json",
    "native/android/gradlew",
    "native/android/gradle/wrapper/gradle-wrapper.properties",
    "RELEASE_NOTES_v0.9.md",
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
    required_ci = [
        "check_v06_release_artifacts.py",
        "check_v07_release_artifacts.py",
        "check_v08_release_artifacts.py",
        "check_v09_release_artifacts.py",
        "./gradlew :echo-guardian-core:testDebugUnitTest",
        "swift test",
    ]
    for token in required_ci:
        if token not in ci:
            print(f"MISSING CI TOKEN: {token}")
            return 1
    print("V0.9 RELEASE ARTIFACT CHECK PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
