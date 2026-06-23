"""Release artifact checks for v0.3."""

from pathlib import Path

REQUIRED_V03_ARTIFACTS = [
    "docs/platform/native-platform-secure-key-integration-plan-v0.3.md",
    "docs/platform/ios/native-ios-sensor-adapter-design-v0.3.md",
    "docs/platform/android/native-android-sensor-adapter-design-v0.3.md",
    "docs/secure-keys/secure-key-integration-plan-v0.3.md",
    "docs/delivery/live-contact-delivery-provider-adapter-v0.3.md",
    "docs/ci/ci-pipeline-v0.3.md",
    "docs/sbom/sbom-generation-plan-v0.3.md",
    "docs/security/dependency-scanning-plan-v0.3.md",
    "docs/accessibility/accessibility-screen-flow-prototype-v0.3.md",
    "RELEASE_NOTES_v0.3.md",
]


def missing_required_artifacts(root: Path) -> list[str]:
    return [artifact for artifact in REQUIRED_V03_ARTIFACTS if not (root / artifact).exists()]
