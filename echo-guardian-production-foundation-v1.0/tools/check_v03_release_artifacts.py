#!/usr/bin/env python3
from pathlib import Path
from echo_guardian_core.security.release_artifacts import missing_required_artifacts

root = Path(__file__).resolve().parents[1]
missing = missing_required_artifacts(root)
if missing:
    print("MISSING V0.3 ARTIFACTS:")
    for item in missing:
        print(f"- {item}")
    raise SystemExit(1)
print("V0.3 RELEASE ARTIFACT CHECK PASSED")
