import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_release_readiness_report_exists_and_passes_gate():
    report_path = ROOT / "docs" / "release" / "production-readiness-report-v0.2.json"
    assert report_path.exists()
    report = json.loads(report_path.read_text())
    assert report["release"] == "production-foundation-v0.2"
    assert report["release_status"] == "PASS_WITH_LIMITATIONS"
    assert report["test_summary"]["tests_failed"] == 0
    assert report["release_gate_decision"]["decision"] == "approved_for_v0.2_production_foundation_baseline"


def test_all_product_laws_have_pass_status():
    report = json.loads((ROOT / "docs" / "release" / "production-readiness-report-v0.2.json").read_text())
    laws = report["production_laws"]
    assert len(laws) >= 9
    assert all(law["status"] == "pass" for law in laws)


def test_release_notes_and_limitations_are_present():
    required = [
        ROOT / "RELEASE_NOTES_v0.2.md",
        ROOT / "docs" / "release" / "production-readiness-summary-v0.2.md",
        ROOT / "docs" / "release" / "known-limitations-v0.2.md",
        ROOT / "docs" / "release" / "open-risks-v0.2.md",
        ROOT / "docs" / "release" / "next-release-requirements-v0.3.md",
    ]
    for path in required:
        assert path.exists()
        assert path.read_text().strip()
