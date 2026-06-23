#!/usr/bin/env python3
"""Generate a minimal local SBOM without network access."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQ = ROOT / "requirements.txt"


def build_sbom(version: str) -> dict:
    components = []
    if REQ.exists():
        for line in REQ.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name = line
            pinned = None
            if "==" in line:
                name, pinned = line.split("==", 1)
            elif ">=" in line:
                name, pinned = line.split(">=", 1)
                pinned = ">=" + pinned
            components.append({"type": "library", "name": name, "version": pinned})
    components.extend([
        {"type": "platform", "name": "CryptoKit", "version": "Apple platform"},
        {"type": "platform", "name": "Keychain", "version": "Apple platform"},
        {"type": "platform", "name": "Android Keystore", "version": "Android platform"},
    ])
    return {
        "bomFormat": "CycloneDX-compatible-minimal",
        "specVersion": "1.5-minimal",
        "metadata": {"component": {"name": "echo-guardian-production-foundation", "version": version}},
        "components": components,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="docs/sbom/sbom-v0.5.json")
    parser.add_argument("--version", default="0.5")
    args = parser.parse_args()
    out = ROOT / args.output
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(build_sbom(args.version), indent=2, sort_keys=True) + "\n")
    print(str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
