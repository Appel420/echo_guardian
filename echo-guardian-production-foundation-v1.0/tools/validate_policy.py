#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from echo_guardian_core.policy import ProductionPolicy


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate an Echo Guardian production policy.")
    parser.add_argument("policy", type=Path)
    parser.add_argument("--schema", type=Path, default=Path("schemas/policy.schema.json"))
    args = parser.parse_args()

    policy = ProductionPolicy.load_file(args.policy, schema_path=args.schema)
    print(f"POLICY VALIDATION PASSED: {policy.policy_id} v{policy.policy_version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
