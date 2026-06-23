#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from echo_guardian_core.audit import AuditLog
from echo_guardian_core.export import ExportPackageBuilder, ExportRequest
from echo_guardian_core.policy import ProductionPolicy


def main() -> int:
    parser = argparse.ArgumentParser(description="Create an explicit user-confirmed local Echo Guardian export package.")
    parser.add_argument("--policy", required=True)
    parser.add_argument("--audit", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--baseline")
    parser.add_argument("--status")
    parser.add_argument("--schema", default="schemas/export-manifest.schema.json")
    parser.add_argument("--confirm", action="store_true", help="Required. Confirms user-requested local export.")
    args = parser.parse_args()

    policy = ProductionPolicy.load_file(args.policy)
    audit_log = AuditLog.open(args.audit)
    builder = ExportPackageBuilder(policy=policy, audit_log=audit_log)
    manifest = builder.create_export(
        request=ExportRequest(export_type="full_export", user_confirmed=args.confirm),
        export_dir=args.out,
        audit_chain_path=args.audit,
        policy_path=args.policy,
        baseline_path=args.baseline,
        status_path=args.status,
        schema_path=args.schema,
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
