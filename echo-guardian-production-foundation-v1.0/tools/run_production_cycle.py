#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from echo_guardian_core.audit import AuditLog
from echo_guardian_core.escalation import load_contacts
from echo_guardian_core.integration import ProductionIntegrationRunner
from echo_guardian_core.policy import ProductionPolicy
from echo_guardian_core.sensor import DeviceSignalSample
from echo_guardian_core.storage import LocalStoragePaths


def main() -> int:
    parser = argparse.ArgumentParser(description="Run one local Echo Guardian production safety cycle.")
    parser.add_argument("--policy", required=True)
    parser.add_argument("--audit-log", required=True)
    parser.add_argument("--storage-root", required=True)
    parser.add_argument("--sample", required=True, help="JSON DeviceSignalSample-like input.")
    parser.add_argument("--contacts", default=None)
    parser.add_argument("--out", required=True)
    parser.add_argument("--confirmation", choices=["safe", "needs_help", "timeout", "none"], default="safe")
    parser.add_argument("--confirmation-mode", choices=["voice", "text", "touch"], default="touch")
    args = parser.parse_args()

    policy = ProductionPolicy.load_file(args.policy)
    audit_log = AuditLog.open(args.audit_log)
    paths = LocalStoragePaths.create(args.storage_root)
    sample_data = json.loads(Path(args.sample).read_text(encoding="utf-8"))
    sample = DeviceSignalSample(**sample_data)
    contacts = load_contacts(args.contacts) if args.contacts else []

    runner = ProductionIntegrationRunner(
        policy=policy,
        audit_log=audit_log,
        storage_paths=paths,
        contacts=contacts,
        outbox_dir=Path(args.storage_root) / "export" / "local_outbox",
    )
    result = runner.run_cycle(sample=sample, confirmation_input=args.confirmation, confirmation_mode=args.confirmation_mode)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    print(result.plain_language_summary)
    print(f"audit_verified={result.audit_verified}")
    print(f"output={out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
