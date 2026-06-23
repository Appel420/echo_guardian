#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from echo_guardian_core.audit import AuditLog
from echo_guardian_core.baseline import BaselineLearningEngine, validate_baseline_summary_schema
from echo_guardian_core.policy import ProductionPolicy
from echo_guardian_core.sensor import SensorObservationRecord


def main() -> int:
    parser = argparse.ArgumentParser(description="Update Echo Guardian local baseline from a minimized sensor observation.")
    parser.add_argument("--policy", required=True, help="Path to production policy JSON")
    parser.add_argument("--observation", required=True, help="Path to sensor observation JSON")
    parser.add_argument("--audit-log", required=True, help="Path to append-only audit JSONL")
    parser.add_argument("--out", required=True, help="Path to write baseline summary JSON")
    parser.add_argument("--schema", default="schemas/baseline-summary.schema.json", help="Baseline summary schema path")
    parser.add_argument("--create", action="store_true", help="Create baseline before ingesting observation")
    args = parser.parse_args()

    policy = ProductionPolicy.load_file(args.policy, schema_path="schemas/policy.schema.json")
    audit_log = AuditLog.open(args.audit_log)
    engine = BaselineLearningEngine(policy=policy, audit_log=audit_log)
    if args.create:
        engine.create_baseline()
    data = json.loads(Path(args.observation).read_text(encoding="utf-8"))
    record = SensorObservationRecord(**data)
    summary = engine.ingest_observation(record)
    validate_baseline_summary_schema(summary, args.schema)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"BASELINE UPDATED: {summary['baseline_id']} status={summary['status']} confidence={summary['confidence']['overall']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
