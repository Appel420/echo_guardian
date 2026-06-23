#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from echo_guardian_core.anomaly import AnomalySeverityClassifier, baseline_profile_from_summary, validate_classification_schema
from echo_guardian_core.audit import AuditLog
from echo_guardian_core.policy import ProductionPolicy
from echo_guardian_core.sensor import SensorObservationRecord


def main() -> int:
    parser = argparse.ArgumentParser(description="Classify a minimized local observation against a baseline summary.")
    parser.add_argument("--policy", required=True)
    parser.add_argument("--observation", required=True)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--audit-log", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--schema", default="schemas/severity-classification.schema.json")
    args = parser.parse_args()

    policy = ProductionPolicy.load_file(args.policy, schema_path="schemas/policy.schema.json")
    observation_data = json.loads(Path(args.observation).read_text(encoding="utf-8"))
    observation = SensorObservationRecord(**observation_data)
    baseline_summary = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
    baseline = baseline_profile_from_summary(baseline_summary)

    classifier = AnomalySeverityClassifier(policy=policy, audit_log=AuditLog.open(args.audit_log))
    record = classifier.classify(observation=observation, baseline=baseline)
    data = record.to_dict()
    validate_classification_schema(data, args.schema)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(data, sort_keys=True, indent=2), encoding="utf-8")
    print(f"CLASSIFICATION COMPLETE: severity={record.severity} anomaly={record.is_anomaly} reason={record.primary_reason_code}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
