#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from echo_guardian_core.audit import AuditLog, utc_now_iso
from echo_guardian_core.policy import ProductionPolicy
from echo_guardian_core.sensor import DeviceSignalSample, SensorIngestionEngine, validate_sensor_observation_schema


def main() -> int:
    parser = argparse.ArgumentParser(description="Ingest a minimized local sensor observation into Echo Guardian audit state.")
    parser.add_argument("--policy", required=True)
    parser.add_argument("--audit", required=True)
    parser.add_argument("--schema", default=str(ROOT / "schemas" / "sensor-observation.schema.json"))
    parser.add_argument("--sensor-id", required=True)
    parser.add_argument("--signal-type", required=True)
    parser.add_argument("--space-id", required=True)
    parser.add_argument("--metadata-json", required=True, help="JSON object containing derived metadata only; raw samples are rejected.")
    parser.add_argument("--quality", default="good")
    args = parser.parse_args()

    policy = ProductionPolicy.load_file(args.policy)
    audit = AuditLog.open(args.audit)
    metadata = json.loads(args.metadata_json)
    if not isinstance(metadata, dict):
        raise SystemExit("--metadata-json must decode to an object")
    sample = DeviceSignalSample(
        sensor_id=args.sensor_id,
        signal_type=args.signal_type,
        space_id=args.space_id,
        private_space=args.space_id in {"bathroom", "bedroom"},
        captured_at=utc_now_iso(),
        quality=args.quality,
        derived_metadata=metadata,
        raw_sample=None,
    )
    record = SensorIngestionEngine(policy=policy, audit_log=audit).ingest(sample)
    data = record.to_dict()
    validate_sensor_observation_schema(data, args.schema)
    print(json.dumps(data, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
