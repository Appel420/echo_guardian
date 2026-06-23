#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from echo_guardian_core.audit import AuditLog
from echo_guardian_core.health import HealthMonitor, validate_health_schema
from echo_guardian_core.policy import ProductionPolicy
from echo_guardian_core.sensor import SensorCapability
from echo_guardian_core.storage import LocalStoragePaths


def main() -> int:
    parser = argparse.ArgumentParser(description="Create an Echo Guardian operational health/readiness report.")
    parser.add_argument("--policy", required=True, help="Path to production policy JSON")
    parser.add_argument("--audit", required=True, help="Path to audit JSONL")
    parser.add_argument("--storage-root", required=True, help="Root directory for separated local stores")
    parser.add_argument("--output", required=True, help="Path to write health report JSON")
    parser.add_argument("--schema", default="schemas/health-status.schema.json", help="Health schema path")
    parser.add_argument("--sensor-id", default="motion-1")
    parser.add_argument("--signal-type", default="motion")
    parser.add_argument("--space-name", default="living room movement")
    parser.add_argument("--permission-state", default="granted", choices=["granted", "denied", "restricted", "not_determined", "unavailable"])
    parser.add_argument("--availability-state", default="healthy", choices=["healthy", "degraded", "critical", "unavailable", "unknown"])
    args = parser.parse_args()

    policy = ProductionPolicy.load_file(args.policy)
    audit_log = AuditLog.open(args.audit)
    monitor = HealthMonitor(policy=policy, audit_log=audit_log)
    paths = LocalStoragePaths.create(args.storage_root)
    capability = SensorCapability(
        sensor_id=args.sensor_id,
        signal_type=args.signal_type,
        display_name=args.space_name,
        permission_state=args.permission_state,
        availability_state=args.availability_state,
        plain_language=f"{args.space_name} signal is {args.availability_state} and permission is {args.permission_state}.",
    )
    report = monitor.generate_report(
        components=[
            monitor.component_from_sensor(capability),
            monitor.component_from_storage_paths(paths),
            monitor.component_from_audit_log(),
            monitor.component_from_policy(),
            monitor.component_from_contacts([]),
        ]
    )
    data = report.to_dict()
    validate_health_schema(data, args.schema)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(data, indent=2, sort_keys=True))
    return 0 if report.ready_for_active_monitoring else 2


if __name__ == "__main__":
    raise SystemExit(main())
