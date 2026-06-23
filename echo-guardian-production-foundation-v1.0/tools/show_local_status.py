#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from echo_guardian_core.audit import AuditLog
from echo_guardian_core.policy import ProductionPolicy
from echo_guardian_core.status import AlertPreview, InterfaceDegradation, LocalStatusInterface, SpaceStatus, validate_status_schema


def main() -> int:
    parser = argparse.ArgumentParser(description="Show Echo Guardian local status in plain language.")
    parser.add_argument("--policy", required=True)
    parser.add_argument("--audit-log", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--schema", default="schemas/local-status.schema.json")
    parser.add_argument("--space-id", default="living_room")
    parser.add_argument("--display-name", default="living room")
    parser.add_argument("--enabled", action="store_true")
    parser.add_argument("--signal-types", default="motion", help="Comma-separated signal types for an enabled space.")
    parser.add_argument("--degraded-component")
    parser.add_argument("--degraded-message")
    args = parser.parse_args()

    policy = ProductionPolicy.load_file(args.policy, schema_path="schemas/policy.schema.json")
    interface = LocalStatusInterface(policy=policy, audit_log=AuditLog.open(args.audit_log))
    signals = [s.strip() for s in args.signal_types.split(",") if s.strip()] if args.enabled else []
    degradations = []
    if args.degraded_component:
        degradations.append(
            InterfaceDegradation(
                component=args.degraded_component,
                health_state="degraded",
                plain_language=args.degraded_message or f"{args.degraded_component} is degraded.",
                user_action="Use another available interaction method.",
            )
        )
    preview = AlertPreview(
        severity="severe",
        reason="No response after safety confirmation prompt.",
        location_context=f"Home - {args.display_name}",
        recommended_action="Please check on the user.",
        sensitive_details_included=False,
        emergency_services_used=False,
    )
    report = interface.generate_status_report(
        spaces=[SpaceStatus(args.space_id, args.display_name, args.enabled, False, signals, "user")],
        degradations=degradations,
        alert_preview=preview,
    )
    data = report.to_dict()
    validate_status_schema(data, args.schema)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    print(report.what_are_you_doing_response)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
