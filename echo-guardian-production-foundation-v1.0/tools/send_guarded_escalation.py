#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from echo_guardian_core.audit import AuditLog
from echo_guardian_core.escalation import (
    EscalationEngine,
    EscalationMessage,
    FileOutboxNotificationProvider,
    load_contacts,
)
from echo_guardian_core.policy import ProductionPolicy


def main() -> int:
    parser = argparse.ArgumentParser(description="Send a guarded live Echo Guardian escalation through a provider adapter.")
    parser.add_argument("--policy", required=True)
    parser.add_argument("--contacts", required=True)
    parser.add_argument("--audit", required=True)
    parser.add_argument("--contact-schema", default="schemas/contact.schema.json")
    parser.add_argument("--outbox", required=True, help="Local outbox directory for the default provider adapter.")
    parser.add_argument("--severity", default="severe", choices=["concerning", "severe", "emergency"])
    parser.add_argument("--reason", required=True)
    parser.add_argument("--location", required=True)
    parser.add_argument("--recommended-action", default="Please check on the user.")
    parser.add_argument("--output", required=False)
    args = parser.parse_args()

    policy = ProductionPolicy.load_file(args.policy, schema_path="schemas/policy.schema.json")
    contacts = load_contacts(args.contacts, args.contact_schema)
    engine = EscalationEngine(
        policy=policy,
        audit_log=AuditLog.open(args.audit),
        provider=FileOutboxNotificationProvider(args.outbox),
    )
    record = engine.send_guarded_live(
        contacts=contacts,
        message=EscalationMessage(
            severity=args.severity,
            reason=args.reason,
            recommended_action=args.recommended_action,
            location_context=args.location,
            sensitive_details_included=False,
        ),
    )
    text = json.dumps(record, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0 if record["delivery_status"] == "delivered" else 2


if __name__ == "__main__":
    raise SystemExit(main())
