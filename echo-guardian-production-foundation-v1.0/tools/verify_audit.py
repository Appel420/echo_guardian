#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from echo_guardian_core.audit import AuditLog


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: verify_audit.py <audit_chain.jsonl>", file=sys.stderr)
        return 2
    log = AuditLog.open(sys.argv[1])
    errors = log.verify()
    if errors:
        print("AUDIT VERIFICATION FAILED")
        for e in errors:
            print(f"- {e}")
        return 1
    print(f"AUDIT VERIFICATION PASSED: {len(log.entries)} entries")
    if log.entries:
        print(f"latest_merkle_root={log.entries[-1]['merkle_root']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
