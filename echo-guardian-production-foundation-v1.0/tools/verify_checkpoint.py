#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from echo_guardian_core.audit import AuditLog


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: verify_checkpoint.py <checkpoint.json>", file=sys.stderr)
        return 2
    checkpoint = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    errors = AuditLog.verify_checkpoint(checkpoint)
    if errors:
        print("CHECKPOINT VERIFICATION FAILED")
        for error in errors:
            print(f"- {error}")
        return 1
    print("CHECKPOINT VERIFICATION PASSED")
    print(f"latest_sequence_number={checkpoint['latest_sequence_number']}")
    print(f"merkle_root={checkpoint['merkle_root']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
