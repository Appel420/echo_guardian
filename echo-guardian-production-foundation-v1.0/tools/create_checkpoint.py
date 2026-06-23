#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from echo_guardian_core.audit import AuditLog
from echo_guardian_core.signing import Ed25519KeyPair


def main() -> int:
    if len(sys.argv) not in (2, 3):
        print("usage: create_checkpoint.py <audit_chain.jsonl> [checkpoint.json]", file=sys.stderr)
        return 2
    audit_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2]) if len(sys.argv) == 3 else audit_path.with_suffix(".checkpoint.json")
    log = AuditLog.open(audit_path)
    errors = log.verify()
    if errors:
        print("cannot checkpoint invalid audit log", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    signer = Ed25519KeyPair.generate()
    checkpoint = log.create_checkpoint(signer)
    out_path.write_text(json.dumps(checkpoint, sort_keys=True, indent=2), encoding="utf-8")
    print(f"checkpoint_written={out_path}")
    print(f"public_key={checkpoint['public_key']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
