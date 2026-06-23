# Echo Guardian Local Audit Engine v0.2

Status: production-foundation implementation

## Purpose

The local audit engine provides a real append-only audit trail for Echo Guardian's production foundation build. It is not a mock path. It writes committed events, verifies hash-chain continuity, computes Merkle roots, and can create signed checkpoints for rollback/truncation detection.

## Implemented

- Deterministic canonical JSON encoding (`canonical_json:v0.2`)
- Strict BLAKE3 hashing with no silent fallback
- Append-only JSONL audit chain
- Previous-entry hash chaining
- Merkle leaf hashing
- Binary Merkle root calculation
- Duplicate-final-node rule for odd Merkle tree levels
- Audit verification CLI
- Ed25519 signed checkpoint interface
- Checkpoint verification CLI
- Tests for:
  - valid append/verify
  - content tampering
  - entry reordering
  - truncation detection using checkpoint comparison
  - checkpoint signature tampering

## Security Position

BLAKE3 is required. The implementation intentionally fails closed if the `blake3` package is missing. It does not downgrade to SHA-256 or another hash silently.

Ed25519 checkpoint signing is included for the Python reference implementation. Platform-native production builds should use Secure Enclave or hardware-backed signing where available. Post-quantum ML-DSA-87 remains part of the production cryptographic profile, but should be integrated through vetted libraries and platform support.

## Verification Commands

```bash
make test
python tools/verify_audit.py <audit_chain.jsonl>
python tools/create_checkpoint.py <audit_chain.jsonl> <checkpoint.json>
python tools/verify_checkpoint.py <checkpoint.json>
```

## Rollback and Truncation Note

A truncated audit log can still be internally coherent if the attacker removes complete entries from the end. Detection requires comparing the current local log against the latest signed checkpoint or another trusted checkpoint record. This is why signed checkpoints are part of v0.2.

## Non-Negotiables

- No audit bypass
- No silent hash fallback
- No production event without audit entry
- No checkpoint signature downgrade
- No hidden monitoring state change
