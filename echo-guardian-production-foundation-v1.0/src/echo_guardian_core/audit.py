from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from .canonical import CANONICALIZATION, canonical_json_bytes
from .crypto import blake3_hex, merkle_root_hex
from .signing import Ed25519KeyPair, verify_ed25519_signature

Severity = Literal["normal", "unusual", "concerning", "severe", "emergency"]
AuthorityContext = Literal["user_controlled", "caregiver_delegated", "mdm_managed", "emergency_policy", "system_internal"]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class AuditEntryInput:
    event_type: str
    severity: Severity
    authority_context: AuthorityContext
    public_context: dict[str, Any]
    policy_id: str | None = None
    policy_version: str | None = None
    sensitive_payload_ref: str | None = None
    sensitive_payload_hash: str | None = None
    redaction_commitment: str | None = None


@dataclass
class AuditLog:
    path: Path
    entries: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def open(cls, path: str | Path) -> "AuditLog":
        p = Path(path)
        entries: list[dict[str, Any]] = []
        if p.exists():
            with p.open("r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        entries.append(json.loads(line))
        return cls(path=p, entries=entries)

    def append(self, item: AuditEntryInput) -> dict[str, Any]:
        seq = len(self.entries) + 1
        previous = self.entries[-1]["current_entry_hash"] if self.entries else "0" * 64
        entry: dict[str, Any] = {
            "schema_version": "0.2",
            "audit_entry_id": str(uuid4()),
            "sequence_number": seq,
            "timestamp": utc_now_iso(),
            "event_type": item.event_type,
            "severity": item.severity,
            "authority_context": item.authority_context,
            "policy_id": item.policy_id,
            "policy_version": item.policy_version,
            "public_context": item.public_context,
            "sensitive_payload_ref": item.sensitive_payload_ref,
            "sensitive_payload_hash": item.sensitive_payload_hash,
            "redaction_commitment": item.redaction_commitment,
            "previous_entry_hash": previous,
            "current_entry_hash": None,
            "merkle_leaf_hash": None,
            "merkle_root": None,
            "checkpoint_id": None,
            "signature": None,
            "canonicalization": CANONICALIZATION,
        }
        hash_material = dict(entry)
        hash_material["current_entry_hash"] = None
        hash_material["merkle_leaf_hash"] = None
        hash_material["merkle_root"] = None
        entry_hash = blake3_hex(canonical_json_bytes(hash_material))
        entry["current_entry_hash"] = entry_hash
        leaf_material = dict(entry)
        leaf_material["merkle_leaf_hash"] = None
        leaf_material["merkle_root"] = None
        leaf_hash = blake3_hex(canonical_json_bytes(leaf_material))
        entry["merkle_leaf_hash"] = leaf_hash
        roots = [e["merkle_leaf_hash"] for e in self.entries] + [leaf_hash]
        entry["merkle_root"] = merkle_root_hex(roots)
        self.entries.append(entry)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
        return entry

    def create_checkpoint(self, signer: Ed25519KeyPair | None = None) -> dict[str, Any]:
        """Create a checkpoint over the current audit state.

        A checkpoint is a compact, optionally signed statement of the latest
        committed sequence number, entry hash, and Merkle root. It is suitable
        for local verification, export manifests, and future rollback detection.
        """
        latest = self.entries[-1] if self.entries else None
        checkpoint: dict[str, Any] = {
            "schema_version": "0.2",
            "checkpoint_id": str(uuid4()),
            "created_at": utc_now_iso(),
            "latest_sequence_number": latest["sequence_number"] if latest else 0,
            "latest_entry_hash": latest["current_entry_hash"] if latest else "0" * 64,
            "merkle_root": latest["merkle_root"] if latest else merkle_root_hex([]),
            "entry_count": len(self.entries),
            "canonicalization": CANONICALIZATION,
            "signature_algorithm": "ed25519" if signer else None,
            "public_key": signer.public_key_hex() if signer else None,
            "signature": None,
        }
        if signer is not None:
            signing_material = dict(checkpoint)
            signing_material["signature"] = None
            checkpoint["signature"] = signer.sign_hex(canonical_json_bytes(signing_material))
        return checkpoint

    @staticmethod
    def verify_checkpoint(checkpoint: dict[str, Any]) -> list[str]:
        errors: list[str] = []
        signature = checkpoint.get("signature")
        public_key = checkpoint.get("public_key")
        algorithm = checkpoint.get("signature_algorithm")
        if signature is None:
            errors.append("checkpoint is unsigned")
            return errors
        if algorithm != "ed25519":
            errors.append("unsupported checkpoint signature algorithm")
            return errors
        if not isinstance(public_key, str):
            errors.append("checkpoint public key missing")
            return errors
        material = dict(checkpoint)
        material["signature"] = None
        if not verify_ed25519_signature(public_key, signature, canonical_json_bytes(material)):
            errors.append("checkpoint signature verification failed")
        return errors

    def verify(self) -> list[str]:
        errors: list[str] = []
        prior_hash = "0" * 64
        leaves: list[str] = []
        for expected_seq, entry in enumerate(self.entries, start=1):
            if entry.get("sequence_number") != expected_seq:
                errors.append(f"sequence mismatch at index {expected_seq}")
            if entry.get("previous_entry_hash") != prior_hash:
                errors.append(f"previous hash mismatch at sequence {expected_seq}")
            hash_material = dict(entry)
            hash_material["current_entry_hash"] = None
            hash_material["merkle_leaf_hash"] = None
            hash_material["merkle_root"] = None
            recomputed_entry_hash = blake3_hex(canonical_json_bytes(hash_material))
            if entry.get("current_entry_hash") != recomputed_entry_hash:
                errors.append(f"current hash mismatch at sequence {expected_seq}")
            leaf_material = dict(entry)
            leaf_material["merkle_leaf_hash"] = None
            leaf_material["merkle_root"] = None
            recomputed_leaf = blake3_hex(canonical_json_bytes(leaf_material))
            if entry.get("merkle_leaf_hash") != recomputed_leaf:
                errors.append(f"leaf hash mismatch at sequence {expected_seq}")
            leaves.append(recomputed_leaf)
            recomputed_root = merkle_root_hex(leaves)
            if entry.get("merkle_root") != recomputed_root:
                errors.append(f"merkle root mismatch at sequence {expected_seq}")
            prior_hash = entry.get("current_entry_hash", "")
        return errors
