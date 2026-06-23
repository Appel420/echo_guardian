from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import base64
import json
import os
from uuid import uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .canonical import canonical_json_bytes
from .crypto import blake3_hex
from .audit import utc_now_iso


class StoragePolicyViolation(ValueError):
    """Raised when local storage rules are violated."""


@dataclass(frozen=True)
class LocalStoragePaths:
    """Separated local storage roots for production foundation v0.2."""

    root: Path
    operational: Path
    audit: Path
    export: Path

    @classmethod
    def create(cls, root: str | Path) -> "LocalStoragePaths":
        base = Path(root)
        paths = cls(
            root=base,
            operational=base / "operational",
            audit=base / "audit",
            export=base / "export",
        )
        for p in [paths.operational, paths.audit, paths.export]:
            p.mkdir(parents=True, exist_ok=True)
        return paths

    def assert_separate(self) -> None:
        resolved = [self.operational.resolve(), self.audit.resolve(), self.export.resolve()]
        if len(set(resolved)) != 3:
            raise StoragePolicyViolation("operational, audit, and export paths must be separate")


class LocalEncryptedStore:
    """AES-256-GCM encrypted local object store.

    This is a production-foundation abstraction. On mobile platforms, the 32-byte
    key should be wrapped or stored using platform-backed secure storage. In this
    portable reference implementation the key is kept in a local key file so tests
    and CLI tools can run deterministically without cloud services.
    """

    def __init__(self, *, store_dir: str | Path, key_path: str | Path):
        self.store_dir = Path(store_dir)
        self.key_path = Path(key_path)
        self.store_dir.mkdir(parents=True, exist_ok=True)
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        self._key = self._load_or_create_key()

    def _load_or_create_key(self) -> bytes:
        if self.key_path.exists():
            raw = self.key_path.read_bytes()
            try:
                key = base64.b64decode(raw, validate=True)
            except Exception as exc:
                raise StoragePolicyViolation("encrypted store key is not valid base64") from exc
            if len(key) != 32:
                raise StoragePolicyViolation("encrypted store key must be 32 bytes for AES-256-GCM")
            return key
        key = os.urandom(32)
        self.key_path.write_bytes(base64.b64encode(key))
        try:
            os.chmod(self.key_path, 0o600)
        except OSError:
            pass
        return key

    def put_json(self, name: str, obj: dict[str, Any], *, aad: bytes | None = None) -> Path:
        if Path(name).is_absolute() or ".." in Path(name).parts:
            raise StoragePolicyViolation("store object name must be relative and stay within the store")
        plaintext = canonical_json_bytes(obj)
        nonce = os.urandom(12)
        aad = aad or b"echo-guardian-local-store-v0.2"
        ciphertext = AESGCM(self._key).encrypt(nonce, plaintext, aad)
        envelope = {
            "schema_version": "0.2",
            "envelope_id": str(uuid4()),
            "created_at": utc_now_iso(),
            "encryption": "aes_256_gcm",
            "aad_hash": blake3_hex(aad),
            "plaintext_hash": blake3_hex(plaintext),
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        }
        path = self.store_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
        return path

    def get_json(self, name: str, *, aad: bytes | None = None) -> dict[str, Any]:
        path = self.store_dir / name
        envelope = json.loads(path.read_text(encoding="utf-8"))
        if envelope.get("encryption") != "aes_256_gcm":
            raise StoragePolicyViolation("unsupported encrypted store envelope")
        aad = aad or b"echo-guardian-local-store-v0.2"
        nonce = base64.b64decode(envelope["nonce_b64"])
        ciphertext = base64.b64decode(envelope["ciphertext_b64"])
        plaintext = AESGCM(self._key).decrypt(nonce, ciphertext, aad)
        if blake3_hex(plaintext) != envelope.get("plaintext_hash"):
            raise StoragePolicyViolation("decrypted plaintext hash mismatch")
        return json.loads(plaintext.decode("utf-8"))

    @staticmethod
    def is_encrypted_file(path: str | Path) -> bool:
        try:
            envelope = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception:
            return False
        return envelope.get("encryption") == "aes_256_gcm" and "ciphertext_b64" in envelope
