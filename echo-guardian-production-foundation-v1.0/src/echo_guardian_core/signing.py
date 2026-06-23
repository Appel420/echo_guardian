from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


@dataclass(frozen=True)
class Ed25519KeyPair:
    """Ed25519 signing keypair for production-foundation checkpoints.

    Platform builds should prefer hardware-backed keys where available. This
    Python reference implementation uses cryptography's Ed25519 primitive for
    deterministic local verification tests and export tooling.
    """

    private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "Ed25519KeyPair":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> "Ed25519KeyPair":
        if len(raw) != 32:
            raise ValueError("Ed25519 private seed must be 32 bytes")
        return cls(Ed25519PrivateKey.from_private_bytes(raw))

    def private_bytes_raw(self) -> bytes:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    def public_key_hex(self) -> str:
        return self.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()

    def sign_hex(self, data: bytes) -> str:
        return self.private_key.sign(data).hex()


def verify_ed25519_signature(public_key_hex: str, signature_hex: str, data: bytes) -> bool:
    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        public_key.verify(bytes.fromhex(signature_hex), data)
        return True
    except (ValueError, InvalidSignature):
        return False
