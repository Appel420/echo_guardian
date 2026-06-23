"""Device-bound key integration prototypes for Echo Guardian v0.4.

This module defines portable proof-of-possession interfaces used by tests and
native platform scaffolds. Production native apps should use iOS Keychain /
Secure Enclave where supported and Android Keystore / StrongBox where
supported. Unsupported primitives must use vetted libraries and must be labeled
as software-protected.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal
import base64

from cryptography.hazmat.primitives.asymmetric import ed25519, ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.backends import default_backend

Platform = Literal["ios", "android", "portable"]
KeyProtection = Literal["secure_enclave", "keychain", "android_keystore", "strongbox", "software_protected"]


@dataclass(frozen=True)
class DeviceKeyCapability:
    platform: Platform
    signing_key_profile: str
    key_agreement_profile: str
    local_storage_profile: str
    pqc_profile: str
    protection: KeyProtection
    notes: str


@dataclass(frozen=True)
class ProofOfPossession:
    key_id: str
    algorithm: str
    challenge_b64: str
    signature_b64: str
    protection: KeyProtection
    created_at: str


class PortableDeviceSigningKey:
    """Portable development key for proof-of-possession testing.

    This is not a substitute for native Keychain/Keystore-backed keys.
    """

    def __init__(self) -> None:
        self._private_key = ed25519.Ed25519PrivateKey.generate()
        public = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.key_id = base64.b64encode(public).decode("ascii")

    def sign_challenge(self, challenge: bytes) -> ProofOfPossession:
        if not challenge:
            raise ValueError("challenge must not be empty")
        signature = self._private_key.sign(challenge)
        return ProofOfPossession(
            key_id=self.key_id,
            algorithm="ed25519_portable_development",
            challenge_b64=base64.b64encode(challenge).decode("ascii"),
            signature_b64=base64.b64encode(signature).decode("ascii"),
            protection="software_protected",
            created_at=datetime.now(timezone.utc).isoformat(),
        )


def recommended_device_key_capability(platform: Platform) -> DeviceKeyCapability:
    if platform == "ios":
        return DeviceKeyCapability(
            platform="ios",
            signing_key_profile="ed25519_keychain_or_p256_secure_enclave_when_required_by_platform",
            key_agreement_profile="x25519_software_or_platform_library",
            local_storage_profile="aes_256_gcm_with_keychain_wrapped_key",
            pqc_profile="ml_kem_ml_dsa_87_vetted_library_when_enabled",
            protection="keychain",
            notes="Use Secure Enclave only for operations actually supported by Apple platform APIs; use Keychain for Ed25519/X25519 when Secure Enclave support is unavailable.",
        )
    if platform == "android":
        return DeviceKeyCapability(
            platform="android",
            signing_key_profile="ecdsa_p256_android_keystore_or_ed25519_vetted_library_if_policy_allows",
            key_agreement_profile="x25519_platform_or_vetted_library",
            local_storage_profile="aes_256_gcm_with_keystore_wrapped_key",
            pqc_profile="ml_kem_ml_dsa_87_vetted_library_when_enabled",
            protection="android_keystore",
            notes="Use StrongBox when available and policy-approved; do not claim hardware protection for unsupported primitives.",
        )
    return DeviceKeyCapability(
        platform="portable",
        signing_key_profile="ed25519_software_protected",
        key_agreement_profile="x25519_software_protected",
        local_storage_profile="aes_256_gcm_local_key",
        pqc_profile="disabled_until_vetted_library_configured",
        protection="software_protected",
        notes="Portable profile is for development and non-certified environments only.",
    )
