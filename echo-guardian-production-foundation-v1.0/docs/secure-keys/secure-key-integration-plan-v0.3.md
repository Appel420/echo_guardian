# Secure Key Integration Plan v0.3

## Objective

Add platform-aware device-bound signing and storage protection while preserving portability of the core audit engine.

## iOS Strategy

- Use Keychain for protected key material and symmetric-key wrapping where appropriate.
- Use Secure Enclave where the requested primitive is actually supported by the platform.
- Use software-backed vetted libraries for primitives not supported by Secure Enclave.
- Do not claim Secure Enclave support for Ed25519, X25519, ML-KEM, or ML-DSA unless platform support exists and is verified.

## Android Strategy

- Use Android Keystore for hardware-backed or TEE-backed key protection where supported.
- Use StrongBox where available and appropriate.
- Use vetted software-backed libraries for PQC primitives not supported by Keystore.

## Primitive Profile

- Ed25519: device-bound audit/checkpoint signatures where supported by library/profile.
- X25519: local key agreement where needed for export encryption workflows.
- AES-256-GCM: local encrypted store abstraction.
- ChaCha20-Poly1305: alternative AEAD for mobile-friendly encrypted payloads.
- ML-KEM: future high-assurance export/key-establishment profile.
- ML-DSA-87: future high-assurance signature profile.
- Shamir secret sharing: future recovery/multi-party unlock workflow; never enabled silently.

## Device-Bound Key Rule

A device-bound signing key must identify an installation trust boundary. Key loss, reset, migration, replacement, or rotation creates an auditable boundary event.
