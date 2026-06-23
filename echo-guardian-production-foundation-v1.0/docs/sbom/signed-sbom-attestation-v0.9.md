# Signed SBOM Attestation v0.9

The SBOM is signed using the persisted signing-key contract. The signature proves artifact integrity for release review. It is not a compliance certification.

Required checks:

- SBOM file exists.
- SBOM hash is computed before signing.
- Signature verifies against the public key.
- Attestation is linked into release evidence.
