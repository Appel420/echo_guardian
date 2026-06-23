# v1.0 Signed SBOM Attestation

The v1.0 release-candidate gate requires a verified signed SBOM attestation.

## Required inputs

- `docs/sbom/sbom-v0.9.json` or later SBOM document.
- A signed SBOM attestation JSON generated with the persisted signing proof contract.
- Signature verification against the SBOM bytes.
- BLAKE3 hash match against the attested hash.

## Scope

This proves artifact integrity for review. It is not a legal compliance certification.
