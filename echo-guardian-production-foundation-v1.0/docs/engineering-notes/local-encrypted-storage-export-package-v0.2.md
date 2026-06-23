# Local Encrypted Storage + Export Package v0.2

Status: implemented in production foundation package.

## Implemented

- AES-256-GCM local encrypted store abstraction.
- Separate local storage roots for operational, audit, and export data.
- Explicit user-confirmed export request record.
- Export manifest generation.
- Audit chain export.
- Policy, baseline summary, and local status export support.
- BLAKE3 hashes for every exported file.
- Automatic export hard-disabled.
- Audit entries for export request, export generation, export denial, and export failure.

## Production Rules

- No automatic export.
- No export without explicit user confirmation.
- No mixed operational/audit/export paths.
- Every export package includes verification instructions.
- Every exported file is hashed with BLAKE3 in `export_manifest.json`.
- Sensitive local operational objects must be written through the encrypted store abstraction.
- This portable reference uses AES-256-GCM with a local key file for testability. Mobile production builds should wrap or store the key using platform secure storage or Secure Enclave-supported key protection where available.

## Package Layout

```text
/export_manifest.json
/human_readable_summary.md
/audit_chain.jsonl
/policy_snapshot.json
/baseline_summary.json
/local_status_report.json
/verification_instructions.md
```

## Verification

1. Verify the audit chain with `tools/verify_audit.py`.
2. Recompute BLAKE3 for every file listed in `export_manifest.json`.
3. Compare computed hashes against the manifest.
4. Treat any mismatch as failed integrity verification.
