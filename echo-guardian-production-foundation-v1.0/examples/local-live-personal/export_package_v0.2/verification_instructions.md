# Verification Instructions

1. Read export_manifest.json.
2. Recompute BLAKE3 for each included file.
3. Compare each digest with the manifest.
4. Verify audit_chain.jsonl with tools/verify_audit.py.
5. Treat any mismatch as a failed integrity check.
