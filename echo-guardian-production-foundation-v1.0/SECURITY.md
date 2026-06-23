# Security Policy

Echo Guardian security-sensitive modules require review before merge:

- audit engine
- canonicalization
- hashing and cryptographic boundaries
- policy engine
- consent records
- escalation engine
- export engine
- storage encryption

## Required security properties

- BLAKE3 is mandatory for audit hashing. There is no silent fallback.
- Unknown schema fields are rejected.
- Production state changes must pass through the policy engine.
- Every significant state change must create an audit entry.
- Export requires explicit user action.
- Live escalation requires configured contacts and successful test alert.
