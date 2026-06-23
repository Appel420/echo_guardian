# Cryptographic Design Note v0.2

## Mandatory

- canonical JSON v0.2 for audit hash material
- BLAKE3 for content hashing
- append-only hash chain
- binary Merkle tree with duplicate-last-leaf odd-node rule
- monotonic sequence numbers
- checkpoint records

## Prohibited

- hashing fallback to SHA-256 or another primitive without explicit spec update
- signing or hashing non-canonical JSON
- modifying committed audit records
- deleting audit records without lifecycle event
