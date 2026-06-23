# Known Limitations v0.2

1. **No certification claims.** v0.2 is not certified as HIPAA compliant, GDPR compliant, medical-device compliant, clinical, or emergency-response ready.
2. **Native platform bindings pending.** The foundation package does not yet provide full native iOS/Android background execution or sensor service integration.
3. **Secure Enclave / Keychain / Keystore work pending.** The cryptographic profile exists, but platform-backed lifecycle implementation remains a v0.3+ target.
4. **PQC integration pending.** ML-KEM and ML-DSA-87 are specified but require vetted production library binding and review.
5. **Private spaces disabled.** Bathroom and bedroom monitoring remain blocked by default in v0.2.
6. **Emergency-services path disabled.** Emergency-services dispatch is not enabled by default and is not production-approved in v0.2.
7. **Clinical validation not complete.** No diagnostic, treatment, medical, or emergency-response efficacy claims are supported.
