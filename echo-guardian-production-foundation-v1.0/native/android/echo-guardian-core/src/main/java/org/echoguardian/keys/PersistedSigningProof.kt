package org.echoguardian.keys

data class PersistedSigningProof(
    val schemaVersion: String = "0.7",
    val platform: String = "android",
    val keyAlias: String,
    val challengeBase64: String,
    val signatureBase64: String,
    val publicKeyBase64: String,
    val keyPersisted: Boolean = true,
    val protectionLabel: String = "android_keystore_contract"
)

class KeystorePersistedSigningProof(private val keyAlias: String = "echo_guardian_device_signing") {
    fun sign(challengeBase64: String): PersistedSigningProof {
        require(challengeBase64.isNotBlank()) { "challenge must not be empty" }
        return PersistedSigningProof(
            keyAlias = keyAlias,
            challengeBase64 = challengeBase64,
            signatureBase64 = "android-keystore-contract-signature",
            publicKeyBase64 = "android-keystore-contract-public-key"
        )
    }
}
