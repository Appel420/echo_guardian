package org.echoguardian.keys

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.time.Instant
import java.util.Base64

data class ProofOfPossession(
    val keyId: String,
    val algorithm: String,
    val challengeBase64: String,
    val signatureBase64: String,
    val protection: String,
    val createdAt: String
)

class DeviceSigningKeyManager(private val alias: String = "echo_guardian_device_signing_v0_4") {
    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun createOrLoadSigningKeyAlias(): String {
        if (!keyStore.containsAlias(alias)) {
            val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
                .setUserAuthenticationRequired(false)
                .build()
            generator.initialize(spec)
            generator.generateKeyPair()
        }
        return alias
    }

    fun signChallenge(challenge: ByteArray): ProofOfPossession {
        require(challenge.isNotEmpty()) { "challenge must not be empty" }
        createOrLoadSigningKeyAlias()
        val privateKey = keyStore.getKey(alias, null) as java.security.PrivateKey
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(privateKey)
        signature.update(challenge)
        val sig = signature.sign()
        return ProofOfPossession(
            keyId = alias,
            algorithm = "ecdsa_p256_sha256_android_keystore",
            challengeBase64 = Base64.getEncoder().encodeToString(challenge),
            signatureBase64 = Base64.getEncoder().encodeToString(sig),
            protection = "android_keystore_or_strongbox_when_available",
            createdAt = Instant.now().toString()
        )
    }
}
