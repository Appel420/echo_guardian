package org.echoguardian.export

data class SignedNativeExportManifest(
    val schemaVersion: String = "0.7",
    val platform: String = "android",
    val exportManifestHash: String,
    val signatureAlgorithm: String = "ed25519_persisted_contract",
    val signatureHex: String,
    val publicKeyHex: String,
    val userConfirmed: Boolean = true,
    val automaticExport: Boolean = false,
    val plainLanguageSummary: String = "Echo Guardian signed a user-confirmed native export manifest. No automatic export was used."
)

object SignedNativeExportPolicy {
    fun validate(userConfirmed: Boolean, automaticExport: Boolean, emergencyServicesUsed: Boolean): Boolean =
        userConfirmed && !automaticExport && !emergencyServicesUsed
}
