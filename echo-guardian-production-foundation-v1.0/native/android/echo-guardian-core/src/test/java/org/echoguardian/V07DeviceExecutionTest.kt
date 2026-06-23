package org.echoguardian

import org.echoguardian.export.SignedNativeExportPolicy
import org.echoguardian.keys.KeystorePersistedSigningProof
import org.echoguardian.receipts.ProviderSandboxReceiptVerifier
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class V07DeviceExecutionTest {
    @Test
    fun signedNativeExportBlocksAutomaticExport() {
        assertTrue(SignedNativeExportPolicy.validate(userConfirmed = true, automaticExport = false, emergencyServicesUsed = false))
        assertFalse(SignedNativeExportPolicy.validate(userConfirmed = false, automaticExport = false, emergencyServicesUsed = false))
        assertFalse(SignedNativeExportPolicy.validate(userConfirmed = true, automaticExport = true, emergencyServicesUsed = false))
    }

    @Test
    fun keystoreProofIsPersistedContract() {
        val proof = KeystorePersistedSigningProof().sign("ZWNo/by1ndWFyZGlhbg==")
        assertTrue(proof.keyPersisted)
        assertTrue(proof.protectionLabel.contains("keystore"))
    }

    @Test
    fun sandboxReceiptRequiresSandbox() {
        assertNotNull(ProviderSandboxReceiptVerifier.verify("local_outbox", "sandbox-1", "attempted", true))
        assertTrue(ProviderSandboxReceiptVerifier.verify("local_outbox", "sandbox-1", "attempted", false) == null)
    }
}
