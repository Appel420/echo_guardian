package org.echoguardian.receipts

data class ProviderSandboxReceipt(
    val schemaVersion: String = "0.7",
    val provider: String,
    val providerMessageId: String,
    val deliveryStatus: String,
    val sandboxVerified: Boolean = true,
    val sensitiveDetailsIncluded: Boolean = false,
    val emergencyServicesUsed: Boolean = false
)

object ProviderSandboxReceiptVerifier {
    fun verify(provider: String, messageId: String, status: String, sandbox: Boolean): ProviderSandboxReceipt? {
        if (!sandbox) return null
        if (status != "attempted" && status != "delivered") return null
        return ProviderSandboxReceipt(provider = provider, providerMessageId = messageId, deliveryStatus = status)
    }
}
