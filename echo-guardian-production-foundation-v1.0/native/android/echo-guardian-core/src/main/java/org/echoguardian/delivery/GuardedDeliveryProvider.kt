package org.echoguardian.delivery

data class GuardedAlertPayload(
    val severity: String,
    val reason: String,
    val locationContext: String,
    val recommendedAction: String,
    val sensitiveDetailsIncluded: Boolean = false,
    val emergencyServicesUsed: Boolean = false
)

data class DeliveryResult(
    val status: String,
    val provider: String,
    val plainLanguageSummary: String
)

interface GuardedDeliveryProvider {
    fun send(payload: GuardedAlertPayload, authorizedContact: String): DeliveryResult
}

class LocalOutboxProvider : GuardedDeliveryProvider {
    override fun send(payload: GuardedAlertPayload, authorizedContact: String): DeliveryResult {
        if (payload.emergencyServicesUsed) {
            return DeliveryResult("blocked", "local_outbox", "Emergency services are not contacted by default.")
        }
        if (payload.sensitiveDetailsIncluded) {
            return DeliveryResult("blocked", "local_outbox", "Sensitive details are blocked in minimal-disclosure mode.")
        }
        return DeliveryResult("attempted", "local_outbox", "A minimal safety alert was prepared for an authorized contact.")
    }
}
