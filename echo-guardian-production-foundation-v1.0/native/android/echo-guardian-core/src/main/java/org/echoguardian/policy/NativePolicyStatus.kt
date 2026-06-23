package org.echoguardian.policy

data class NativePolicyStatus(
    val monitoringEnabled: Boolean,
    val privateSpaceMonitoringEnabled: Boolean,
    val authorityLabel: String,
    val cloudRequiredForCoreLoop: Boolean = false,
    val silentTelemetryEnabled: Boolean = false,
) {
    init {
        require(!privateSpaceMonitoringEnabled) { "Private-space monitoring is blocked by default in v0.5" }
        require(!cloudRequiredForCoreLoop) { "Cloud dependency is blocked for the core loop" }
        require(!silentTelemetryEnabled) { "Silent telemetry is blocked" }
    }

    val plainLanguage: String = if (monitoringEnabled) {
        "Echo Guardian monitoring is on. You can see what is being watched."
    } else {
        "Echo Guardian monitoring is off."
    }
}
