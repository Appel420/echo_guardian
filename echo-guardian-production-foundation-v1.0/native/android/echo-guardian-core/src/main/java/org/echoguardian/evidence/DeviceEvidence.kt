package org.echoguardian.evidence

class EvidenceViolation(message: String) : IllegalArgumentException(message)

data class DeviceExecutionEvidence(
    val schemaVersion: String = "0.8",
    val platform: String = "android",
    val deviceModel: String,
    val osVersion: String,
    val appBuild: String,
    val physicalDevice: Boolean,
    val simulatorOrEmulator: Boolean,
    val permissionsVisible: Boolean,
    val privateSpaceBlocked: Boolean,
    val rawDataBlocked: Boolean,
    val plainLanguageSummary: String = "Echo Guardian recorded real Android device evidence without raw data, private-space monitoring, or hidden behavior."
) {
    init {
        if (platform != "android") throw EvidenceViolation("Android evidence must use android platform")
        if (deviceModel.isBlank() || osVersion.isBlank() || appBuild.isBlank()) throw EvidenceViolation("device model, OS, and build are required")
        if (!physicalDevice || simulatorOrEmulator) throw EvidenceViolation("physical Android device evidence is required")
        if (!permissionsVisible) throw EvidenceViolation("permission status must be visible")
        if (!privateSpaceBlocked) throw EvidenceViolation("private-space blocking must be evidenced")
        if (!rawDataBlocked) throw EvidenceViolation("raw-data blocking must be evidenced")
    }

    fun toCoreCompatibleJson(): String =
        "{\"appBuild\":\"$appBuild\",\"deviceModel\":\"$deviceModel\",\"osVersion\":\"$osVersion\",\"permissionsVisible\":$permissionsVisible,\"physicalDevice\":$physicalDevice,\"platform\":\"$platform\",\"privateSpaceBlocked\":$privateSpaceBlocked,\"rawDataBlocked\":$rawDataBlocked,\"schemaVersion\":\"$schemaVersion\",\"simulatorOrEmulator\":$simulatorOrEmulator}"
}

data class AccessibilityEvidence(
    val schemaVersion: String = "0.8",
    val screenName: String,
    val spokenOrVisibleText: List<String>,
    val whatAreYouDoingAvailable: Boolean = true,
    val emergencyClaimsAbsent: Boolean = true
) {
    init {
        val joined = spokenOrVisibleText.joinToString(" ").lowercase()
        if (screenName.isBlank() || spokenOrVisibleText.isEmpty()) throw EvidenceViolation("screen evidence is required")
        if (!joined.contains("what are you doing")) throw EvidenceViolation("what are you doing explanation is required")
        listOf("hipaa compliant", "gdpr compliant", "medical device", "emergency certified").forEach {
            if (joined.contains(it)) throw EvidenceViolation("unsupported compliance or medical claim present")
        }
    }
}
