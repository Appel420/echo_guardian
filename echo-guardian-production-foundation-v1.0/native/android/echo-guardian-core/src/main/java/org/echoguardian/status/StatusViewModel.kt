package org.echoguardian.status

data class PlainStatus(
    val monitoringOn: Boolean,
    val activeSpaces: List<String>,
    val activeSignalTypes: List<String>,
    val authorityLabel: String,
    val degraded: Boolean,
    val whatAreYouDoing: String
)

class StatusViewModel {
    fun makeStatus(monitoringOn: Boolean, spaces: List<String>, signals: List<String>, authority: String, degraded: Boolean): PlainStatus {
        val onOff = if (monitoringOn) "on" else "off"
        val spacesText = if (spaces.isEmpty()) "no rooms" else spaces.joinToString(", ")
        val signalText = if (signals.isEmpty()) "no safety signals" else signals.joinToString(", ")
        val degradedText = if (degraded) " Some parts need attention." else " Everything needed for this local status view is working."
        return PlainStatus(monitoringOn, spaces, signals, authority, degraded, "Echo Guardian monitoring is $onOff. Active spaces: $spacesText. It uses: $signalText. Control: $authority.$degradedText")
    }
}
