package org.echoguardian.accessibility

data class AccessibilityScreen(
    val id: String,
    val title: String,
    val plainLanguage: String,
    val primaryAction: String,
    val voicePrompt: String,
)

object AccessibilityFlowFactory {
    fun defaultScreens(): List<AccessibilityScreen> = listOf(
        AccessibilityScreen("status", "Safety Status", "This screen tells you if Echo Guardian is watching for safety changes.", "Ask what are you doing", "What are you doing?"),
        AccessibilityScreen("confirmation", "Are you okay?", "Echo Guardian is checking if you are okay. You can answer by voice, text, or touch.", "I am okay", "Are you okay?"),
        AccessibilityScreen("alert_preview", "Alert Preview", "This shows exactly what your safety contact would receive.", "Review alert", "Read the alert preview")
    )
}
