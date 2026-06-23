import Foundation

public struct AccessibilityScreen: Codable, Equatable {
    public let id: String
    public let title: String
    public let plainLanguage: String
    public let primaryAction: String
    public let voicePrompt: String
}

public enum AccessibilityFlowFactory {
    public static func defaultScreens() -> [AccessibilityScreen] {
        [
            AccessibilityScreen(id: "status", title: "Safety Status", plainLanguage: "This screen tells you if Echo Guardian is watching for safety changes.", primaryAction: "Ask what are you doing", voicePrompt: "What are you doing?"),
            AccessibilityScreen(id: "confirmation", title: "Are you okay?", plainLanguage: "Echo Guardian is checking if you are okay. You can answer by voice, text, or touch.", primaryAction: "I am okay", voicePrompt: "Are you okay?"),
            AccessibilityScreen(id: "alert_preview", title: "Alert Preview", plainLanguage: "This shows exactly what your safety contact would receive.", primaryAction: "Review alert", voicePrompt: "Read the alert preview")
        ]
    }
}
