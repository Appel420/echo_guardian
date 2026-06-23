package org.echoguardian

import org.echoguardian.accessibility.AccessibilityFlowFactory
import org.echoguardian.policy.NativePolicyStatus
import org.echoguardian.runtime.CoreJsonBridge
import org.echoguardian.sensors.MinimizedSensorObservation
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class V05RuntimeTest {
    @Test
    fun observationBridgesToCoreJson() {
        val native = MinimizedSensorObservation(
            signalType = "motion",
            spaceId = "living_room",
            privateSpace = false,
            permissionState = "granted",
            availabilityState = "healthy",
            derivedMetadata = mapOf("motion_detected" to 1, "confidence_scaled" to 90)
        )
        val bridged = CoreJsonBridge().bridge(native)
        assertEquals("0.5", bridged.schema_version)
        assertFalse(bridged.raw_sensor_retained)
        assertTrue(CoreJsonBridge().toCoreJson(bridged).contains("derived_metadata"))
    }

    @Test
    fun policyStatusIsPlainLanguage() {
        val status = NativePolicyStatus(true, false, "User controlled")
        assertTrue(status.plainLanguage.contains("monitoring is on"))
    }

    @Test
    fun accessibilityFlowIncludesWhatAreYouDoing() {
        assertTrue(AccessibilityFlowFactory.defaultScreens().any { it.voicePrompt == "What are you doing?" })
    }
}
