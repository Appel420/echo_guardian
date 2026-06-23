package org.echoguardian

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.echoguardian.evidence.AccessibilityEvidence
import org.echoguardian.evidence.DeviceExecutionEvidence
import org.echoguardian.evidence.EvidenceViolation

class V08EvidenceTest {
    @Test
    fun androidPhysicalDeviceEvidenceRequiresSafetyFlags() {
        val evidence = DeviceExecutionEvidence(
            deviceModel = "Pixel physical device",
            osVersion = "Android test evidence",
            appBuild = "0.8.0",
            physicalDevice = true,
            simulatorOrEmulator = false,
            permissionsVisible = true,
            privateSpaceBlocked = true,
            rawDataBlocked = true
        )
        assertEquals("0.8", evidence.schemaVersion)
        assertTrue(evidence.toCoreCompatibleJson().contains("rawDataBlocked"))
    }

    @Test
    fun androidPhysicalDeviceEvidenceRejectsEmulator() {
        assertFailsWith<EvidenceViolation> {
            DeviceExecutionEvidence(
                deviceModel = "emulator",
                osVersion = "Android test evidence",
                appBuild = "0.8.0",
                physicalDevice = false,
                simulatorOrEmulator = true,
                permissionsVisible = true,
                privateSpaceBlocked = true,
                rawDataBlocked = true
            )
        }
    }

    @Test
    fun accessibilityEvidenceRequiresWhatAreYouDoing() {
        val evidence = AccessibilityEvidence(screenName = "Status", spokenOrVisibleText = listOf("What are you doing?", "Checking safety signals."))
        assertTrue(evidence.whatAreYouDoingAvailable)
        assertFailsWith<EvidenceViolation> {
            AccessibilityEvidence(screenName = "Status", spokenOrVisibleText = listOf("HIPAA compliant medical device"))
        }
    }
}
