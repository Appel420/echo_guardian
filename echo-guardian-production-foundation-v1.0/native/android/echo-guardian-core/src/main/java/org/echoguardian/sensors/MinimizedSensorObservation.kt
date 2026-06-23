package org.echoguardian.sensors

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorManager
import java.time.Instant
import java.util.UUID

data class MinimizedSensorObservation(
    val schemaVersion: String = "0.5",
    val observationId: String = UUID.randomUUID().toString(),
    val createdAt: String = Instant.now().toString(),
    val signalType: String,
    val spaceId: String,
    val privateSpace: Boolean,
    val permissionState: String,
    val availabilityState: String,
    val rawSensorRetained: Boolean = false,
    val derivedMetadata: Map<String, Int>,
    val plainLanguageSummary: String
)

class AndroidSensorAdapter(private val context: Context) {
    private val sensorManager: SensorManager = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager

    fun accelerometerAvailability(): String =
        if (sensorManager.getDefaultSensor(Sensor.TYPE_ACCELEROMETER) != null) "available" else "unavailable"

    fun makeMotionObservation(spaceId: String, confidenceScaled: Int, motionDetected: Boolean): MinimizedSensorObservation {
        require(spaceId != "bathroom" && spaceId != "bedroom") { "Private-space monitoring is blocked by default in v0.5" }
        return MinimizedSensorObservation(
            signalType = "motion",
            spaceId = spaceId,
            privateSpace = false,
            permissionState = "authorized_or_not_required",
            availabilityState = accelerometerAvailability(),
            derivedMetadata = mapOf(
                "confidence_scaled" to confidenceScaled.coerceIn(0, 100),
                "motion_detected" to if (motionDetected) 1 else 0
            ),
            plainLanguageSummary = "Echo Guardian received a minimized safety signal for $spaceId. Raw sensor data was not kept."
        )
    }
}
