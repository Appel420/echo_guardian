package org.echoguardian.sensors

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorManager

data class AndroidSensorPermissionStatus(
    val schemaVersion: String = "0.6",
    val platform: String = "android",
    val permissionName: String = "android_sensor",
    val permissionState: String,
    val availabilityState: String,
    val sensorId: String,
    val signalType: String,
    val rawSensorRetained: Boolean = false,
    val privateSpaceMonitoring: Boolean = false,
    val plainLanguageSummary: String = "Echo Guardian checked Android sensor permission and availability. Raw sensor data was not kept."
)

class AndroidSensorPermissionReader(private val context: Context) {
    private val sensorManager: SensorManager = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager

    fun currentMotionStatus(): AndroidSensorPermissionStatus {
        val available = sensorManager.getDefaultSensor(Sensor.TYPE_ACCELEROMETER) != null
        return AndroidSensorPermissionStatus(
            permissionState = if (available) "granted" else "unavailable",
            availabilityState = if (available) "healthy" else "unavailable",
            sensorId = "android.sensor.accelerometer",
            signalType = "motion"
        )
    }
}
