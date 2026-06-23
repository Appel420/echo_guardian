package org.echoguardian.runtime

import org.echoguardian.sensors.MinimizedSensorObservation

class CoreBridgeException(message: String) : IllegalArgumentException(message)

data class CoreCompatibleObservation(
    val schema_version: String = "0.5",
    val observation_id: String,
    val created_at: String,
    val sensor_id: String,
    val signal_type: String,
    val space_id: String,
    val private_space: Boolean,
    val quality: String,
    val permission_state: String,
    val availability_state: String,
    val raw_sensor_retained: Boolean,
    val derived_metadata: Map<String, Int>,
    val plain_language_summary: String
)

class CoreJsonBridge {
    fun bridge(native: MinimizedSensorObservation, sensorId: String = "android-native-sensor", quality: String = "good"): CoreCompatibleObservation {
        if (native.privateSpace) throw CoreBridgeException("Private-space monitoring is blocked by default in v0.5")
        if (native.rawSensorRetained) throw CoreBridgeException("Raw sensor retention is blocked")
        return CoreCompatibleObservation(
            observation_id = native.observationId,
            created_at = native.createdAt,
            sensor_id = sensorId,
            signal_type = native.signalType,
            space_id = native.spaceId,
            private_space = native.privateSpace,
            quality = quality,
            permission_state = native.permissionState,
            availability_state = native.availabilityState,
            raw_sensor_retained = false,
            derived_metadata = native.derivedMetadata,
            plain_language_summary = native.plainLanguageSummary
        )
    }

    fun toCoreJson(observation: CoreCompatibleObservation): String {
        val metadata = observation.derived_metadata.toSortedMap().entries.joinToString(",") { "\"${it.key}\":${it.value}" }
        return "{" +
            "\"schema_version\":\"${observation.schema_version}\"," +
            "\"observation_id\":\"${observation.observation_id}\"," +
            "\"created_at\":\"${observation.created_at}\"," +
            "\"sensor_id\":\"${observation.sensor_id}\"," +
            "\"signal_type\":\"${observation.signal_type}\"," +
            "\"space_id\":\"${observation.space_id}\"," +
            "\"private_space\":${observation.private_space}," +
            "\"quality\":\"${observation.quality}\"," +
            "\"permission_state\":\"${observation.permission_state}\"," +
            "\"availability_state\":\"${observation.availability_state}\"," +
            "\"raw_sensor_retained\":${observation.raw_sensor_retained}," +
            "\"derived_metadata\":{$metadata}," +
            "\"plain_language_summary\":\"${observation.plain_language_summary}\"" +
            "}"
    }
}
