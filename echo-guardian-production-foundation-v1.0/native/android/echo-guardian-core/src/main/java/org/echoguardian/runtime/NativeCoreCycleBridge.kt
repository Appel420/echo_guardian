package org.echoguardian.runtime

import org.echoguardian.sensors.MinimizedSensorObservation

class NativeCoreCycleBridge {
    private val forbiddenKeys = setOf("raw", "raw_data", "raw_sample", "samples", "audio_buffer", "video_frame", "transcript", "waveform", "packet_capture")

    fun bridge(observation: MinimizedSensorObservation): Map<String, Any> {
        require(!observation.privateSpace && observation.spaceId != "bathroom" && observation.spaceId != "bedroom") {
            "Private-space monitoring is blocked by default in v0.6"
        }
        require(!observation.rawSensorRetained) { "Raw sensor retention is blocked by default in v0.6" }
        require(observation.derivedMetadata.keys.none { forbiddenKeys.contains(it.lowercase()) }) {
            "Raw-like metadata keys are blocked by default in v0.6"
        }
        return mapOf(
            "schema_version" to "0.6",
            "raw_sensor_retained" to false,
            "private_space" to false,
            "ready_for_core" to true,
            "plain_language_summary" to "The native observation is minimized and ready for the Echo Guardian core loop."
        )
    }
}
