package org.echoguardian.audit

import java.io.File
import java.time.Instant

data class NativeAuditRecord(
    val schemaVersion: String = "0.5",
    val eventType: String,
    val severity: String,
    val authorityContext: String,
    val plainLanguage: String,
    val createdAt: String = Instant.now().toString()
)

class NativeAuditAppender(private val auditFile: File) {
    fun append(record: NativeAuditRecord) {
        auditFile.parentFile?.mkdirs()
        val escaped = record.plainLanguage.replace("\"", "'")
        val line = "{" +
            "\"schema_version\":\"${record.schemaVersion}\"," +
            "\"event_type\":\"${record.eventType}\"," +
            "\"severity\":\"${record.severity}\"," +
            "\"authority_context\":\"${record.authorityContext}\"," +
            "\"plain_language\":\"$escaped\"," +
            "\"created_at\":\"${record.createdAt}\"" +
            "}\n"
        auditFile.appendText(line)
    }
}
