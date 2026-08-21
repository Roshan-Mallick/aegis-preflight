package aegis.audit;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.time.Instant;

/**
 * A single hash-chained audit log entry.
 *
 * Stored columns: id, timestamp, event_type, payload_json, prev_hash, curr_hash
 * curr_hash = SHA256(prev_hash + timestamp + event_type + payload_json)
 */
public record AuditEvent(
    long id,
    Instant timestamp,
    EventType eventType,
    String payloadJson,
    String prevHash,
    String currHash
) {

    private static final Gson gson = new GsonBuilder().disableHtmlEscaping().create();

    public enum EventType {
        SANDBOX_START,
        SANDBOX_STOP,
        SANDBOX_KILL,
        SANDBOX_SUSPEND,
        SANDBOX_REVOKE_NETWORK,
        AGENT_RUN,
        AGENT_FIX_ATTEMPT,
        FIX_APPLIED,
        SCAN_START,
        SCAN_COMPLETE,
        VERDICT_BLOCK,
        VERDICT_PASS,
        VERDICT_WARNING,
        FINDING_SECRET,
        FINDING_CVE,
        FINDING_DEPENDENCY,
        RELEASED,
        MANUAL_REVIEW,
        DEVELOPER_OVERRIDE,
        INCIDENT_REPORTED,
        POLICY_VIOLATION,
        ACTIVITY_FLAGGED,
        NETWORK_BLOCKED,
        TOOL_BLOCKED,
        CHAIN_VERIFIED
    }

    public enum Severity {
        INFO,
        WARNING,
        ERROR,
        CRITICAL
    }

    /**
     * Structured payload stored as JSON in the payload_json column.
     */
    public record Payload(
        String severity,
        String source,
        String message,
        String details
    ) {
    }

    public static AuditEvent unchained(EventType type, Severity severity, String source,
                                       String message, String details) {
        Payload payload = new Payload(
            severity.name(),
            source == null ? "Aegis" : source,
            message == null ? "" : message,
            details
        );
        return new AuditEvent(-1, Instant.now(), type, gson.toJson(payload), null, null);
    }

    public static AuditEvent info(EventType type, String source, String message) {
        return unchained(type, Severity.INFO, source, message, null);
    }

    public static AuditEvent info(EventType type, String source, String message, String details) {
        return unchained(type, Severity.INFO, source, message, details);
    }

    public static AuditEvent warn(EventType type, String source, String message) {
        return unchained(type, Severity.WARNING, source, message, null);
    }

    public static AuditEvent warn(EventType type, String source, String message, String details) {
        return unchained(type, Severity.WARNING, source, message, details);
    }

    public static AuditEvent error(EventType type, String source, String message, String details) {
        return unchained(type, Severity.ERROR, source, message, details);
    }

    public static AuditEvent critical(EventType type, String source, String message) {
        return unchained(type, Severity.CRITICAL, source, message, null);
    }

    public static AuditEvent critical(EventType type, String source, String message, String details) {
        return unchained(type, Severity.CRITICAL, source, message, details);
    }

    public Payload payload() {
        try {
            Payload p = gson.fromJson(payloadJson, Payload.class);
            if (p == null) {
                return new Payload(Severity.INFO.name(), "Aegis", "", payloadJson);
            }
            return p;
        } catch (Exception e) {
            return new Payload(Severity.INFO.name(), "Aegis", payloadJson == null ? "" : payloadJson, null);
        }
    }

    public String severity() {
        return payload().severity();
    }

    public String source() {
        return payload().source();
    }

    public String message() {
        return payload().message();
    }

    public String details() {
        return payload().details();
    }

    @Override
    public String toString() {
        Payload p = payload();
        return String.format("#%d [%s] %s (%s): %s", id, timestamp, eventType, p.severity(), p.message());
    }
}
