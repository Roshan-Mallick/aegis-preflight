package aegis.audit;

import java.time.Instant;

public record AuditEvent(
    Instant timestamp,
    EventType type,
    Severity severity,
    String source,
    String message,
    String details
) {

    public enum EventType {
        SANDBOX_START,
        SANDBOX_STOP,
        SANDBOX_REVOKE_NETWORK,
        AGENT_RUN,
        AGENT_FIX_ATTEMPT,
        SCAN_START,
        SCAN_COMPLETE,
        VERDICT_BLOCK,
        VERDICT_PASS,
        VERDICT_WARNING,
        FINDING_SECRET,
        FINDING_CVE,
        FINDING_DEPENDENCY,
        INCIDENT_REPORTED,
        POLICY_VIOLATION,
        NETWORK_BLOCKED,
        TOOL_BLOCKED
    }

    public enum Severity {
        INFO,
        WARNING,
        ERROR,
        CRITICAL
    }

    public AuditEvent {
    }

    public static AuditEvent info(EventType type, String source, String message) {
        return new AuditEvent(Instant.now(), type, Severity.INFO, source, message, null);
    }

    public static AuditEvent info(EventType type, String source, String message, String details) {
        return new AuditEvent(Instant.now(), type, Severity.INFO, source, message, details);
    }

    public static AuditEvent warn(EventType type, String source, String message) {
        return new AuditEvent(Instant.now(), type, Severity.WARNING, source, message, null);
    }

    public static AuditEvent warn(EventType type, String source, String message, String details) {
        return new AuditEvent(Instant.now(), type, Severity.WARNING, source, message, details);
    }

    public static AuditEvent error(EventType type, String source, String message) {
        return new AuditEvent(Instant.now(), type, Severity.ERROR, source, message, null);
    }

    public static AuditEvent error(EventType type, String source, String message, String details) {
        return new AuditEvent(Instant.now(), type, Severity.ERROR, source, message, details);
    }

    public static AuditEvent critical(EventType type, String source, String message) {
        return new AuditEvent(Instant.now(), type, Severity.CRITICAL, source, message, null);
    }

    public static AuditEvent critical(EventType type, String source, String message, String details) {
        return new AuditEvent(Instant.now(), type, Severity.CRITICAL, source, message, details);
    }

    @Override
    public String toString() {
        return String.format("[%s] %s %s: %s",
            timestamp, type, source, message);
    }
}
