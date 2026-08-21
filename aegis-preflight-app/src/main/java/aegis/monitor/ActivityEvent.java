package aegis.monitor;

import java.time.Instant;

/**
 * One structured runtime event observed by the ActivityMonitor.
 * Kinds map to the Aegis spec: file_access, process_exec, network_attempt,
 * plus container lifecycle events surfaced from `docker events`.
 */
public record ActivityEvent(
    Instant timestamp,
    Kind kind,
    String detail,
    boolean flagged,
    String rule
) {

    public enum Kind {
        FILE_ACCESS("file_access"),
        PROCESS_EXEC("process_exec"),
        NETWORK_ATTEMPT("network_attempt"),
        CONTAINER_EVENT("container_event"),
        POLICY_VIOLATION("policy_violation");

        private final String label;

        Kind(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    public static ActivityEvent of(Kind kind, String detail) {
        return new ActivityEvent(Instant.now(), kind, detail, false, null);
    }

    public ActivityEvent flagged(String ruleId) {
        return new ActivityEvent(timestamp, kind, detail, true, ruleId);
    }

    @Override
    public String toString() {
        return String.format("%s [%s]%s %s",
            timestamp.toString().substring(11, 19),
            kind.label(),
            flagged ? " FLAGGED(" + rule + ")" : "",
            detail);
    }
}
