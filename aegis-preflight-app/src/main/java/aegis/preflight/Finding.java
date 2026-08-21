package aegis.preflight;

/**
 * Unified finding model produced by all PreFlight scanners.
 * Shape per Aegis spec: {tool, severity, file, line, description}.
 */
public record Finding(
    FindingType type,
    Severity severity,
    String tool,
    String file,
    int line,
    String description
) {

    public enum Severity {
        CRITICAL,
        HIGH,
        MEDIUM,
        LOW,
        INFO
    }

    public enum FindingType {
        SECRET,
        CVE,
        DEPENDENCY,
        CONFIG,
        SAST
    }

    /** Backwards-compatible alias used across the loop and UI. */
    public String remediation() {
        return description;
    }

    public Verdict toVerdict() {
        return switch (severity) {
            case CRITICAL, HIGH -> Verdict.BLOCK;
            case MEDIUM -> Verdict.WARNING;
            case LOW, INFO -> Verdict.PASS;
        };
    }

    @Override
    public String toString() {
        return String.format("[%s/%s/%s] %s:%d — %s", tool, type, severity, file, line, description);
    }
}
