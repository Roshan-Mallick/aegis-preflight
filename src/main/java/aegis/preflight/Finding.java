package aegis.preflight;

public record Finding(
    FindingType type,
    Severity severity,
    String file,
    int line,
    String remediation
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
        VULN
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
        return String.format("[%s/%s] %s:%d — %s", type, severity, file, line, remediation);
    }
}
