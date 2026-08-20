package aegis.preflight;

import java.time.Duration;
import java.util.List;
import java.util.Map;

public class ScanResult {

    private final String scannerName;
    private final Verdict verdict;
    private final List<Finding> findings;
    private final Duration duration;
    private final boolean scannerAvailable;
    private final String rawOutput;

    public ScanResult(String scannerName, Verdict verdict,
                      List<Finding> findings, Duration duration,
                      boolean scannerAvailable, String rawOutput) {
        this.scannerName = scannerName;
        this.verdict = verdict;
        this.findings = findings;
        this.duration = duration;
        this.scannerAvailable = scannerAvailable;
        this.rawOutput = rawOutput;
    }

    public String getScannerName() {
        return scannerName;
    }

    public Verdict getVerdict() {
        return verdict;
    }

    public List<Finding> getFindings() {
        return findings;
    }

    public Duration getDuration() {
        return duration;
    }

    public boolean isScannerAvailable() {
        return scannerAvailable;
    }

    public String getRawOutput() {
        return rawOutput;
    }

    public int findingCount() {
        return findings.size();
    }

    public boolean hasBlockers() {
        return verdict == Verdict.BLOCK;
    }

    public List<Finding> getBlockers() {
        return findings.stream()
            .filter(f -> f.toVerdict() == Verdict.BLOCK)
            .toList();
    }

    public String summary() {
        return String.format(
            "%s: %s | Findings: %d | Duration: %dms",
            scannerName, verdict, findings.size(), duration.toMillis()
        );
    }
}
