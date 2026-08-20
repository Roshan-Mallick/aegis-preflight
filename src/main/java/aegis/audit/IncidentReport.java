package aegis.audit;

import aegis.preflight.Finding;
import aegis.preflight.Verdict;

import java.time.Instant;
import java.util.List;

public record IncidentReport(
    Instant timestamp,
    Verdict verdict,
    List<Finding> findings,
    String agentCommand,
    int roundNumber,
    String developerNote,
    List<String> evidenceFiles
) {

    public IncidentReport {
    }

    public int findingCount() {
        return findings.size();
    }

    public long blockerCount() {
        return findings.stream()
            .filter(f -> f.toVerdict() == Verdict.BLOCK)
            .count();
    }

    public String summary() {
        return String.format(
            "Incident at %s | Verdict: %s | Findings: %d | Blockers: %d | Round: %d",
            timestamp, verdict, findingCount(), blockerCount(), roundNumber
        );
    }
}
