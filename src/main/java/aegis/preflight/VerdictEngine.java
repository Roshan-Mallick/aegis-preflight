package aegis.preflight;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

public class VerdictEngine {

    private static final Logger log = LoggerFactory.getLogger(VerdictEngine.class);
    private static final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    private final List<Finding> findings;

    public VerdictEngine(List<Finding> findings) {
        this.findings = findings != null ? List.copyOf(findings) : List.of();
    }

    public Verdict computeVerdict() {
        Verdict verdict = Verdict.PASS;
        for (Finding f : findings) {
            verdict = verdict.mergeWith(f.toVerdict());
        }
        log.debug("Verdict computed: {} ({} findings)", verdict, findings.size());
        return verdict;
    }

    public List<Finding> getBlockers() {
        return findings.stream()
            .filter(f -> f.toVerdict() == Verdict.BLOCK)
            .toList();
    }

    public List<Finding> getWarnings() {
        return findings.stream()
            .filter(f -> f.toVerdict() == Verdict.WARNING)
            .toList();
    }

    public boolean hasBlockers() {
        return findings.stream().anyMatch(f -> f.toVerdict() == Verdict.BLOCK);
    }

    public String toJson() {
        return gson.toJson(findings);
    }

    public String toSummaryJson(Verdict verdict, int round) {
        List<Object> summary = new ArrayList<>();
        for (Finding f : findings) {
            summary.add(new FindingSummary(
                f.type().name(),
                f.severity().name(),
                f.file(),
                f.line(),
                f.remediation()
            ));
        }

        Output output = new Output();
        output.verdict = verdict.name();
        output.round = round;
        output.findingCount = findings.size();
        output.findings = summary;

        return gson.toJson(output);
    }

    public List<Finding> getAllFindings() {
        return findings;
    }

    public int count() {
        return findings.size();
    }

    public static VerdictEngine fromScanResults(List<ScanResult> scanResults) {
        List<Finding> allFindings = new ArrayList<>();
        for (ScanResult result : scanResults) {
            allFindings.addAll(result.getFindings());
        }
        return new VerdictEngine(allFindings);
    }

    private static class FindingSummary {
        String type;
        String severity;
        String file;
        int line;
        String remediation;

        FindingSummary(String type, String severity, String file, int line, String remediation) {
            this.type = type;
            this.severity = severity;
            this.file = file;
            this.line = line;
            this.remediation = remediation;
        }
    }

    private static class Output {
        String verdict;
        int round;
        int findingCount;
        List<Object> findings;
    }
}
