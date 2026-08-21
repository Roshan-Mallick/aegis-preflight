package aegis.preflight;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * PreFlight exit gate: runs Gitleaks + Semgrep + Trivy against the workspace
 * and produces a unified ScanResult list. Scanners are external host
 * subprocesses running fully offline (bundled rules/binaries, cached Trivy DB)
 * — findings always come from real tool output.
 */
public class ScanEngine {

    private static final Logger log = LoggerFactory.getLogger(ScanEngine.class);
    private static final Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    private final Path workspace;

    public ScanEngine(Path workspace) {
        this.workspace = workspace;
    }

    public List<ScanResult> scanAll() throws ScannerException {
        List<ScanResult> results = new ArrayList<>();

        GitleaksScanner gitleaks = new GitleaksScanner(workspace);
        results.add(gitleaks.scan());

        SemgrepScanner semgrep = new SemgrepScanner(workspace);
        results.add(semgrep.scan());

        TrivyScanner trivy = new TrivyScanner(workspace);
        results.add(trivy.scan());

        log.info("ScanEngine complete: {} scanner result(s)", results.size());
        return results;
    }

    public Verdict computeOverallVerdict(List<ScanResult> results) {
        Verdict verdict = Verdict.PASS;
        for (ScanResult result : results) {
            if (!result.isScannerAvailable()) {
                continue; // an unavailable scanner must not silently pass the gate
            }
            verdict = verdict.mergeWith(result.getVerdict());
        }
        return verdict;
    }

    public List<Finding> collectAllFindings(List<ScanResult> results) {
        List<Finding> all = new ArrayList<>();
        for (ScanResult result : results) {
            all.addAll(result.getFindings());
        }
        return all;
    }

    public List<Finding> getBlockers(List<ScanResult> results) {
        return collectAllFindings(results).stream()
            .filter(f -> f.toVerdict() == Verdict.BLOCK)
            .toList();
    }

    public List<Finding> getWarnings(List<ScanResult> results) {
        return collectAllFindings(results).stream()
            .filter(f -> f.toVerdict() == Verdict.WARNING)
            .toList();
    }

    /**
     * Serializes findings into findings.json which is written into the sandbox
     * workspace for the agent to read and self-fix.
     */
    public String buildFindingsJson(Verdict verdict, int round, List<Finding> blockers) {
        List<FindingJson> items = blockers.stream()
            .map(f -> new FindingJson(f.tool(), f.type().name(), f.severity().name(),
                f.file(), f.line(), f.description()))
            .toList();

        Output out = new Output();
        out.verdict = verdict.name();
        out.round = round;
        out.findingCount = blockers.size();
        out.instruction = "Fix every finding below, then re-run your task. Do not reintroduce secrets.";
        out.findings = items;

        return gson.toJson(out);
    }

    /**
     * Deterministic template explanation for a finding (no LLM).
     */
    public static String explain(Finding f) {
        return String.format("Tool %s reported %s [%s] at %s:%d — severity %s. Fix: %s",
            f.tool(), f.type(), f.severity(), f.file(), f.line(), f.severity(), f.description());
    }

    private static class FindingJson {
        final String tool;
        final String type;
        final String severity;
        final String file;
        final int line;
        final String description;

        FindingJson(String tool, String type, String severity, String file, int line, String description) {
            this.tool = tool;
            this.type = type;
            this.severity = severity;
            this.file = file;
            this.line = line;
            this.description = description;
        }
    }

    private static class Output {
        String verdict;
        int round;
        int findingCount;
        String instruction;
        List<FindingJson> findings;
    }
}
